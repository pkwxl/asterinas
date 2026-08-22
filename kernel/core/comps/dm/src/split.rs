// SPDX-License-Identifier: MPL-2.0

//! Copy-based bio splitting for the DM core (the slow path of `enqueue`).
//!
//! aster-block does not support zero-copy splitting of a `SubmittedBio`:
//! its fields are private, the only producer is `Bio::submit`, and the
//! completion state machine allows exactly one `Submit -> final` transition
//! (see docs/009c-bio-split.md). So a bio that crosses a target boundary or
//! a per-target `max_io_len` boundary is split here by copying each piece
//! into a freshly allocated child segment and submitting one child bio per
//! piece. A [`SplitTracker`] aggregates the child completions and completes
//! the original bio once all pieces have finished (copying the data back
//! into the original segments first for read bios).

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use aster_block::{
    BlockDevice, SECTOR_SIZE,
    bio::{
        Bio, BioCompleteFn, BioDirection, BioEnqueueError, BioSegment, BioStatus, BioType,
        SubmittedBio,
    },
    id::Sid,
};
use io_util::batch::IoBatch;
use ostd::{
    mm::{Infallible, VmReader, VmWriter, io::util::HasVmReaderWriter},
    sync::SpinLock,
};

use crate::DmTable;

/// Computes the split points for a bio covering `[start, end)`.
///
/// Each returned piece `(piece_start, piece_end)`
/// - lies entirely within a single target's `[begin, end)` range, and
/// - does not cross a `max_io_len` multiple boundary within that target
///   (measured in sectors relative to the target's begin) when the target's
///   `max_io_len` is non-zero.
///
/// Returns `None` if some sector in `[start, end)` is not covered by any
/// target (which the caller normally rules out beforehand by checking the
/// bio against the table size).
pub fn compute_pieces(table: &DmTable, start: u64, end: u64) -> Option<Vec<(u64, u64)>> {
    debug_assert!(start < end && end <= table.nr_sectors());

    let mut pieces = Vec::new();
    let mut cur = start;
    while cur < end {
        let target = table.find_target(cur)?;
        let mut piece_end = target.end().min(end);
        if target.max_io_len > 0 {
            let rel = cur - target.begin;
            let room = target.max_io_len - rel % target.max_io_len;
            piece_end = piece_end.min(cur + room);
        }
        pieces.push((cur, piece_end));
        cur = piece_end;
    }
    Some(pieces)
}

/// Splits `bio` according to `pieces` and submits one child bio per piece
/// to the underlying device selected by the owning target.
///
/// The original bio is completed (possibly with an error status) once all
/// pieces have finished; pieces whose mapping fails, and children that fail
/// submission, are accounted as pieces completed with `BioStatus::IoError`.
///
/// This function always accepts the bio (`Ok(())`), because some child bios
/// may already be in flight when a later piece fails; the aggregated error
/// is reported through the original bio's completion status instead.
pub fn split_and_submit(
    table: &DmTable,
    bio: SubmittedBio,
    pieces: &[(u64, u64)],
) -> Result<(), BioEnqueueError> {
    debug_assert!(!pieces.is_empty());

    let type_ = bio.type_();
    let bio_start = bio.sid_range().start.to_raw();
    let direction = match type_ {
        BioType::Read => BioDirection::FromDevice,
        BioType::Write => BioDirection::ToDevice,
        // Flush bios carry no data and are never split.
        BioType::Flush => return Err(BioEnqueueError::Refused),
    };

    // Phase 1: build the child segments. For write bios the payload is
    // copied out of the original segments now, before the original bio is
    // moved into the tracker.
    let mut children = Vec::new();
    let mut pre_failed = 0usize;
    for &(piece_start, piece_end) in pieces {
        let nsectors = (piece_end - piece_start) as usize;
        let rel_start = (piece_start - bio_start) as usize * SECTOR_SIZE;

        let mapped = table
            .find_target(piece_start)
            .and_then(|target| target.map(piece_start).ok());
        let Some(mapped) = mapped else {
            // E.g. an error target owns this piece.
            pre_failed += 1;
            continue;
        };

        let child_seg = BioSegment::alloc_sectors(nsectors, direction);
        if type_ == BioType::Write {
            let slice = child_seg.inner_dma_slice();
            let mut writer = slice.writer().unwrap();
            copy_from_segments(bio.segments(), rel_start, &mut writer);
        }
        children.push(Child {
            device: mapped.device,
            sector: mapped.sector,
            seg: child_seg,
            rel_start,
        });
    }

    // Phase 2: move the original bio into the tracker and submit the
    // children. The tracker must observe exactly `pieces.len()` piece
    // completions in total.
    let tracker = Arc::new(SplitTracker::new(type_, pieces.len(), bio));
    for child in children {
        if type_ == BioType::Read {
            // Record the copy-back information *before* submitting: the
            // child may complete synchronously inside `submit`.
            tracker.record_read_piece(child.seg.clone(), child.rel_start);
        }
        let tracker_clone = tracker.clone();
        let complete_fn: BioCompleteFn =
            Box::new(move |status| tracker_clone.piece_done(status));
        let child_bio = Bio::new(
            type_,
            Sid::new(child.sector),
            alloc::vec![child.seg],
            Some(complete_fn),
        );
        // The batch is throwaway: completion is tracked via the callback.
        let mut batch = IoBatch::new();
        if child_bio.submit(&*child.device, &mut batch).is_err() {
            // `Bio::submit` has reverted the child bio; account the piece
            // as failed.
            tracker.piece_done(BioStatus::IoError);
        }
    }
    for _ in 0..pre_failed {
        tracker.piece_done(BioStatus::IoError);
    }
    Ok(())
}

/// A piece of a split bio that is ready for submission.
struct Child {
    device: Arc<dyn BlockDevice>,
    sector: u64,
    seg: BioSegment,
    /// Byte offset of this piece within the original bio's segments.
    rel_start: usize,
}

/// Aggregates the completions of the child bios produced by
/// [`split_and_submit`] and completes the original bio exactly once.
pub struct SplitTracker {
    type_: BioType,
    /// The number of pieces that have not finished yet.
    remaining: AtomicUsize,
    /// The first non-`Complete` child status (`BioStatus` as `u32`; 0 = none).
    first_error: AtomicU32,
    /// The original bio, taken by the last finishing piece.
    original: SpinLock<Option<SubmittedBio>>,
    /// Copy-back table for read bios: `(child segment, byte offset of the
    /// piece within the original segments)`.
    read_pieces: SpinLock<Vec<(BioSegment, usize)>>,
}

impl SplitTracker {
    fn new(type_: BioType, nr_pieces: usize, original: SubmittedBio) -> Self {
        Self {
            type_,
            remaining: AtomicUsize::new(nr_pieces),
            first_error: AtomicU32::new(0),
            original: SpinLock::new(Some(original)),
            read_pieces: SpinLock::new(Vec::new()),
        }
    }

    fn record_read_piece(&self, seg: BioSegment, rel_start: usize) {
        self.read_pieces.lock().push((seg, rel_start));
    }

    /// Accounts one finished piece; the last finisher completes the
    /// original bio.
    fn piece_done(&self, status: BioStatus) {
        debug_assert!(status != BioStatus::Init && status != BioStatus::Submit);
        if status != BioStatus::Complete {
            let _ = self.first_error.compare_exchange(
                0,
                status as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        if self.remaining.fetch_sub(1, Ordering::SeqCst) != 1 {
            return;
        }

        // All pieces have finished.
        let Some(original) = self.original.lock().take() else {
            // The piece accounting guarantees this is unreachable.
            debug_assert!(false, "split tracker completed twice");
            return;
        };
        let err = self.first_error.load(Ordering::SeqCst);
        if err != 0 {
            let status = BioStatus::try_from(err).unwrap_or(BioStatus::IoError);
            original.complete(status);
            return;
        }

        if self.type_ == BioType::Read {
            // Copy the data of every piece back into the original segments.
            let read_pieces = core::mem::take(&mut *self.read_pieces.lock());
            for (seg, rel_start) in read_pieces {
                let slice = seg.inner_dma_slice();
                let mut reader = slice.reader().unwrap();
                copy_into_segments(original.segments(), rel_start, &mut reader);
            }
        }
        original.complete(BioStatus::Complete);
    }
}

/// Copies `writer.avail()` bytes out of `segments`, starting `skip` bytes
/// into the concatenated segment data.
fn copy_from_segments(
    segments: &[BioSegment],
    mut skip: usize,
    writer: &mut VmWriter<'_, Infallible>,
) {
    let mut remaining = writer.avail();
    for seg in segments {
        if remaining == 0 {
            break;
        }
        let size = seg.nbytes();
        if skip >= size {
            skip -= size;
            continue;
        }
        let take = (size - skip).min(remaining);
        let slice = seg.inner_dma_slice().slice(skip..skip + take);
        let mut reader = slice.reader().unwrap();
        let n = writer.write(&mut reader);
        debug_assert_eq!(n, take);
        remaining -= n;
        skip = 0;
    }
    debug_assert_eq!(remaining, 0);
}

/// Copies `reader.remain()` bytes into `segments`, starting `skip` bytes
/// into the concatenated segment data.
fn copy_into_segments(
    segments: &[BioSegment],
    mut skip: usize,
    reader: &mut VmReader<'_, Infallible>,
) {
    let mut remaining = reader.remain();
    for seg in segments {
        if remaining == 0 {
            break;
        }
        let size = seg.nbytes();
        if skip >= size {
            skip -= size;
            continue;
        }
        let take = (size - skip).min(remaining);
        let slice = seg.inner_dma_slice().slice(skip..skip + take);
        let mut writer = slice.writer().unwrap();
        let n = writer.write(reader);
        debug_assert_eq!(n, take);
        remaining -= n;
        skip = 0;
    }
    debug_assert_eq!(remaining, 0);
}
