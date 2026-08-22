// SPDX-License-Identifier: MPL-2.0

use alloc::{
    boxed::Box,
    collections::VecDeque,
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt::Debug,
    sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering},
};

use aster_block::{
    BlockDevice, BlockDeviceMeta,
    bio::{BioEnqueueError, BioType, SubmittedBio},
};
use device_id::DeviceId;
use ostd::sync::{RwLock, SpinLock, WaitQueue};

use crate::{
    DmTable,
    split::{compute_pieces, split_and_submit},
};

/// Represents a mapped device with active/inactive table slots
#[derive(Debug)]
pub struct DmDevice {
    name: String,
    id: DeviceId,
    open_count: AtomicI32,
    tables: RwLock<(Option<DmTable>, Option<DmTable>)>,
    suspend_flag: AtomicU32,
    deferred_queue: SpinLock<VecDeque<SubmittedBio>>,
    in_flight: Arc<InFlight>,
}

/// Tracks the bios that the device has accepted but that have not been
/// completed yet, so that `suspend` can wait for them to drain.
struct InFlight {
    count: AtomicUsize,
    drained: WaitQueue,
}

// `WaitQueue` does not implement `Debug`.
impl Debug for InFlight {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InFlight").field("count", &self.count).finish()
    }
}

impl InFlight {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            drained: WaitQueue::new(),
        }
    }

    fn inc(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    fn dec(&self) {
        if self.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.drained.wake_all();
        }
    }
}

impl DmDevice {
    /// Create a new dm device with the given name and device ID
    /// (suspended state, no table).
    ///
    /// The device ID (major 253, minor N) is allocated by the
    /// control-plane glue; this crate only stores it.
    pub fn create(name: &str, id: DeviceId) -> Arc<Self> {
        let device = DmDevice {
            name: String::from(name),
            id,
            open_count: AtomicI32::new(0),
            tables: RwLock::new((None, None)),
            suspend_flag: AtomicU32::new(0),
            deferred_queue: SpinLock::new(VecDeque::new()),
            in_flight: Arc::new(InFlight::new()),
        };
        Arc::new(device)
    }

    /// Returns the number of open handles on this device.
    ///
    /// The counter is maintained via the `BlockDevice::on_open`/`on_close`
    /// hooks, which the device-file layer (`BlockFile`/`OpenBlockFile` in
    /// aster-core) invokes around each open and the final close.
    pub fn open_count(&self) -> i32 {
        self.open_count.load(Ordering::SeqCst)
    }

    /// Load a table into the inactive slot
    pub fn load_table(&self, table: DmTable) {
        let mut tables = self.tables.write();
        tables.1 = Some(table);
    }

    /// Swap active and inactive tables (resume), making the inactive table active
    pub fn swap_table(&self) {
        // Use a temporary to break the borrow chain
        let old_inactive;
        {
            let mut tables = self.tables.write();
            old_inactive = tables.1.take();
            tables.1 = tables.0.take();
            tables.0 = old_inactive;
        }
    }

    /// Remove the device (requires open_count == 0, simplified: just drop)
    pub fn remove(&self) {
        let mut tables = self.tables.write();
        tables.0 = None;
        tables.1 = None;
    }

    /// Get the current active table
    pub fn get_active_table(&self) -> Option<DmTable> {
        self.tables.read().0.clone()
    }

    /// Get both active and inactive tables (for TABLE_STATUS)
    pub fn get_tables(&self) -> (Option<DmTable>, Option<DmTable>) {
        let tables = self.tables.read();
        (tables.0.clone(), tables.1.clone())
    }

    /// Suspend the device: block new I/O and wait for in-flight to complete
    pub fn suspend(&self) {
        // Set the suspend flag first; new bios are deferred from now on.
        self.suspend_flag.store(1, Ordering::SeqCst);
        // Wait until all bios accepted before the flag was set complete.
        //
        // The `inc` (SeqCst) in `enqueue` happens before its suspended
        // check, so any bio that observes the flag as clear is already
        // reflected in this counter.
        self.in_flight
            .drained
            .wait_until(|| (self.in_flight.count.load(Ordering::SeqCst) == 0).then_some(()));
    }

    /// Resume the device: unblock and replay deferred queue
    pub fn resume(&self) {
        // Clear suspend flag
        self.suspend_flag.store(0, Ordering::SeqCst);

        // Pop the deferred bios into a local backlog first, then replay them
        // without holding the queue lock. Replaying under the lock would
        // risk a deadlock if a replayed bio re-enters the defer branch.
        let mut backlog = Vec::new();
        {
            let mut queue = self.deferred_queue.lock();
            while let Some(bio) = queue.pop_front() {
                backlog.push(bio);
            }
        }
        for bio in backlog {
            // Re-enqueue with the current active table; a bio deferred due
            // to a transient suspend during replay simply lands back in the
            // queue.
            let _ = self.enqueue(bio);
        }
    }

    /// Check if device is suspended
    pub fn is_suspended(&self) -> bool {
        self.suspend_flag.load(Ordering::SeqCst) != 0
    }

    /// Add a bio to deferred queue (called when suspended)
    pub fn defer_bio(&self, bio: SubmittedBio) {
        self.deferred_queue.lock().push_back(bio);
    }
}

/// Dispatches a bio against the active table: maps and forwards it (fast
/// path) or splits it into per-piece child bios (slow path).
fn dispatch_bio(table: &DmTable, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
    let start = bio.sid_range().start.to_raw();
    let end = bio.sid_range().end.to_raw();

    if bio.type_() == BioType::Flush {
        // Simplified flush handling: forward the flush to the underlying
        // device mapped by the target that contains sector 0.
        let Some(target) = table.find_target(0) else {
            return Err(BioEnqueueError::Refused);
        };
        let Ok(mapped) = target.map(0) else {
            return Err(BioEnqueueError::Refused);
        };
        return mapped.device.enqueue(bio);
    }

    if end <= start || end > table.nr_sectors() {
        // An out-of-range bio is a bug of the upper layer; refuse it so
        // that `Bio::submit` can roll the bio back to the Init state.
        return Err(BioEnqueueError::Refused);
    }

    let pieces =
        compute_pieces(table, start, end).ok_or(BioEnqueueError::Refused)?;
    if pieces.len() == 1 {
        // Fast path: the whole bio maps to a single contiguous run on one
        // underlying device; forward it zero-copy via a sector offset.
        let target = table.find_target(start).ok_or(BioEnqueueError::Refused)?;
        let mapped = target.map(start).map_err(|_| BioEnqueueError::Refused)?;
        // `sid_offset` is a sector offset that can only *add* to the bio's
        // start sector; a negative remapping cannot be expressed, so fall
        // back to the copy-based slow path there.
        if mapped.sector >= start {
            bio.set_sid_offset(mapped.sector - start);
            return mapped.device.enqueue(bio);
        }
    }
    split_and_submit(table, bio, &pieces)
}

impl BlockDevice for DmDevice {
    fn enqueue(&self, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        // The in-flight increment (SeqCst) precedes the suspended check so
        // that a concurrent `suspend` either counts this bio or has its
        // flag observed by the check below.
        self.in_flight.inc();
        if self.is_suspended() {
            // Defer the *whole* bio before any splitting; it will be
            // re-split against the new table when replayed on resume.
            self.in_flight.dec();
            self.defer_bio(bio);
            return Ok(());
        }

        // Clone the active table while holding the lock and release the
        // lock before any mapping/forwarding work, so that completions or
        // blocking inside the underlying enqueue never hold the table lock.
        let table = self.tables.read().0.clone();
        let Some(table) = table else {
            // Suspended (or freshly created) device without a table.
            self.in_flight.dec();
            return Err(BioEnqueueError::Refused);
        };

        // The bio will be completed by the underlying device (fast path) or
        // by the split tracker (slow path); in both cases the hook below
        // runs on completion and drops the in-flight count.
        let in_flight = self.in_flight.clone();
        bio.add_complete_hook(Box::new(move |_| in_flight.dec()));

        match dispatch_bio(&table, bio) {
            Ok(()) => Ok(()),
            Err(err) => {
                // The bio was dropped without being completed, so the hook
                // never runs; undo the accounting here.
                self.in_flight.dec();
                Err(err)
            }
        }
    }

    fn metadata(&self) -> BlockDeviceMeta {
        let nr_sectors = self
            .tables
            .read()
            .0
            .as_ref()
            .map_or(0, |table| table.nr_sectors() as usize);
        // The DM core splits incoming bios by sector boundaries and accepts
        // any number of segments (the underlying queues enforce their own
        // limits on the child bios), same as the mlsdisk precedent.
        BlockDeviceMeta {
            max_nr_segments_per_bio: usize::MAX,
            nr_sectors,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn on_open(&self) {
        self.open_count.fetch_add(1, Ordering::SeqCst);
    }

    fn on_close(&self) {
        self.open_count.fetch_sub(1, Ordering::SeqCst);
    }
}
