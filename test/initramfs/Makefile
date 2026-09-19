# SPDX-License-Identifier: MPL-2.0

TARGET_ARCH ?= x86_64
SMP ?= 1
VERBOSE ?= 1
ENABLE_CONFORMANCE_TEST ?= false
CONFORMANCE_TEST_SUITE ?= ltp
CONFORMANCE_TEST_WORKDIR ?= /tmp
ENABLE_REGRESSION_TEST ?= false
# Specify whether to build erofs test images and attach them to the VM
# (requires the erofs regression tests under src/regression/fs/erofs/).
ENABLE_EROFS_TEST ?= false
# Specify platform macros when building regression tests (supported: asterinas, linux).
# - asterinas: Define both `__asterinas__` and `__linux__`. Tests may fail in Linux.
# - linux: Define only `__linux__`. Tests may fail in Asterinas.
REGRESSION_TEST_PLATFORM ?= asterinas
DNS_SERVER ?= none
# Set Nix's cached tarballs to be live for a longer period of time (30 days) to avoid network traffics.
# Nix's default value is rather small (1 hour or 3600 seconds).
NIXPKGS_CACHE_TTL := 2592000 # In seconds
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CUR_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))
BUILD_DIR := $(CUR_DIR)/build
INITRAMFS := $(BUILD_DIR)/initramfs
INITRAMFS_SKIP_GZIP ?= 0
ifeq ($(INITRAMFS_SKIP_GZIP),1)
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.cpio
INITRAMFS_COMPRESSED := false
else
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.cpio.gz
INITRAMFS_COMPRESSED := true
endif
EXT2_IMAGE := $(BUILD_DIR)/ext2.img
EXFAT_IMAGE := $(BUILD_DIR)/exfat.img
LTP_DEV_IMAGE := $(BUILD_DIR)/ltp_dev.img
SSD_IMAGE := $(BUILD_DIR)/nvme0n1.img
XFSTESTS_TEST_IMAGE := $(BUILD_DIR)/xfstests_test.img
XFSTESTS_SCRATCH_IMAGE := $(BUILD_DIR)/xfstests_scratch.img
XFSTESTS_DISK_SIZE ?= 12G
EROFS_TREE_DIR := $(CUR_DIR)/erofs_tree
EROFS_STAGE_SCRIPT := $(CUR_DIR)/erofs_stage.sh
EROFS_TREE_STAGE := $(BUILD_DIR)/erofs_tree_stage
EROFS_BASE_IMAGE := $(BUILD_DIR)/erofs_base.img
EROFS_BASE_CPT_IMAGE := $(BUILD_DIR)/erofs_base_cpt.img
EROFS_UUID0_IMAGE := $(BUILD_DIR)/erofs_uuid0.img
EROFS_BS512_IMAGE := $(BUILD_DIR)/erofs_bs_512.img
EROFS_BS1024_IMAGE := $(BUILD_DIR)/erofs_bs_1024.img
EROFS_BS2048_IMAGE := $(BUILD_DIR)/erofs_bs_2048.img
EROFS_COMP_LZ4_IMAGE := $(BUILD_DIR)/erofs_comp_lz4.img
EROFS_XATTR_SHARED_ALL_IMAGE := $(BUILD_DIR)/erofs_xattr_shared_all.img
EROFS_XATTR_NONE_IMAGE := $(BUILD_DIR)/erofs_xattr_none.img
EROFS_PREFIX_IMAGE := $(BUILD_DIR)/erofs_prefix.img
EROFS_FLATDEV_IMAGE := $(BUILD_DIR)/erofs_flatdev.img
EROFS_BLOB_IMAGE := $(BUILD_DIR)/erofs_blob.img
EROFS_CHUNK4B_IMAGE := $(BUILD_DIR)/erofs_chunk4b.img
EROFS_FLATDEV_CONCAT_IMAGE := $(BUILD_DIR)/erofs_flatdev_concat.img
EROFS_FLATDEV_BADTAG_IMAGE := $(BUILD_DIR)/erofs_flatdev_badtag.img
EROFS_ALL_IMAGES := $(EROFS_BASE_IMAGE) $(EROFS_BASE_CPT_IMAGE) \
    $(EROFS_UUID0_IMAGE) $(EROFS_BS512_IMAGE) $(EROFS_BS1024_IMAGE) \
    $(EROFS_BS2048_IMAGE) $(EROFS_COMP_LZ4_IMAGE) \
    $(EROFS_XATTR_SHARED_ALL_IMAGE) $(EROFS_XATTR_NONE_IMAGE) \
    $(EROFS_PREFIX_IMAGE) $(EROFS_FLATDEV_IMAGE) $(EROFS_BLOB_IMAGE) \
    $(EROFS_CHUNK4B_IMAGE) $(EROFS_FLATDEV_CONCAT_IMAGE) \
    $(EROFS_FLATDEV_BADTAG_IMAGE)
# Interface constants (single source: docs/T-016/analysis.md §1;
# blueprint: docs/T-016/S03/index.md §2.2).
EROFS_UUID_BASE := e2e4f0c8-1a2b-4c3d-9e8f-5a6b7c8d9e0f
EROFS_UUID_BASE_CPT := e2e4f0c8-1a2b-4c3d-9e8f-5a6b7c8d9e10
EROFS_UUID0 := 00000000-0000-0000-0000-000000000000
EROFS_XATTR_PREFIX := user.erofs_test.lpx.
EROFS_FLATDEV_CHUNKSIZE := 4096
EROFS_CHUNK4B_CHUNKSIZE := 32768
EROFS_DEVT_SLOTOFF := 9

# Include benchmark, if BENCHMARK is set.
ifeq ($(BENCHMARK), none)
ENABLE_BENCHMARK_TEST = false
else
ENABLE_BENCHMARK_TEST = true
endif

BUILD_XFSTESTS_IMAGES = false
ifeq ($(ENABLE_CONFORMANCE_TEST), true)
ifeq ($(CONFORMANCE_TEST_SUITE), xfstests)
BUILD_XFSTESTS_IMAGES = true
endif
endif

BUILD_EROFS_IMAGES = false
ifeq ($(ENABLE_EROFS_TEST), true)
BUILD_EROFS_IMAGES = true
endif

EROFS_BUILD_DEPS :=
ifeq ($(BUILD_EROFS_IMAGES), true)
EROFS_BUILD_DEPS := $(EROFS_ALL_IMAGES)
endif

# Decreases the level of verbosity of diagnostic messages from Nix.
ifeq ($(VERBOSE), 0)
NIX_QUIET = --quiet -Q
endif

.PHONY: all
all: build

.PHONY: build
ifeq ($(TARGET_ARCH), loongarch64)
build: $(EXT2_IMAGE) $(EXFAT_IMAGE)
	@echo "For loongarch, we generate a fake initramfs to successfully test or build."
	@touch $(INITRAMFS_IMAGE)
else ifeq ($(BUILD_XFSTESTS_IMAGES), true)
build: $(INITRAMFS_IMAGE) $(EXT2_IMAGE) $(EXFAT_IMAGE) $(LTP_DEV_IMAGE) $(SSD_IMAGE) $(XFSTESTS_TEST_IMAGE) $(XFSTESTS_SCRATCH_IMAGE) $(EROFS_BUILD_DEPS)
else
build: $(INITRAMFS_IMAGE) $(EXT2_IMAGE) $(EXFAT_IMAGE) $(LTP_DEV_IMAGE) $(SSD_IMAGE) $(EROFS_BUILD_DEPS)
endif

.PHONY: $(INITRAMFS_IMAGE)
$(INITRAMFS_IMAGE): $(INITRAMFS)
	@nix-build \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		--argstr target $(TARGET_ARCH) \
		--arg enableBenchmarkTest $(ENABLE_BENCHMARK_TEST) \
		--arg enableConformanceTest $(ENABLE_CONFORMANCE_TEST) \
		--arg enableRegressionTest $(ENABLE_REGRESSION_TEST) \
		--argstr conformanceTestSuite $(CONFORMANCE_TEST_SUITE) \
		--argstr conformanceTestWorkDir $(CONFORMANCE_TEST_WORKDIR) \
		--argstr regressionTestPlatform $(REGRESSION_TEST_PLATFORM) \
		--argstr dnsServer ${DNS_SERVER} \
		--arg initramfsCompressed $(INITRAMFS_COMPRESSED) \
		--arg smp $(SMP) \
		--out-link $@ \
		nix -A initramfs-image

.PHONY: $(INITRAMFS)
$(INITRAMFS):
	@nix-build \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		--argstr target $(TARGET_ARCH) \
		--arg enableBenchmarkTest $(ENABLE_BENCHMARK_TEST) \
		--arg enableConformanceTest $(ENABLE_CONFORMANCE_TEST) \
		--arg enableRegressionTest $(ENABLE_REGRESSION_TEST) \
		--argstr conformanceTestSuite $(CONFORMANCE_TEST_SUITE) \
		--argstr conformanceTestWorkDir $(CONFORMANCE_TEST_WORKDIR) \
		--argstr regressionTestPlatform $(REGRESSION_TEST_PLATFORM) \
		--argstr dnsServer ${DNS_SERVER} \
		--arg smp $(SMP) \
		--out-link $@ \
		nix -A initramfs

# Prebuild x86_64 packages
x86_64_pkgs:
	@nix-build \
		nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		$(NIX_QUIET) \
		--argstr target x86_64 \
		--arg enableBenchmarkTest true \
		--arg enableConformanceTest true \
		--out-link /nix/var/nix/gcroots/auto/x86_64-pkgs \
		-A busybox \
		-A benchmark.fio \
		-A benchmark.hackbench \
		-A benchmark.iperf3 \
		-A benchmark.lmbench \
		-A benchmark.memcached \
		-A benchmark.nginx \
		-A benchmark.redis \
		-A benchmark.schbench \
		-A benchmark.sqlite-speedtest1 \
		-A benchmark.sysbench \
		-A conformance.ltp \
		-A conformance.kselftest \
		-A regression.package

# Prebuild riscv64 packages
# Note: This may cause GitHub Runner ResourceExhausted errors when publish nix docker image.
# If such errors occur, try building each package individually and clear the build cache.
riscv64_pkgs:
	@nix-build \
		nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		$(NIX_QUIET) \
		--argstr target riscv64 \
		--arg enableBenchmarkTest false \
		--arg enableConformanceTest true \
		--out-link /nix/var/nix/gcroots/auto/riscv64-pkgs \
		-A busybox \
		-A conformance.ltp \
		-A regression.package

install_host_pkgs:
	@nix-env \
		--file nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		--install \
		-A apacheHttpd \
		-A iperf3 \
		-A libmemcached \
		-A lmbench \
		-A redis

nix_gc:
	@nix-collect-garbage -d

# This target is used to accelerate CI workflows, e.g., `benchmark_x86` and `benchmark_x86_tdx`.
initramfs_pkgs:
	@nix-build \
		nix/default.nix \
		--tarball-ttl $(NIXPKGS_CACHE_TTL) \
		$(NIX_QUIET) \
		--argstr target x86_64 \
		--arg enableBenchmarkTest true \
		--out-link /nix/var/nix/gcroots/auto/x86_64-initramfs-with-benchmark \
		-A initramfs-image

$(EXT2_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@dd if=/dev/zero of=$(EXT2_IMAGE) bs=2G count=1
	@mke2fs $(EXT2_IMAGE)

$(EXFAT_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@fallocate -l 512M $(EXFAT_IMAGE)
	@mkfs.exfat $(EXFAT_IMAGE)

$(LTP_DEV_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@dd if=/dev/zero of=$(LTP_DEV_IMAGE) bs=512M count=1
	@mke2fs -t ext2 -F $(LTP_DEV_IMAGE)

$(SSD_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@dd if=/dev/zero of=$(SSD_IMAGE) bs=256M count=1
	@mke2fs -t ext2 -F $(SSD_IMAGE)

$(XFSTESTS_TEST_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@truncate -s $(XFSTESTS_DISK_SIZE) $(XFSTESTS_TEST_IMAGE)
	@mkfs.ext2 $(XFSTESTS_TEST_IMAGE)

$(XFSTESTS_SCRATCH_IMAGE):
	@mkdir -p $(BUILD_DIR)
	@truncate -s $(XFSTESTS_DISK_SIZE) $(XFSTESTS_SCRATCH_IMAGE)
	@mkfs.ext2 $(XFSTESTS_SCRATCH_IMAGE)

# erofs test image pipeline (T-018; blueprint: docs/T-016/S03/index.md §3).
# Dependency chain: erofs_tree/ files + erofs_stage.sh -> $(EROFS_TREE_STAGE)
# -> C1-C12 mkfs images (parallel; all read-only on the stage tree) -> D1/D2
# derived images. Version gate (erofs-utils 1.7.1) rides the stage self-checks.
#
# The dependency set lists files and directories, NOT symlinks: make stats
# prerequisites through symlinks, and the deliberately dangling pattern
# symlinks under erofs_tree/symlink/ (256B single-component targets >
# NAME_MAX) would fail stat with ENAMETOOLONG ("No rule to make target").
# Symlink-level changes are still caught: creating/replacing/removing any
# dirent updates the parent directory's mtime, and directories are deps.
EROFS_TREE_DEPS := $(shell find $(EROFS_TREE_DIR) \( -type f -o -type d \) 2>/dev/null)

$(EROFS_TREE_STAGE): $(EROFS_STAGE_SCRIPT) $(EROFS_TREE_DEPS)
	@$(EROFS_STAGE_SCRIPT) $(EROFS_TREE_DIR) $(EROFS_TREE_STAGE)

$(EROFS_BASE_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -U $(EROFS_UUID_BASE) $@ $(EROFS_TREE_STAGE)

$(EROFS_BASE_CPT_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -U $(EROFS_UUID_BASE_CPT) -E force-inode-compact $@ $(EROFS_TREE_STAGE)

$(EROFS_UUID0_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -U $(EROFS_UUID0) $@ $(EROFS_TREE_STAGE)

$(EROFS_BS512_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -b 512 $@ $(EROFS_TREE_STAGE)

$(EROFS_BS1024_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -b 1024 $@ $(EROFS_TREE_STAGE)

$(EROFS_BS2048_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -b 2048 $@ $(EROFS_TREE_STAGE)

$(EROFS_COMP_LZ4_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -z lz4 $@ $(EROFS_TREE_STAGE)

$(EROFS_XATTR_SHARED_ALL_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -x0 $@ $(EROFS_TREE_STAGE)

$(EROFS_XATTR_NONE_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs -x-1 $@ $(EROFS_TREE_STAGE)

$(EROFS_PREFIX_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs --xattr-prefix=$(EROFS_XATTR_PREFIX) $@ $(EROFS_TREE_STAGE)

# C11 (docs/T-016/S02/index.md §2): one mkfs call produces two files
# (main image + blob) — grouped target
$(EROFS_FLATDEV_IMAGE) $(EROFS_BLOB_IMAGE) &: $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs --chunksize=$(EROFS_FLATDEV_CHUNKSIZE) --blobdev=$(EROFS_BLOB_IMAGE) $(EROFS_FLATDEV_IMAGE) $(EROFS_TREE_STAGE)

$(EROFS_CHUNK4B_IMAGE): $(EROFS_TREE_STAGE)
	@mkdir -p $(BUILD_DIR)
	@mkfs.erofs --chunksize=$(EROFS_CHUNK4B_CHUNKSIZE) $@ $(EROFS_TREE_STAGE)

$(EROFS_FLATDEV_CONCAT_IMAGE): $(EROFS_FLATDEV_IMAGE) $(EROFS_BLOB_IMAGE)
	@cat $^ > $@

$(EROFS_FLATDEV_BADTAG_IMAGE): $(EROFS_FLATDEV_IMAGE)
	@cp $< $@
	@printf 'XBADTAG!' | dd of=$@ bs=1 seek=$$(( $(EROFS_DEVT_SLOTOFF) * 128 )) conv=notrunc

.PHONY: format
format:
	@$(MAKE) --no-print-directory -C src/regression format
	@nixfmt nix

.PHONY: check
check:
	@$(MAKE) --no-print-directory -C src/regression check
	@nixfmt --check nix

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
