// SPDX-License-Identifier: MPL-2.0

/*
 * Regression tests for the dm-linear target.
 *
 * Tests the complete workflow: create device, load table, resume, read/write,
 * verify data, cleanup. All ioctls use the real Linux DM ABI (see
 * include/uapi/linux/dm-ioctl.h).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "../common/test.h"

#define DM_CONTROL_PATH "/dev/mapper/control"
#define DM_DIR "/dev/mapper"
#define DM_TEST_DEV "dmtest"
#define TEST_PARTITION "/dev/vdd"

#define DM_IOCTL_VERSION 0
#define DM_IOCTL_DEV_CREATE 3
#define DM_IOCTL_DEV_REMOVE 4
#define DM_IOCTL_DEV_STATUS 7
#define DM_IOCTL_DEV_SUSPEND 6
#define DM_IOCTL_TABLE_LOAD 9

#define DM_VERSION_MAJOR 4
#define DM_VERSION_MINOR 48
#define DM_VERSION_PATCH 0

#define DM_SUSPEND_FLAG (1 << 1)
#define DM_ACTIVE_PRESENT_FLAG (1 << 5)
#define DM_INACTIVE_PRESENT_FLAG (1 << 6)

#define DM_NAME_LEN 128
#define DM_UUID_LEN 129

#define DM_CTL_MAJOR 10
#define DM_CTL_MINOR 236

#define DM_BLOCK_MAJOR 253

/* _IOR(0x12, 114, u64); <linux/fs.h> is not available in this build env. */
#define BLKGETSIZE64 0x80081272

/* struct dm_ioctl, exactly as in linux/include/uapi/linux/dm-ioctl.h
 * (sizeof == 312). */
struct dm_ioctl {
	uint32_t version[3];
	uint32_t data_size;
	uint32_t data_start;
	uint32_t target_count;
	int32_t open_count;
	uint32_t flags;
	uint32_t event_nr;
	uint32_t padding;
	uint64_t dev;
	char name[DM_NAME_LEN];
	char uuid[DM_UUID_LEN];
	char data[7];
};

/* struct dm_target_spec (sizeof == 40), immediately followed by the
 * NUL-terminated parameter string, 8-byte aligned. */
struct dm_target_spec {
	uint64_t sector_start;
	uint64_t length;
	int32_t status;
	uint32_t next;
	char target_type[16];
};

#define DM_CMD(nr) (0xC138FD00 | (nr))

/* Fills the common header fields every DM ioctl needs. */
static void dm_ioctl_init(struct dm_ioctl *dev, const char *name,
			  size_t data_size) {
	memset(dev, 0, sizeof(*dev));
	dev->version[0] = DM_VERSION_MAJOR;
	dev->version[1] = DM_VERSION_MINOR;
	dev->version[2] = DM_VERSION_PATCH;
	dev->data_size = data_size;
	dev->data_start = sizeof(struct dm_ioctl);
	if (name)
		strncpy(dev->name, name, DM_NAME_LEN - 1);
}

/*
 * The helpers below are plain functions (not FN_TEST bodies), so they must
 * not use the TEST_*() macros; they return -1/0 on failure and leave the
 * assertions to their callers.
 */

static int do_version_check(int fd) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, NULL, sizeof(buf));

	if (ioctl(fd, DM_CMD(DM_IOCTL_VERSION), dev) < 0)
		return -1;
	if (dev->version[0] != DM_VERSION_MAJOR ||
	    dev->version[1] > DM_VERSION_MINOR)
		return -1;
	return 0;
}

/* Creates a DM device and returns the kernel-reported device number,
 * or 0 on failure. */
static uint64_t do_create_device(int fd, const char *name) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));

	if (ioctl(fd, DM_CMD(DM_IOCTL_DEV_CREATE), dev) < 0)
		return 0;

	return dev->dev;
}

static int do_remove_device(int fd, const char *name) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));

	return ioctl(fd, DM_CMD(DM_IOCTL_DEV_REMOVE), dev);
}

/* Queries DEV_STATUS, returning the reported flags via `flags` and the
 * device number via `dev_number` (both may be NULL). */
static int do_status_device(int fd, const char *name, uint32_t *flags,
			    uint64_t *dev_number) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));

	if (ioctl(fd, DM_CMD(DM_IOCTL_DEV_STATUS), dev) < 0)
		return -1;

	if (flags)
		*flags = dev->flags;
	if (dev_number)
		*dev_number = dev->dev;
	return 0;
}

static int do_load_linear_table(int fd, const char *name, uint64_t nr_sectors,
				const char *target_params) {
	struct dm_ioctl *dev;
	char buf[4096];
	struct dm_target_spec *spec;
	char *data, *params;
	size_t params_len;

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));
	dev->target_count = 1;

	data = buf + dev->data_start;
	spec = (struct dm_target_spec *)data;
	spec->sector_start = 0;
	spec->length = nr_sectors;
	spec->status = 0;
	strncpy(spec->target_type, "linear", sizeof(spec->target_type) - 1);

	params = data + sizeof(*spec);
	strcpy(params, target_params);
	params_len = strlen(params) + 1;
	spec->next = (sizeof(*spec) + params_len + 7) & ~7UL;

	return ioctl(fd, DM_CMD(DM_IOCTL_TABLE_LOAD), dev);
}

/* Resumes the device (promotes the inactive table to active). */
static int do_resume_device(int fd, const char *name) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));
	dev->flags = 0; /* no DM_SUSPEND_FLAG: this is a resume */

	return ioctl(fd, DM_CMD(DM_IOCTL_DEV_SUSPEND), dev);
}

/* mknod(2) that tolerates an already-existing node. */
static int mknod_or_exist(const char *path, mode_t mode, dev_t dev) {
	if (mknod(path, mode, dev) < 0 && errno != EEXIST)
		return -1;
	return 0;
}

static uint64_t get_partition_nr_sectors(void) {	int fd = open(TEST_PARTITION, O_RDWR);
	uint64_t size_bytes = 0;

	if (fd < 0)
		return 0;
	/* fstat() does not report the size of a block device; ask the
	 * driver via BLKGETSIZE64 instead. */
	if (ioctl(fd, BLKGETSIZE64, &size_bytes) < 0)
		size_bytes = 0;
	close(fd);

	return size_bytes / 512;
}

FN_SETUP(dm_linear_prepare_test_env) {
	int fd;

	fd = open(TEST_PARTITION, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "dm-linear tests skipped: %s unavailable\n",
			TEST_PARTITION);
		exit(EXIT_SUCCESS);
	}
	close(fd);

	fd = open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT) {
			/* The devtmpfs node may be missing; mknod it. */
			mkdir(DM_DIR, 0755);
			CHECK(mknod(DM_CONTROL_PATH, S_IFCHR | 0600,
				    makedev(DM_CTL_MAJOR, DM_CTL_MINOR)));
			fd = CHECK(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
		} else if (errno == ENODEV) {
			fprintf(stderr,
				"dm-linear tests skipped: %s unavailable\n",
				DM_CONTROL_PATH);
			exit(EXIT_SUCCESS);
		} else {
			CHECK(fd);
		}
	}
	close(fd);
}

END_SETUP()

FN_TEST(dm_linear_version_check) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct stat st;

	TEST_RES(fstat(fd, &st), S_ISCHR(st.st_mode) &&
					 major(st.st_rdev) == DM_CTL_MAJOR &&
					 minor(st.st_rdev) == DM_CTL_MINOR);
	TEST_RES(do_version_check(fd), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_linear_create_status_remove) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	uint64_t dev_number, status_dev = 0;
	uint32_t flags = 0;

	TEST_RES(do_version_check(fd), _ret == 0);

	dev_number = do_create_device(fd, DM_TEST_DEV);
	TEST_RES(dev_number, _ret != 0);
	/* The major is 253 if DM could acquire it, otherwise a dynamic one;
	 * user space must use whatever DEV_CREATE reports. */
	TEST_RES(minor(dev_number), _ret == 0);

	TEST_RES(do_status_device(fd, DM_TEST_DEV, &flags, &status_dev),
		 _ret == 0);
	TEST_RES(status_dev, _ret == dev_number);
	TEST_RES(flags,
		 (_ret & (DM_ACTIVE_PRESENT_FLAG | DM_INACTIVE_PRESENT_FLAG)) ==
			 0);

	TEST_RES(do_remove_device(fd, DM_TEST_DEV), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_linear_load_table_and_resume) {
	int control_fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	uint64_t nr_sectors;
	uint32_t flags = 0;

	TEST_RES(do_version_check(control_fd), _ret == 0);

	TEST_RES(do_create_device(control_fd, DM_TEST_DEV), _ret != 0);

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);
	TEST_RES(do_load_linear_table(control_fd, DM_TEST_DEV, nr_sectors,
				      TEST_PARTITION " 0"),
		 _ret == 0);

	TEST_RES(do_status_device(control_fd, DM_TEST_DEV, &flags, NULL),
		 _ret == 0);
	TEST_RES(flags, (_ret & DM_INACTIVE_PRESENT_FLAG) != 0);

	TEST_RES(do_resume_device(control_fd, DM_TEST_DEV), _ret == 0);

	TEST_RES(do_status_device(control_fd, DM_TEST_DEV, &flags, NULL),
		 _ret == 0);
	TEST_RES(flags, (_ret & DM_ACTIVE_PRESENT_FLAG) != 0);

	TEST_RES(do_remove_device(control_fd, DM_TEST_DEV), _ret == 0);
	close(control_fd);
}
END_TEST()

FN_TEST(dm_linear_io) {
	int control_fd, dm_fd, test_disk_fd;
	uint64_t nr_sectors, dev_number;
	const char *test_pattern = "dm-linear-test-data-2026";
	const char *test_pattern2 = "dm-linear-second-write!";
	char buf[512];
	char dm_path[64];

	control_fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	TEST_RES(do_version_check(control_fd), _ret == 0);

	dev_number = do_create_device(control_fd, DM_TEST_DEV);
	TEST_RES(dev_number, _ret != 0);

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);
	TEST_RES(do_load_linear_table(control_fd, DM_TEST_DEV, nr_sectors,
				      TEST_PARTITION " 0"),
		 _ret == 0);
	TEST_RES(do_resume_device(control_fd, DM_TEST_DEV), _ret == 0);

	/* Runtime-registered DM devices do not get a devtmpfs node
	 * automatically; mknod it with the device number from DEV_CREATE. */
	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%u", minor(dev_number));
	TEST_SUCC(mknod_or_exist(dm_path, S_IFBLK | 0644, dev_number));

	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));

	/* Write via the dm device, verify on the underlying disk. */
	TEST_RES(pwrite(dm_fd, test_pattern, strlen(test_pattern), 4096),
		 _ret == (ssize_t)strlen(test_pattern));

	test_disk_fd = TEST_SUCC(open(TEST_PARTITION, O_RDWR));
	memset(buf, 0, sizeof(buf));
	TEST_RES(pread(test_disk_fd, buf, strlen(test_pattern), 4096),
		 _ret == (ssize_t)strlen(test_pattern));
	TEST_RES(memcmp(buf, test_pattern, strlen(test_pattern)), _ret == 0);

	/* Write to the underlying disk, verify via the dm device. */
	memset(buf, 0, sizeof(buf));
	memcpy(buf, test_pattern2, strlen(test_pattern2));
	TEST_RES(pwrite(test_disk_fd, buf, 512, 8192), _ret == 512);
	close(test_disk_fd);

	memset(buf, 0, sizeof(buf));
	TEST_RES(pread(dm_fd, buf, strlen(test_pattern2), 8192),
		 _ret == (ssize_t)strlen(test_pattern2));
	TEST_RES(memcmp(buf, test_pattern2, strlen(test_pattern2)), _ret == 0);

	close(dm_fd);

	TEST_RES(do_remove_device(control_fd, DM_TEST_DEV), _ret == 0);
	close(control_fd);

	unlink(dm_path);
}
END_TEST()

FN_TEST(dm_linear_cleanup) {
	/* Best-effort cleanup in case a previous test aborted midway. */
	int control_fd = open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC);
	if (control_fd >= 0) {
		struct dm_ioctl *dev;
		char buf[512];

		dev = (struct dm_ioctl *)buf;
		dm_ioctl_init(dev, DM_TEST_DEV, sizeof(buf));
		ioctl(control_fd, DM_CMD(DM_IOCTL_DEV_REMOVE), dev);
		close(control_fd);
	}

	unlink("/dev/dm-0");
}
END_TEST()
