// SPDX-License-Identifier: MPL-2.0

/*
 * Regression tests for the DM control-plane ioctls added by the audit
 * remediation (docs/014 wave 2/3): DEV_RENAME (name and uuid),
 * LIST_DEVICES, TABLE_DEPS, TABLE_CLEAR, GET_TARGET_VERSION,
 * SET_GEOMETRY, DM_READONLY_FLAG, DM_DEFERRED_REMOVE_FLAG (including
 * `@cancel_deferred_remove`), DM_PERSISTENT_DEV_FLAG, plus the
 * error-path contract (EINVAL/EBUSY/ENXIO/ENOTTY). All ioctls use the
 * real Linux DM ABI (see include/uapi/linux/dm-ioctl.h).
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
#define TEST_PARTITION "/dev/vdd"

#define DM_IOCTL_VERSION 0
#define DM_IOCTL_LIST_DEVICES 2
#define DM_IOCTL_DEV_CREATE 3
#define DM_IOCTL_DEV_REMOVE 4
#define DM_IOCTL_DEV_RENAME 5
#define DM_IOCTL_DEV_SUSPEND 6
#define DM_IOCTL_DEV_STATUS 7
#define DM_IOCTL_TABLE_LOAD 9
#define DM_IOCTL_TABLE_CLEAR 10
#define DM_IOCTL_TABLE_DEPS 11
#define DM_IOCTL_TARGET_MSG 14
#define DM_IOCTL_DEV_SET_GEOMETRY 15
#define DM_IOCTL_GET_TARGET_VERSION 17

#define DM_VERSION_MAJOR 4
#define DM_VERSION_MINOR 48
#define DM_VERSION_PATCH 0

#define DM_READONLY_FLAG (1 << 0)
#define DM_SUSPEND_FLAG (1 << 1)
#define DM_PERSISTENT_DEV_FLAG (1 << 3)
#define DM_ACTIVE_PRESENT_FLAG (1 << 5)
#define DM_INACTIVE_PRESENT_FLAG (1 << 6)
#define DM_BUFFER_FULL_FLAG (1 << 8)
#define DM_UUID_FLAG (1 << 14)
#define DM_DEFERRED_REMOVE_FLAG (1 << 17)

#define DM_NAME_LIST_FLAG_HAS_UUID 1
#define DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID 2

#define DM_NAME_LEN 128
#define DM_UUID_LEN 129

#define DM_CTL_MAJOR 10
#define DM_CTL_MINOR 236

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

/* struct dm_name_list (fixed part; see dm-ioctl.h). After the
 * NUL-terminated name, padded to 8 bytes, come `event_nr` and `flags`,
 * then the uuid (only with DM_UUID_FLAG and DM_NAME_LIST_FLAG_HAS_UUID). */
struct dm_name_list {
	uint64_t dev;
	uint32_t next;
	char name[];
};

/* struct dm_target_versions. */
struct dm_target_versions {
	uint32_t next;
	uint32_t version[3];
	char name[];
};

/* struct dm_target_deps. */
struct dm_target_deps {
	uint32_t count;
	uint32_t padding;
	uint64_t dev[];
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

/* Queries DEV_STATUS, returning the reported flags, device number and
 * event number via the out parameters (each may be NULL). */
static int do_status_device(int fd, const char *name, uint32_t *flags,
			    uint64_t *dev_number, uint32_t *event_nr) {
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
	if (event_nr)
		*event_nr = dev->event_nr;
	return 0;
}

/* Loads a single-target linear table: `0 <nr_sectors> linear <params>`.
 * `load_flags` are ORed into `dm_ioctl.flags` (e.g. DM_READONLY_FLAG). */
static int do_load_linear_table(int fd, const char *name, uint64_t nr_sectors,
				const char *target_params, uint32_t load_flags) {
	struct dm_ioctl *dev;
	char buf[4096];
	struct dm_target_spec *spec;
	char *data, *params;
	size_t params_len;

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));
	dev->target_count = 1;
	dev->flags = load_flags;

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

static int do_suspend_resume(int fd, const char *name, int suspend) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));
	dev->flags = suspend ? DM_SUSPEND_FLAG : 0;

	return ioctl(fd, DM_CMD(DM_IOCTL_DEV_SUSPEND), dev);
}

/* DEV_RENAME: the new name (or, with DM_UUID_FLAG, the new uuid) is the
 * NUL-terminated string at `data_start`. */
static int do_rename_device(int fd, const char *name, const char *new_name,
			    uint32_t flags) {
	struct dm_ioctl *dev;
	char buf[512];
	char *data;

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));
	dev->flags = flags;

	data = buf + dev->data_start;
	strcpy(data, new_name);

	return ioctl(fd, DM_CMD(DM_IOCTL_DEV_RENAME), dev);
}

/* DM_TARGET_MSG with the given message string (sector is 0; the DM core
 * messages we use are sector-independent). */
static int do_target_msg(int fd, const char *name, const char *msg) {
	struct dm_ioctl *dev;
	char buf[512];
	char *data;

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));

	data = buf + dev->data_start;
	memset(data, 0, 8); /* sector */
	strcpy(data + 8, msg);

	return ioctl(fd, DM_CMD(DM_IOCTL_TARGET_MSG), dev);
}

/* mknod(2) that tolerates an already-existing node. */
static int mknod_or_exist(const char *path, mode_t mode, dev_t dev) {
	if (mknod(path, mode, dev) < 0 && errno != EEXIST)
		return -1;
	return 0;
}

static uint64_t get_partition_nr_sectors(void) {
	int fd = open(TEST_PARTITION, O_RDWR);
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

/* Best-effort removal of a device that may not exist. */
static void remove_if_exists(int fd, const char *name) {
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, name, sizeof(buf));
	ioctl(fd, DM_CMD(DM_IOCTL_DEV_REMOVE), dev);
}

FN_SETUP(dm_ioctl_prepare_test_env) {
	int fd;

	fd = open(TEST_PARTITION, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "dm-ioctl tests skipped: %s unavailable\n",
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
				"dm-ioctl tests skipped: %s unavailable\n",
				DM_CONTROL_PATH);
			exit(EXIT_SUCCESS);
		} else {
			CHECK(fd);
		}
	}
	close(fd);
}

END_SETUP()

FN_TEST(dm_ioctl_unknown_command) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *dev;
	char buf[512];

	/* An unassigned DM command number. */
	dev = (struct dm_ioctl *)buf;
	dm_ioctl_init(dev, NULL, sizeof(buf));
	TEST_ERRNO(ioctl(fd, DM_CMD(18), dev), ENOTTY);

	/* A valid command number with a wrong ioctl encoding (the size
	 * bits do not match `struct dm_ioctl`). */
	dm_ioctl_init(dev, NULL, sizeof(buf));
	TEST_ERRNO(ioctl(fd, 0xC004FD03, dev), ENOTTY);

	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_name_validation) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *dev;
	char buf[512];

	dev = (struct dm_ioctl *)buf;

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, "w4dup"), _ret != 0);

	/* Duplicate name. */
	TEST_ERRNO(do_create_device(fd, "w4dup"), EBUSY);

	/* Invalid names: empty, containing '/', and the reserved ones. */
	dm_ioctl_init(dev, NULL, sizeof(buf));
	TEST_ERRNO(ioctl(fd, DM_CMD(DM_IOCTL_DEV_CREATE), dev), EINVAL);
	TEST_ERRNO(do_create_device(fd, "a/b"), EINVAL);
	TEST_ERRNO(do_create_device(fd, "control"), EINVAL);
	TEST_ERRNO(do_create_device(fd, ".."), EINVAL);

	/* Status of a nonexistent device. */
	TEST_ERRNO(do_status_device(fd, "w4noexist", NULL, NULL, NULL), ENXIO);

	TEST_RES(do_remove_device(fd, "w4dup"), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_suspend_resume_errors) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	uint64_t nr_sectors;
	uint32_t flags = 0;

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, "w4susp"), _ret != 0);

	/* A freshly created device is born suspended. */
	TEST_RES(do_status_device(fd, "w4susp", &flags, NULL, NULL), _ret == 0);
	TEST_RES(flags, (_ret & DM_SUSPEND_FLAG) != 0);

	/* Resume without any table. */
	TEST_ERRNO(do_suspend_resume(fd, "w4susp", 0), EINVAL);
	/* Suspend an already-suspended device. */
	TEST_ERRNO(do_suspend_resume(fd, "w4susp", 1), EINVAL);

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);
	TEST_RES(do_load_linear_table(fd, "w4susp", nr_sectors,
				      TEST_PARTITION " 0", 0),
		 _ret == 0);

	TEST_RES(do_suspend_resume(fd, "w4susp", 0), _ret == 0);
	/* Resume an already-live device. */
	TEST_ERRNO(do_suspend_resume(fd, "w4susp", 0), EINVAL);

	TEST_RES(do_suspend_resume(fd, "w4susp", 1), _ret == 0);
	/* Suspend twice. */
	TEST_ERRNO(do_suspend_resume(fd, "w4susp", 1), EINVAL);

	TEST_RES(do_remove_device(fd, "w4susp"), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_rename_and_uuid) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *dev;
	char buf[512];
	uint32_t event_nr_before = 0, event_nr_after = 0;

	dev = (struct dm_ioctl *)buf;

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, "w4ren_a"), _ret != 0);
	TEST_RES(do_create_device(fd, "w4ren_c"), _ret != 0);

	/* Rename to an already-taken name. */
	TEST_ERRNO(do_rename_device(fd, "w4ren_a", "w4ren_c", 0), EBUSY);

	/* Rename, then the old name must be gone and the new one live. */
	TEST_RES(do_status_device(fd, "w4ren_a", NULL, NULL, &event_nr_before),
		 _ret == 0);
	TEST_RES(do_rename_device(fd, "w4ren_a", "w4ren_b", 0), _ret == 0);
	TEST_ERRNO(do_status_device(fd, "w4ren_a", NULL, NULL, NULL), ENXIO);
	TEST_RES(do_status_device(fd, "w4ren_b", NULL, NULL, &event_nr_after),
		 _ret == 0);
	/* A rename is an event: the device event number must advance. */
	TEST_RES(event_nr_after, _ret > event_nr_before);

	/* Rename to an invalid name. */
	TEST_ERRNO(do_rename_device(fd, "w4ren_b", "x/y", 0), EINVAL);

	/* Set a uuid, then look the device up by uuid. */
	TEST_RES(do_rename_device(fd, "w4ren_b", "w4-uuid-1", DM_UUID_FLAG),
		 _ret == 0);
	dm_ioctl_init(dev, NULL, sizeof(buf));
	strncpy(dev->uuid, "w4-uuid-1", DM_UUID_LEN - 1);
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_DEV_STATUS), dev));
	TEST_RES(strcmp(dev->name, "w4ren_b"), _ret == 0);
	TEST_RES(strcmp(dev->uuid, "w4-uuid-1"), _ret == 0);

	/* A uuid can only be set once, and must be unique. */
	TEST_ERRNO(do_rename_device(fd, "w4ren_b", "w4-uuid-2", DM_UUID_FLAG),
		 EINVAL);
	TEST_ERRNO(do_rename_device(fd, "w4ren_c", "w4-uuid-1", DM_UUID_FLAG),
		 EBUSY);

	TEST_RES(do_remove_device(fd, "w4ren_b"), _ret == 0);
	TEST_RES(do_remove_device(fd, "w4ren_c"), _ret == 0);
	close(fd);
}
END_TEST()

/* Walks a LIST_DEVICES result and records how many devices match the
 * names in `wanted` (bitmask by index); returns the record count. */
static int list_devices_collect(int fd, const char *name_pfx, uint32_t flags,
				uint64_t *devs, uint32_t *uuid_flags,
				int max_records) {
	struct dm_ioctl *io;
	char buf[4096];
	struct dm_name_list *nl;
	uint32_t offset;
	int count = 0;

	io = (struct dm_ioctl *)buf;
	dm_ioctl_init(io, NULL, sizeof(buf));
	io->flags = flags;
	if (name_pfx)
		strncpy(io->name, name_pfx, DM_NAME_LEN - 1);

	if (ioctl(fd, DM_CMD(DM_IOCTL_LIST_DEVICES), io) < 0)
		return -1;
	if (io->flags & DM_BUFFER_FULL_FLAG)
		return -1;

	offset = 0;
	while (offset < io->data_size - io->data_start) {
		nl = (struct dm_name_list *)(buf + io->data_start + offset);
		if (count < max_records) {
			/* event_nr/flags sit right after the NUL-terminated
			 * name, padded to an 8-byte boundary (offsets are
			 * relative to the record start, which is itself
			 * 8-byte aligned). The fixed header is 12 bytes
			 * (dev + next); sizeof(struct dm_name_list) would
			 * be padded to 16. */
			size_t name_end = 12 + strlen(nl->name) + 1;
			uint32_t *ext =
				(uint32_t *)((char *)nl + ((name_end + 7) & ~7UL));

			devs[count] = nl->dev;
			uuid_flags[count] = ext[1];
		}
		count++;
		if (nl->next == 0)
			break;
		offset += nl->next;
	}
	return count;
}

FN_TEST(dm_ioctl_list_devices) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *io;
	char buf[512];
	uint64_t devs[4];
	uint32_t uuid_flags[4];
	uint64_t dev_a, dev_b;
	int count, i, seen_a, seen_b;

	TEST_RES(do_version_check(fd), _ret == 0);

	dev_a = do_create_device(fd, "w4list_a");
	TEST_RES(dev_a, _ret != 0);
	dev_b = do_create_device(fd, "w4list_b");
	TEST_RES(dev_b, _ret != 0);
	TEST_RES(do_rename_device(fd, "w4list_b", "w4-uuid-b", DM_UUID_FLAG),
		 _ret == 0);

	/* Prefix-filtered listing: exactly our two devices. */
	count = list_devices_collect(fd, "w4list", 0, devs, uuid_flags, 4);
	TEST_RES(count, _ret == 2);
	seen_a = seen_b = 0;
	for (i = 0; i < 2 && i < count; i++) {
		if (devs[i] == dev_a) {
			seen_a = 1;
			TEST_RES(uuid_flags[i],
				 _ret == DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID);
		}
		if (devs[i] == dev_b) {
			seen_b = 1;
			TEST_RES(uuid_flags[i],
				 _ret == DM_NAME_LIST_FLAG_HAS_UUID);
		}
	}
	TEST_RES(seen_a && seen_b, _ret != 0);

	/* A longer prefix filters down to a single device. */
	count = list_devices_collect(fd, "w4list_a", 0, devs, uuid_flags, 4);
	TEST_RES(count, _ret == 1);
	TEST_RES(devs[0], _ret == dev_a);

	/* A buffer too small for the records sets DM_BUFFER_FULL_FLAG. */
	io = (struct dm_ioctl *)buf;
	dm_ioctl_init(io, "w4list", sizeof(struct dm_ioctl) + 8);
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_LIST_DEVICES), io));
	TEST_RES(io->flags, (_ret & DM_BUFFER_FULL_FLAG) != 0);

	TEST_RES(do_remove_device(fd, "w4list_a"), _ret == 0);
	TEST_RES(do_remove_device(fd, "w4list_b"), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_table_deps) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *io;
	struct dm_target_deps *deps;
	char buf[4096];
	struct stat st;
	uint64_t nr_sectors;

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_SUCC(stat(TEST_PARTITION, &st));

	/* A device without a table reports no deps (and no error). */
	TEST_RES(do_create_device(fd, "w4deps"), _ret != 0);
	io = (struct dm_ioctl *)buf;
	dm_ioctl_init(io, "w4deps", sizeof(buf));
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_TABLE_DEPS), io));

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);
	TEST_RES(do_load_linear_table(fd, "w4deps", nr_sectors,
				      TEST_PARTITION " 0", 0),
		 _ret == 0);
	TEST_RES(do_suspend_resume(fd, "w4deps", 0), _ret == 0);

	/* The active table depends on exactly the underlying disk. */
	dm_ioctl_init(io, "w4deps", sizeof(buf));
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_TABLE_DEPS), io));
	deps = (struct dm_target_deps *)(buf + io->data_start);
	TEST_RES(deps->count, _ret == 1);
	TEST_RES(deps->dev[0], _ret == (uint64_t)st.st_rdev);

	/* A buffer too small for the deps sets DM_BUFFER_FULL_FLAG. */
	dm_ioctl_init(io, "w4deps", sizeof(struct dm_ioctl) + 8);
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_TABLE_DEPS), io));
	TEST_RES(io->flags, (_ret & DM_BUFFER_FULL_FLAG) != 0);

	TEST_RES(do_remove_device(fd, "w4deps"), _ret == 0);
	close(fd);
}
END_TEST()

/* Queries GET_TARGET_VERSION for `target`, returning the version via
 * `version` (may be NULL); -1 on ioctl failure. */
static int do_get_target_version(int fd, const char *target,
				 uint32_t version[3]) {
	struct dm_ioctl *io;
	char buf[512];
	struct dm_target_versions *tv;

	io = (struct dm_ioctl *)buf;
	dm_ioctl_init(io, target, sizeof(buf));

	if (ioctl(fd, DM_CMD(DM_IOCTL_GET_TARGET_VERSION), io) < 0)
		return -1;

	tv = (struct dm_target_versions *)(buf + io->data_start);
	if (tv->next != 0 || strcmp(tv->name, target) != 0)
			return -1;
	if (version)
		memcpy(version, tv->version, sizeof(tv->version));
	return 0;
}

FN_TEST(dm_ioctl_get_target_version) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	uint32_t version[3];

	TEST_RES(do_version_check(fd), _ret == 0);

	TEST_RES(do_get_target_version(fd, "linear", version), _ret == 0);
	TEST_RES(version[0], _ret == 1);
	TEST_RES(version[1], _ret == 4);
	TEST_RES(version[2], _ret == 0);

	TEST_RES(do_get_target_version(fd, "striped", version), _ret == 0);
	TEST_RES(version[0], _ret == 1);
	TEST_RES(version[1], _ret == 6);
	TEST_RES(version[2], _ret == 0);

	TEST_RES(do_get_target_version(fd, "error", version), _ret == 0);
	TEST_RES(version[0], _ret == 1);
	TEST_RES(version[1], _ret == 7);
	TEST_RES(version[2], _ret == 0);

	TEST_ERRNO(do_get_target_version(fd, "nosuchtarget", NULL), EINVAL);

	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_set_geometry) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *io;
	char buf[512];

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, "w4geo"), _ret != 0);

#define DO_SET_GEOMETRY(str)                                     \
	({                                                       \
		io = (struct dm_ioctl *)buf;                     \
		dm_ioctl_init(io, "w4geo", sizeof(buf));         \
		strcpy(buf + io->data_start, str);               \
		ioctl(fd, DM_CMD(DM_IOCTL_DEV_SET_GEOMETRY), io); \
	})

	TEST_RES(DO_SET_GEOMETRY("100 4 32 0"), _ret == 0);
	/* On success the command reports no output data. */
	TEST_RES(io->data_size, _ret == 0);

	/* Wrong field count, non-numeric fields, out-of-range values. */
	TEST_ERRNO(DO_SET_GEOMETRY("1 2 3"), EINVAL);
	TEST_ERRNO(DO_SET_GEOMETRY("1 2 3 4 5"), EINVAL);
	TEST_ERRNO(DO_SET_GEOMETRY("a b c d"), EINVAL);
	TEST_ERRNO(DO_SET_GEOMETRY("70000 1 1 0"), EINVAL);
	TEST_ERRNO(DO_SET_GEOMETRY("1 300 1 0"), EINVAL);
	TEST_ERRNO(DO_SET_GEOMETRY("1 1 300 0"), EINVAL);
	TEST_ERRNO(DO_SET_GEOMETRY("1 1 1 2"), EINVAL);

#undef DO_SET_GEOMETRY

	TEST_RES(do_remove_device(fd, "w4geo"), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_readonly) {
	int control_fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	int dm_fd;
	uint64_t nr_sectors, dev_number;
	uint32_t flags = 0;
	char dm_path[64];
	char buf[512];

	TEST_RES(do_version_check(control_fd), _ret == 0);

	dev_number = do_create_device(control_fd, "w4ro");
	TEST_RES(dev_number, _ret != 0);

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);
	/* DM_READONLY_FLAG on TABLE_LOAD makes the table read-only. */
	TEST_RES(do_load_linear_table(control_fd, "w4ro", nr_sectors,
				      TEST_PARTITION " 0", DM_READONLY_FLAG),
		 _ret == 0);
	TEST_RES(do_suspend_resume(control_fd, "w4ro", 0), _ret == 0);

	TEST_RES(do_status_device(control_fd, "w4ro", &flags, NULL, NULL),
		 _ret == 0);
	TEST_RES(flags, (_ret & DM_READONLY_FLAG) != 0);

	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%u", minor(dev_number));
	TEST_SUCC(mknod_or_exist(dm_path, S_IFBLK | 0644, dev_number));
	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));

	/* Writes are refused (no EROFS channel exists; the bio enqueue
	 * failure surfaces as EBUSY), reads still work. */
	TEST_ERRNO(pwrite(dm_fd, buf, sizeof(buf), 0), EBUSY);
	TEST_RES(pread(dm_fd, buf, sizeof(buf), 0), _ret == (ssize_t)sizeof(buf));

	close(dm_fd);
	TEST_RES(do_remove_device(control_fd, "w4ro"), _ret == 0);
	close(control_fd);

	unlink(dm_path);
}
END_TEST()

FN_TEST(dm_ioctl_deferred_remove) {
	int control_fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	int dm_fd;
	uint64_t nr_sectors, dev_number;
	uint32_t flags = 0;
	char dm_path[64];
	char buf[512];
	int i, gone;

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);

	/* (1) Deferred remove: the device disappears on the last close. */
	dev_number = do_create_device(control_fd, "w4def");
	TEST_RES(dev_number, _ret != 0);
	TEST_RES(do_load_linear_table(control_fd, "w4def", nr_sectors,
				      TEST_PARTITION " 0", 0),
		 _ret == 0);
	TEST_RES(do_suspend_resume(control_fd, "w4def", 0), _ret == 0);

	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%u", minor(dev_number));
	TEST_SUCC(mknod_or_exist(dm_path, S_IFBLK | 0644, dev_number));
	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));

	/* A plain remove fails while the device is open... */
	TEST_ERRNO(do_remove_device(control_fd, "w4def"), EBUSY);

	/* ...but arming a deferred remove succeeds and reports the flag. */
	{
		struct dm_ioctl *io;
		char ctl_buf[512];

		io = (struct dm_ioctl *)ctl_buf;
		dm_ioctl_init(io, "w4def", sizeof(ctl_buf));
		io->flags = DM_DEFERRED_REMOVE_FLAG;
		TEST_SUCC(ioctl(control_fd, DM_CMD(DM_IOCTL_DEV_REMOVE), io));
		TEST_RES(io->flags, (_ret & DM_DEFERRED_REMOVE_FLAG) != 0);
	}

	/* The device is still listed and usable until the last close. */
	TEST_RES(do_status_device(control_fd, "w4def", &flags, NULL, NULL),
		 _ret == 0);
	TEST_RES(flags, (_ret & DM_DEFERRED_REMOVE_FLAG) != 0);
	TEST_RES(pread(dm_fd, buf, sizeof(buf), 0), _ret == (ssize_t)sizeof(buf));

	close(dm_fd);

	/* The finalization happens on the last close; poll briefly to
	 * tolerate any asynchronous drop of the file handle. */
	gone = 0;
	for (i = 0; i < 100 && !gone; i++) {
		if (do_status_device(control_fd, "w4def", NULL, NULL, NULL) < 0 &&
		    errno == ENXIO)
			gone = 1;
		else
			usleep(1000);
	}
	TEST_RES(gone, _ret != 0);
	unlink(dm_path);

	/* (2) `@cancel_deferred_remove` disarms a pending removal. */
	dev_number = do_create_device(control_fd, "w4def2");
	TEST_RES(dev_number, _ret != 0);
	TEST_RES(do_load_linear_table(control_fd, "w4def2", nr_sectors,
				      TEST_PARTITION " 0", 0),
		 _ret == 0);
	TEST_RES(do_suspend_resume(control_fd, "w4def2", 0), _ret == 0);

	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%u", minor(dev_number));
	TEST_SUCC(mknod_or_exist(dm_path, S_IFBLK | 0644, dev_number));
	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));

	{
		struct dm_ioctl *io;
		char ctl_buf[512];

		io = (struct dm_ioctl *)ctl_buf;
		dm_ioctl_init(io, "w4def2", sizeof(ctl_buf));
		io->flags = DM_DEFERRED_REMOVE_FLAG;
		TEST_SUCC(ioctl(control_fd, DM_CMD(DM_IOCTL_DEV_REMOVE), io));
	}
	TEST_RES(do_target_msg(control_fd, "w4def2", "@cancel_deferred_remove"),
		 _ret == 0);

	close(dm_fd);

	/* The device must still exist, with the deferred flag cleared. */
	TEST_RES(do_status_device(control_fd, "w4def2", &flags, NULL, NULL),
		 _ret == 0);
	TEST_RES(flags, (_ret & DM_DEFERRED_REMOVE_FLAG) == 0);
	TEST_RES(do_remove_device(control_fd, "w4def2"), _ret == 0);
	close(control_fd);

	unlink(dm_path);
}
END_TEST()

FN_TEST(dm_ioctl_table_clear) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	uint64_t nr_sectors;
	uint32_t flags = 0;

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, "w4clr"), _ret != 0);

	nr_sectors = get_partition_nr_sectors();
	TEST_RES(nr_sectors, _ret > 0);
	TEST_RES(do_load_linear_table(fd, "w4clr", nr_sectors,
				      TEST_PARTITION " 0", 0),
		 _ret == 0);
	TEST_RES(do_status_device(fd, "w4clr", &flags, NULL, NULL), _ret == 0);
	TEST_RES(flags, (_ret & DM_INACTIVE_PRESENT_FLAG) != 0);

	/* TABLE_CLEAR discards the inactive table and is idempotent. */
	{
		struct dm_ioctl *io;
		char ctl_buf[512];

		io = (struct dm_ioctl *)ctl_buf;
		dm_ioctl_init(io, "w4clr", sizeof(ctl_buf));
		TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_TABLE_CLEAR), io));
		TEST_RES(io->flags, (_ret & DM_INACTIVE_PRESENT_FLAG) == 0);
		TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_TABLE_CLEAR), io));
	}

	/* With no table at all, resume is rejected again. */
	TEST_ERRNO(do_suspend_resume(fd, "w4clr", 0), EINVAL);

	TEST_RES(do_remove_device(fd, "w4clr"), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_persistent_dev) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *dev;
	char buf[512];
	uint64_t dev_number, requested;
	unsigned int dm_major;

	TEST_RES(do_version_check(fd), _ret == 0);

	/* Learn the (possibly dynamic) DM block major from a normal
	 * creation, then hand it back via DM_PERSISTENT_DEV_FLAG. */
	dev_number = do_create_device(fd, "w4pd0");
	TEST_RES(dev_number, _ret != 0);
	dm_major = major(dev_number);
	TEST_RES(do_remove_device(fd, "w4pd0"), _ret == 0);

	dev = (struct dm_ioctl *)buf;
	requested = makedev(dm_major, 77);
	dm_ioctl_init(dev, "w4pd1", sizeof(buf));
	dev->flags = DM_PERSISTENT_DEV_FLAG;
	dev->dev = requested;
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_DEV_CREATE), dev));
	TEST_RES(dev->dev, _ret == requested);

	/* The same minor cannot be handed out twice. */
	dm_ioctl_init(dev, "w4pd2", sizeof(buf));
	dev->flags = DM_PERSISTENT_DEV_FLAG;
	dev->dev = requested;
	TEST_ERRNO(ioctl(fd, DM_CMD(DM_IOCTL_DEV_CREATE), dev), EBUSY);

	/* A device number outside the DM block major is invalid. */
	dm_ioctl_init(dev, "w4pd3", sizeof(buf));
	dev->flags = DM_PERSISTENT_DEV_FLAG;
	dev->dev = makedev(dm_major + 100, 77);
	TEST_ERRNO(ioctl(fd, DM_CMD(DM_IOCTL_DEV_CREATE), dev), EINVAL);

	TEST_RES(do_remove_device(fd, "w4pd1"), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_ioctl_cleanup) {
	/* Best-effort cleanup in case a previous test aborted midway. */
	static const char *names[] = {
		"w4dup",   "w4susp",  "w4ren_a", "w4ren_b", "w4ren_c",
		"w4list_a", "w4list_b", "w4deps", "w4geo",  "w4ro",
		"w4def",   "w4def2",  "w4clr",   "w4pd0",   "w4pd1",
		"w4pd2",   "w4pd3",
	};
	int control_fd = open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC);
	size_t i;

	if (control_fd >= 0) {
		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
			remove_if_exists(control_fd, names[i]);
		close(control_fd);
	}
}
END_TEST()
