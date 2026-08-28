// SPDX-License-Identifier: MPL-2.0

/*
 * Regression tests for the dm-striped target.
 *
 * Tests the complete workflow: create device, load a 2-leg striped table,
 * resume, read/write across chunk boundaries, cross-verify the stripe
 * distribution on both underlying disks, TABLE_STATUS, malformed-table
 * rejection, cleanup. All ioctls use the real Linux DM ABI (see
 * include/uapi/linux/dm-ioctl.h).
 *
 * Table under test (chunk_size = 8 sectors = 4096 bytes, stripes = 2,
 * both physical starts 0):
 *
 *     0 4096 striped 2 8 vdd 0 vde 0
 *
 * Mapping: dm chunk c (4096-byte unit) lands on leg (c % 2) at byte
 * offset (c / 2) * 4096 + (offset within chunk).
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
#define DM_TEST_DEV "dmstriptest"
#define TEST_DISK_A "/dev/vdd"
#define TEST_DISK_B "/dev/vde"

#define DM_IOCTL_VERSION 0
#define DM_IOCTL_DEV_CREATE 3
#define DM_IOCTL_DEV_REMOVE 4
#define DM_IOCTL_DEV_SUSPEND 6
#define DM_IOCTL_TABLE_LOAD 9
#define DM_IOCTL_TABLE_STATUS 12

#define DM_VERSION_MAJOR 4
#define DM_VERSION_MINOR 48
#define DM_VERSION_PATCH 0

#define DM_SUSPEND_FLAG (1 << 1)
#define DM_STATUS_TABLE_FLAG (1 << 4)
#define DM_QUERY_INACTIVE_TABLE_FLAG (1 << 12)

#define DM_NAME_LEN 128
#define DM_UUID_LEN 129

#define DM_CTL_MAJOR 10
#define DM_CTL_MINOR 236

/* stripe geometry: 8 sectors per chunk, 2 stripes */
#define CHUNK_BYTES 4096
#define TABLE_SECTORS 4096
/* Bare device names: TABLE_STATUS reports them without the /dev/ prefix,
 * so load with bare names to make the table string comparable. */
#define STRIPE_PARAMS "2 8 vdd 0 vde 0"

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

/* Loads a single-target striped table: `0 <nr_sectors> striped <params>`. */
static int do_load_striped_table(int fd, const char *name, uint64_t nr_sectors,
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
	strncpy(spec->target_type, "striped", sizeof(spec->target_type) - 1);

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

FN_SETUP(dm_stripe_prepare_test_env) {
	int fd;

	fd = open(TEST_DISK_A, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "dm-striped tests skipped: %s unavailable\n",
			TEST_DISK_A);
		exit(EXIT_SUCCESS);
	}
	close(fd);

	fd = open(TEST_DISK_B, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "dm-striped tests skipped: %s unavailable\n",
			TEST_DISK_B);
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
				"dm-striped tests skipped: %s unavailable\n",
				DM_CONTROL_PATH);
			exit(EXIT_SUCCESS);
		} else {
			CHECK(fd);
		}
	}
	close(fd);
}

END_SETUP()

FN_TEST(dm_stripe_version_check) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct stat st;

	TEST_RES(fstat(fd, &st), S_ISCHR(st.st_mode) &&
					 major(st.st_rdev) == DM_CTL_MAJOR &&
					 minor(st.st_rdev) == DM_CTL_MINOR);
	TEST_RES(do_version_check(fd), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_stripe_bad_tables) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, DM_TEST_DEV), _ret != 0);

	/* length not divisible by stripes: 4095 % 2 != 0 */
	TEST_ERRNO(do_load_striped_table(fd, DM_TEST_DEV, 4095, STRIPE_PARAMS),
		   EINVAL);
	/* width (len / stripes) not divisible by chunk_size: 12 % 8 != 0 */
	TEST_ERRNO(do_load_striped_table(fd, DM_TEST_DEV, 24, STRIPE_PARAMS),
		   EINVAL);
	/* missing one leg: argc (3) != 2 + 2 * stripes (6) */
	TEST_ERRNO(do_load_striped_table(fd, DM_TEST_DEV, TABLE_SECTORS,
					 "2 8 vdd 0"),
		   EINVAL);

	/* The failed loads must not prevent removing the device. */
	TEST_RES(do_remove_device(fd, DM_TEST_DEV), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_stripe_table_status) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct dm_ioctl *io;
	struct dm_target_spec *spec;
	char buf[4096];
	char *params;

	TEST_RES(do_version_check(fd), _ret == 0);
	TEST_RES(do_create_device(fd, DM_TEST_DEV), _ret != 0);
	TEST_RES(do_load_striped_table(fd, DM_TEST_DEV, TABLE_SECTORS,
				       STRIPE_PARAMS),
		 _ret == 0);

	io = (struct dm_ioctl *)buf;
	dm_ioctl_init(io, DM_TEST_DEV, sizeof(buf));
	/* The device is still suspended (no resume yet), so the live table
	 * is empty; query the inactive table explicitly, as Linux requires.
	 * DM_STATUS_TABLE_FLAG selects the STATUSTYPE_TABLE (ctr-params)
	 * form of the parameter string. */
	io->flags = DM_QUERY_INACTIVE_TABLE_FLAG | DM_STATUS_TABLE_FLAG;
	TEST_SUCC(ioctl(fd, DM_CMD(DM_IOCTL_TABLE_STATUS), io));

	TEST_RES(io->target_count, _ret == 1);
	spec = (struct dm_target_spec *)(buf + io->data_start);
	TEST_RES(spec->sector_start, _ret == 0);
	TEST_RES(spec->length, _ret == TABLE_SECTORS);
	TEST_RES(strcmp(spec->target_type, "striped"), _ret == 0);
	params = (char *)spec + sizeof(*spec);
	TEST_RES(strcmp(params, STRIPE_PARAMS), _ret == 0);

	TEST_RES(do_remove_device(fd, DM_TEST_DEV), _ret == 0);
	close(fd);
}
END_TEST()

FN_TEST(dm_stripe_io) {
	int control_fd, dm_fd, disk_a_fd, disk_b_fd;
	uint64_t dev_number;
	char dm_path[64];
	/* 3 consecutive chunks (chunk 0/1/2) written via the dm device. */
	static char wbuf[3 * CHUNK_BYTES];
	static char rbuf[3 * CHUNK_BYTES];
	char xbuf[1024];
	char verify[1024];
	const char *rev_pattern = "dm-stripe-reverse-write-check!";
	size_t i;

	control_fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	TEST_RES(do_version_check(control_fd), _ret == 0);

	dev_number = do_create_device(control_fd, DM_TEST_DEV);
	TEST_RES(dev_number, _ret != 0);

	TEST_RES(do_load_striped_table(control_fd, DM_TEST_DEV, TABLE_SECTORS,
				       STRIPE_PARAMS),
		 _ret == 0);
	TEST_RES(do_resume_device(control_fd, DM_TEST_DEV), _ret == 0);

	/* Runtime-registered DM devices do not get a devtmpfs node
	 * automatically; mknod it with the device number from DEV_CREATE. */
	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%u", minor(dev_number));
	TEST_SUCC(mknod_or_exist(dm_path, S_IFBLK | 0644, dev_number));

	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));
	disk_a_fd = TEST_SUCC(open(TEST_DISK_A, O_RDWR));
	disk_b_fd = TEST_SUCC(open(TEST_DISK_B, O_RDWR));

	/* Fill each 512-byte sector of wbuf with a distinct byte value. */
	for (i = 0; i < sizeof(wbuf); i++)
		wbuf[i] = (char)(0xA0 + i / 512);

	/* (1) Write chunks 0,1,2 via the dm device at offset 0. */
	TEST_RES(pwrite(dm_fd, wbuf, sizeof(wbuf), 0),
		 _ret == (ssize_t)sizeof(wbuf));

	/* chunk 0 -> leg A (vdd) @ 0 */
	memset(rbuf, 0, sizeof(rbuf));
	TEST_RES(pread(disk_a_fd, rbuf, CHUNK_BYTES, 0),
		 _ret == CHUNK_BYTES);
	TEST_RES(memcmp(rbuf, wbuf, CHUNK_BYTES), _ret == 0);

	/* chunk 1 -> leg B (vde) @ 0 */
	memset(rbuf, 0, sizeof(rbuf));
	TEST_RES(pread(disk_b_fd, rbuf, CHUNK_BYTES, 0),
		 _ret == CHUNK_BYTES);
	TEST_RES(memcmp(rbuf, wbuf + CHUNK_BYTES, CHUNK_BYTES), _ret == 0);

	/* chunk 2 -> leg A (vdd) @ 4096 */
	memset(rbuf, 0, sizeof(rbuf));
	TEST_RES(pread(disk_a_fd, rbuf, CHUNK_BYTES, CHUNK_BYTES),
		 _ret == CHUNK_BYTES);
	TEST_RES(memcmp(rbuf, wbuf + 2 * CHUNK_BYTES, CHUNK_BYTES),
		 _ret == 0);

	/* Read the same 3-chunk region back through the dm device. */
	memset(rbuf, 0, sizeof(rbuf));
	TEST_RES(pread(dm_fd, rbuf, sizeof(wbuf), 0),
		 _ret == (ssize_t)sizeof(wbuf));
	TEST_RES(memcmp(rbuf, wbuf, sizeof(wbuf)), _ret == 0);

	/* (2) Cross-chunk-boundary write: 1024B at dm offset
	 * 3*4096+3584 = 15872. The first 512B stay in chunk 3
	 * (-> leg B @ 4096+3584 = 7680), the second 512B cross into
	 * chunk 4 (-> leg A @ 8192). */
	for (i = 0; i < sizeof(xbuf); i++)
		xbuf[i] = (char)(0x40 + i / 512);
	TEST_RES(pwrite(dm_fd, xbuf, sizeof(xbuf), 3 * CHUNK_BYTES + 3584),
		 _ret == (ssize_t)sizeof(xbuf));

	memset(verify, 0, sizeof(verify));
	TEST_RES(pread(disk_b_fd, verify, 512, CHUNK_BYTES + 3584),
		 _ret == 512);
	TEST_RES(memcmp(verify, xbuf, 512), _ret == 0);

	memset(verify, 0, sizeof(verify));
	TEST_RES(pread(disk_a_fd, verify, 512, 2 * CHUNK_BYTES), _ret == 512);
	TEST_RES(memcmp(verify, xbuf + 512, 512), _ret == 0);

	/* (3) Reverse direction: write leg B directly, read via the dm
	 * device. vde @ 12288 == dm chunk 7 ((7/2)*4096) == dm offset
	 * 7*4096 = 28672. */
	memset(verify, 0, sizeof(verify));
	memcpy(verify, rev_pattern, strlen(rev_pattern));
	TEST_RES(pwrite(disk_b_fd, verify, 512, 3 * CHUNK_BYTES), _ret == 512);

	memset(verify, 0, sizeof(verify));
	TEST_RES(pread(dm_fd, verify, strlen(rev_pattern), 7 * CHUNK_BYTES),
		 _ret == (ssize_t)strlen(rev_pattern));
	TEST_RES(memcmp(verify, rev_pattern, strlen(rev_pattern)), _ret == 0);

	/* DEV_REMOVE requires open_count == 0: close the dm device first. */
	close(dm_fd);
	close(disk_a_fd);
	close(disk_b_fd);

	TEST_RES(do_remove_device(control_fd, DM_TEST_DEV), _ret == 0);
	close(control_fd);

	unlink(dm_path);
}
END_TEST()

FN_TEST(dm_stripe_cleanup) {
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
