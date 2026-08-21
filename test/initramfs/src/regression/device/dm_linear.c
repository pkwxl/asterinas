// SPDX-License-Identifier: MPL-2.0

/*
 * Regression tests for dm-linear target.
 *
 * Tests the complete workflow: create device, load table, resume, read/write,
 * verify data, cleanup.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/test.h"

#define DM_CONTROL_PATH "/dev/mapper/control"
#define DM_DIR "/dev/mapper"
#define DM_TEST_DEV "dmtest"
#define DM_TEST_NODE "/dev/mapper/dmtest"
#define TEST_PARTITION "/dev/vdd"

#define DM_IOCTL_VERSION 0
#define DM_IOCTL_DEV_CREATE 3
#define DM_IOCTL_DEV_REMOVE 4
#define DM_IOCTL_TABLE_LOAD 9
#define DM_IOCTL_DEV_SUSPEND 6

#define DM_VERSION_MAJOR 4
#define DM_VERSION_MINOR 48
#define DM_VERSION_PATCH 0

#define DM_SUSPEND_FLAG (1 << 1)

#define DM_NAME_LEN 128
#define DM_UUID_LEN 128
#define DM_MAX_TARGETS 256

struct dm_ioctl {
	uint32_t version[3];
	uint32_t data_size;
	uint32_t data_start;
	uint32_t target_count;
	uint32_t open_count;
	int32_t flags;
	uint32_t event_nr;
	uint64_t sector_start;
	uint64_t nr_sectors;
	uint32_t error_cnt;
	uint32_t target_count_extra;
	uint32_t reserved[5];
	char name[DM_NAME_LEN];
	char uuid[DM_UUID_LEN];
	char data[4];
};

struct dm_target_spec {
	uint64_t sector_start;
	uint64_t length;
	int32_t status;
	uint32_t next;
	char target_type[16];
};

#define DM_CTL_MAJOR 10
#define DM_CTL_MINOR 236

static char *dm_ioctl_data(struct dm_ioctl *dev) { return dev->data; }

static int open_dm_control(void) {
	int fd = TEST_SUCC(open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC));
	struct stat st;

	TEST_RES(fstat(fd, &st), S_ISCHR(st.st_mode) &&
					 major(st.st_rdev) == DM_CTL_MAJOR &&
					 minor(st.st_rdev) == DM_CTL_MINOR);

	return fd;
}

static void version_check(int fd) {
	struct dm_ioctl *dev;
	char buf[4096];

	dev = (struct dm_ioctl *)buf;
	memset(dev, 0, sizeof(*dev));
	dev->data_size = sizeof(buf);
	dev->version[0] = DM_VERSION_MAJOR;
	dev->version[1] = DM_VERSION_MINOR;
	dev->version[2] = DM_VERSION_PATCH;

	TEST_RES(ioctl(fd, 0xC138FD00 | DM_IOCTL_VERSION, dev), _ret == 0);
	TEST_RES(dev->version[0], _ret == DM_VERSION_MAJOR);
	TEST_RES(dev->version[1] <= DM_VERSION_MINOR, _ret);
}

static int create_device(int fd, const char *name, uint64_t *dev_number) {
	struct dm_ioctl *dev;
	char buf[4096];

	dev = (struct dm_ioctl *)buf;
	memset(dev, 0, sizeof(*dev));
	dev->data_size = sizeof(buf);
	strncpy(dev->name, name, DM_NAME_LEN - 1);

	TEST_RES(ioctl(fd, 0xC138FD00 | DM_IOCTL_DEV_CREATE, dev), _ret == 0);

	if (dev_number)
		*dev_number = dev->dev;

	return 0;
}

static int remove_device(int fd, const char *name) {
	struct dm_ioctl *dev;
	char buf[4096];

	dev = (struct dm_ioctl *)buf;
	memset(dev, 0, sizeof(*dev));
	dev->data_size = sizeof(buf);
	strncpy(dev->name, name, DM_NAME_LEN - 1);

	return TEST_RES(ioctl(fd, 0xC138FD00 | DM_IOCTL_DEV_REMOVE, dev), _ret == 0);
}

static int load_table(int fd, const char *name, uint64_t sector_start,
					  uint64_t nr_sectors, const char *target_type,
					  const char *target_params) {
	struct dm_ioctl *dev;
	char buf[8192];
	struct dm_target_spec *spec;
	char *data;

	dev = (struct dm_ioctl *)buf;
	memset(dev, 0, sizeof(*dev));
	dev->data_size = sizeof(buf);
	dev->sector_start = sector_start;
	dev->nr_sectors = nr_sectors;
	dev->target_count = 1;
	strncpy(dev->name, name, DM_NAME_LEN - 1);

	data = dm_ioctl_data(dev);
	spec = (struct dm_target_spec *)data;

	spec->sector_start = 0;
	spec->length = nr_sectors;
	spec->next = sizeof(struct dm_target_spec) + strlen(target_type) + 1 +
				 ((8 - (strlen(target_type) + 1)) & 7);
	strncpy(spec->target_type, target_type, sizeof(spec->target_type) - 1);

	char *params = data + spec->next;
	strcpy(params, target_params);

	return TEST_RES(ioctl(fd, 0xC138FD00 | DM_IOCTL_TABLE_LOAD, dev), _ret == 0);
}

static int resume_device(int fd, const char *name) {
	struct dm_ioctl *dev;
	char buf[4096];

	dev = (struct dm_ioctl *)buf;
	memset(dev, 0, sizeof(*dev));
	dev->data_size = sizeof(buf);
	dev->flags = DM_SUSPEND_FLAG;
	strncpy(dev->name, name, DM_NAME_LEN - 1);

	return TEST_RES(ioctl(fd, 0xC138FD00 | DM_IOCTL_DEV_SUSPEND, dev), _ret == 0);
}

static int create_dm_node(uint64_t major, uint64_t minor) {
	char path[256];
	struct stat st;

	snprintf(path, sizeof(path), "/dev/dm-%lu", minor);

	if (stat(path, &st) == 0 && S_ISBLK(st.st_mode))
		return 0;

	return TEST_ERRNO(mknod(path, S_IFBLK | 0644, makedev(major, minor)), EEXIST);
}

static void write_test_pattern(int fd, uint64_t offset, const char *pattern) {
	lseek(fd, offset, SEEK_SET);
	TEST_RES(write(fd, pattern, strlen(pattern)), _ret == strlen(pattern));
}

static bool read_verify_pattern(int fd, uint64_t offset, const char *pattern,
								int len) {
	char buf[256];

	lseek(fd, offset, SEEK_SET);
	memset(buf, 0, sizeof(buf));
	TEST_RES(read(fd, buf, len), _ret == len);

	return memcmp(buf, pattern, strlen(pattern)) == 0;
}

static void cleanup_dm_device(int fd, const char *name) {
	int status_fd;
	char path[256];
	struct stat st;

	snprintf(path, sizeof(path), "/dev/mapper/%s", name);
	status_fd = open(path, O_RDONLY);
	if (status_fd >= 0) {
		close(status_fd);
		remove_device(fd, name);
	}

	snprintf(path, sizeof(path), "/dev/dm-%lu", 0);
	if (stat(path, &st) == 0)
		unlink(path);
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
		if (errno == ENOENT || errno == ENODEV) {
			fprintf(stderr, "dm-linear tests skipped: %s unavailable\n",
					DM_CONTROL_PATH);
			exit(EXIT_SUCCESS);
		}
		CHECK(fd);
	}
	close(fd);

	mkdir(DM_DIR, 0755);
}

END_SETUP()

FN_TEST(dm_linear_version_check) {
	int fd = open_dm_control();
	version_check(fd);
	close(fd);
}
END_TEST()

FN_TEST(dm_linear_create_device) {
	int fd = open_dm_control();
	uint64_t dev_number;

	create_device(fd, DM_TEST_DEV, &dev_number);
	TEST_RES(dev_number, _ret > 0);

	remove_device(fd, DM_TEST_DEV);
	close(fd);
}
END_TEST()

FN_TEST(dm_linear_load_table_and_resume) {
	int control_fd, test_disk_fd;
	struct stat st;
	uint64_t nr_sectors;

	control_fd = open_dm_control();
	version_check(control_fd);

	create_device(control_fd, DM_TEST_DEV, NULL);

	test_disk_fd = TEST_SUCC(open(TEST_PARTITION, O_RDWR));
	TEST_RES(fstat(test_disk_fd, &st), S_ISBLK(st.st_mode));
	nr_sectors = st.st_size / 512;

	close(test_disk_fd);

	load_table(control_fd, DM_TEST_DEV, 0, nr_sectors, "linear",
			   (char[]){TEST_PARTITION, ' ', '0', '\0'});

	resume_device(control_fd, DM_TEST_DEV);
	remove_device(control_fd, DM_TEST_DEV);
	close(control_fd);
}
END_TEST()

FN_TEST(dm_linear_io) {
	int control_fd, dm_fd, test_disk_fd;
	struct stat st;
	uint64_t nr_sectors, dev_major, dev_minor;
	char pattern[256];
	const char *test_pattern = "dm-linear-test-data-2024";
	char dm_path[256];

	control_fd = open_dm_control();
	version_check(control_fd);

	create_device(control_fd, DM_TEST_DEV, &dev_number);
	test_disk_fd = TEST_SUCC(open(TEST_PARTITION, O_RDWR));
	TEST_RES(fstat(test_disk_fd, &st), S_ISBLK(st.st_mode));
	nr_sectors = st.st_size / 512;
	close(test_disk_fd);

	load_table(control_fd, DM_TEST_DEV, 0, nr_sectors, "linear",
			   (char[]){TEST_PARTITION, ' ', '0', '\0'});

	resume_device(control_fd, DM_TEST_DEV);

	snprintf(dm_path, sizeof(dm_path), "/dev/mapper/%s", DM_TEST_DEV);
	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));

	write_test_pattern(dm_fd, 4096, test_pattern);

	test_disk_fd = TEST_SUCC(open(TEST_PARTITION, O_RDWR));
	TEST_RES(read_verify_pattern(test_disk_fd, 4096, test_pattern,
								 strlen(test_pattern)),
			 _ret);
	close(test_disk_fd);
	close(dm_fd);

	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%lu", dev_minor);
	create_dm_node(dev_major, dev_minor);

	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%lu", dev_minor);
	dm_fd = TEST_SUCC(open(dm_path, O_RDWR));

	memset(pattern, 0, sizeof(pattern));
	strncpy(pattern, test_pattern, strlen(test_pattern));
	lseek(dm_fd, 4096 + 512, SEEK_SET);
	TEST_RES(write(dm_fd, pattern, strlen(pattern)), _ret == strlen(pattern));

	test_disk_fd = TEST_SUCC(open(TEST_PARTITION, O_RDWR));
	TEST_RES(read_verify_pattern(test_disk_fd, 4096 + 512, pattern,
								 strlen(pattern)),
			 _ret);

	close(dm_fd);
	close(test_disk_fd);

	remove_device(control_fd, DM_TEST_DEV);
	close(control_fd);

	snprintf(dm_path, sizeof(dm_path), "/dev/dm-%lu", dev_minor);
	unlink(dm_path);
}
END_TEST()

FN_TEST(dm_linear_cleanup) {
	int control_fd;
	char path[256];

	control_fd = open_dm_control();
	remove_device(control_fd, DM_TEST_DEV);
	close(control_fd);

	snprintf(path, sizeof(path), "/dev/mapper/%s", DM_TEST_DEV);
	unlink(path);

	snprintf(path, sizeof(path), "/dev/dm-%lu", 0);
	unlink(path);
}
END_TEST()
