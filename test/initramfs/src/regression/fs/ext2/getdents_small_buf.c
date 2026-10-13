// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

#define BASE_DIR "/ext2/getdents_small_buf_test"

#define NUM_SHORT_FILES 4
#define LONG_NAME_LEN 100
/* The short files, the long file, "." and "..". */
#define NUM_ENTRIES (NUM_SHORT_FILES + 1 + 2)

/*
 * The length of the shortest possible directory entry record: the offset of
 * `d_name` (19 for `getdents64`, 18 for the legacy `getdents`), plus one name
 * byte, the NUL terminator (and the trailing `d_type` byte for the legacy
 * `getdents`), rounded up to the 8-byte alignment. Both layouts give 24.
 */
#define MIN_DIRENT_LEN 24

struct linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static char long_name[LONG_NAME_LEN + 1];

static void create_test_file(const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s", BASE_DIR, name);
	int fd = CHECK(open(path, O_CREAT | O_WRONLY, 0644));
	CHECK(close(fd));
}

FN_SETUP(create_dir)
{
	memset(long_name, 'x', LONG_NAME_LEN);
	long_name[LONG_NAME_LEN] = '\0';

	CHECK_WITH(mkdir(BASE_DIR, 0755), _ret == 0 || errno == EEXIST);

	for (int i = 0; i < NUM_SHORT_FILES; i++) {
		char name[8];

		snprintf(name, sizeof(name), "f%d", i);
		create_test_file(name);
	}
	create_test_file(long_name);
}
END_SETUP()

FN_TEST(getdents64_tiny_buffer_einval)
{
	int fd = TEST_SUCC(open(BASE_DIR, O_RDONLY | O_DIRECTORY));
	char buf[MIN_DIRENT_LEN * 4];

	/*
	 * The buffer cannot hold even the first (shortest possible) entry, so
	 * each call must fail with EINVAL instead of reporting EOF (0), which
	 * would make libc report an empty directory.
	 */
	const size_t tiny_lens[] = { 0, 1, 8, MIN_DIRENT_LEN - 1 };
	for (size_t i = 0; i < sizeof(tiny_lens) / sizeof(tiny_lens[0]); i++)
		TEST_ERRNO(syscall(SYS_getdents64, fd, buf, tiny_lens[i]),
			   EINVAL);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(getdents_tiny_buffer_einval)
{
#ifdef SYS_getdents
	int fd = TEST_SUCC(open(BASE_DIR, O_RDONLY | O_DIRECTORY));
	char buf[MIN_DIRENT_LEN * 4];

	TEST_ERRNO(syscall(SYS_getdents, fd, buf, 10), EINVAL);
	TEST_ERRNO(syscall(SYS_getdents, fd, buf, MIN_DIRENT_LEN - 1), EINVAL);

	TEST_SUCC(close(fd));
#else
	SKIP_TEST_IF(1); /* The legacy getdents syscall does not exist */
#endif
}
END_TEST()

FN_TEST(getdents64_small_buffer_partial_read)
{
	int fd = TEST_SUCC(open(BASE_DIR, O_RDONLY | O_DIRECTORY));

	/*
	 * The buffer fits the longest single record but not the whole
	 * directory, so reading until EOF must take several calls, each
	 * returning the number of bytes written, and every entry must be
	 * seen exactly once.
	 */
	char buf[128];
	int num_reads = 0;
	int num_entries = 0;
	int short_hits = 0;
	int long_hits = 0;

	for (;;) {
		long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		TEST(nread, 0,
		     _ret == 0 || (_ret > 0 && _ret <= (long)sizeof(buf)));
		if (nread <= 0)
			break;

		num_reads++;
		for (long pos = 0; pos < nread;) {
			struct linux_dirent64 *d =
				(struct linux_dirent64 *)(buf + pos);

			if (strcmp(d->d_name, long_name) == 0)
				long_hits++;
			else if (strlen(d->d_name) == 2 && d->d_name[0] == 'f')
				short_hits++;
			num_entries++;
			pos += d->d_reclen;
		}
	}

	TEST_SUCC(close(fd));

	TEST_RES(num_reads, _ret > 1);
	TEST_RES(num_entries, _ret == NUM_ENTRIES);
	TEST_RES(short_hits, _ret == NUM_SHORT_FILES);
	TEST_RES(long_hits, _ret == 1);
}
END_TEST()

FN_TEST(getdents64_large_buffer_then_eof)
{
	int fd = TEST_SUCC(open(BASE_DIR, O_RDONLY | O_DIRECTORY));
	static char buf[8192];

	long nread = TEST_RES(syscall(SYS_getdents64, fd, buf, sizeof(buf)),
			      _ret > 0);

	int num_entries = 0;
	for (long pos = 0; pos < nread;) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);

		num_entries++;
		pos += d->d_reclen;
	}
	TEST_RES(num_entries, _ret == NUM_ENTRIES);

	/* The call after the last entry must report EOF, not an error. */
	TEST_RES(syscall(SYS_getdents64, fd, buf, sizeof(buf)), _ret == 0);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_SETUP(cleanup)
{
	char path[256];

	for (int i = 0; i < NUM_SHORT_FILES; i++) {
		snprintf(path, sizeof(path), BASE_DIR "/f%d", i);
		CHECK(unlink(path));
	}
	snprintf(path, sizeof(path), BASE_DIR "/%s", long_name);
	CHECK(unlink(path));
	CHECK(rmdir(BASE_DIR));
}
END_SETUP()
