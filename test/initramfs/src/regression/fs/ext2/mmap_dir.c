// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../common/test.h"

#define BASE_DIR "/ext2/mmap_dir_test"
#define TEST_FILE BASE_DIR "/file"
#define FILE_CONTENT "hello mmap"
#define PAGE_SIZE 4096

FN_SETUP(create_file)
{
	CHECK_WITH(mkdir(BASE_DIR, 0755), _ret == 0 || errno == EEXIST);

	int fd = CHECK(open(TEST_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644));
	CHECK(write(fd, FILE_CONTENT, sizeof(FILE_CONTENT)));
	CHECK(close(fd));
}
END_SETUP()

FN_TEST(mmap_dir_enodev)
{
	/*
	 * Directories are not mappable: mmap must fail with ENODEV, even
	 * though the inode of an on-disk directory is backed by a page cache
	 * just like a regular file. Without the check on the inode type, the
	 * raw directory blocks (including deleted file names) would be exposed
	 * to user space.
	 */
	int fd = TEST_SUCC(open(BASE_DIR, O_RDONLY | O_DIRECTORY));

	TEST_ERRNO(mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0),
		   ENODEV);
	TEST_ERRNO(mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0), ENODEV);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(mmap_regular_file)
{
	/* Sanity check: regular files on the same file system are mappable. */
	int fd = TEST_SUCC(open(TEST_FILE, O_RDONLY));

	char *addr =
		TEST_RES(mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0),
			 _ret != MAP_FAILED);
	TEST_RES(memcmp(addr, FILE_CONTENT, sizeof(FILE_CONTENT)), _ret == 0);
	TEST_SUCC(munmap(addr, PAGE_SIZE));

	TEST_SUCC(close(fd));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(unlink(TEST_FILE));
	CHECK(rmdir(BASE_DIR));
}
END_SETUP()
