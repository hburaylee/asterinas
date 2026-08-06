// SPDX-License-Identifier: MPL-2.0

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../common/test.h"

#define BASE "/squashfs"

#define LONG_FILENAME                                        \
	"long_filename_"                                     \
	"00000000000000000000000000000000000000000000000000" \
	"00000000000000000000000000000000000000000000000000" \
	"00000000000000000000000000000000000000000000000000" \
	"00000000000000000000000000000000000000000000000000" \
	".txt"

FN_TEST(read_small_file)
{
	const char *expected = "hello squashfs\n";
	char buf[64] = { 0 };

	int fd = TEST_SUCC(open(BASE "/small.txt", O_RDONLY));
	TEST_RES(read(fd, buf, sizeof(buf)), _ret == (ssize_t)strlen(expected));
	TEST_RES(memcmp(buf, expected, strlen(expected)), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(read_empty_file)
{
	struct stat st;
	TEST_SUCC(stat(BASE "/empty.txt", &st));
	TEST_RES(st.st_size, _ret == 0);

	int fd = TEST_SUCC(open(BASE "/empty.txt", O_RDONLY));
	char buf[1];
	TEST_RES(read(fd, buf, sizeof(buf)), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(read_exact_block_file)
{
	struct stat st;
	TEST_SUCC(stat(BASE "/exact_block.bin", &st));
	TEST_RES(st.st_size, _ret == 4096);

	int fd = TEST_SUCC(open(BASE "/exact_block.bin", O_RDONLY));
	char buf[4096];
	TEST_RES(read(fd, buf, sizeof(buf)), _ret == 4096);

	int all_a = 1;
	for (int i = 0; i < 4096; i++) {
		if (buf[i] != 'A') {
			all_a = 0;
			break;
		}
	}
	TEST_RES(all_a, _ret == 1);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(read_large_file)
{
	const int expected_size = 128 * 1024;
	struct stat st;
	TEST_SUCC(stat(BASE "/large.bin", &st));
	TEST_RES(st.st_size, _ret == expected_size);

	int fd = TEST_SUCC(open(BASE "/large.bin", O_RDONLY));
	unsigned char buf[4096];
	int total = 0;
	ssize_t n;
	int correct = 1;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		for (int i = 0; i < n; i++) {
			if (buf[i] != (unsigned char)((total + i) % 256)) {
				correct = 0;
				break;
			}
		}
		total += n;
		if (!correct)
			break;
	}
	TEST_RES(total, _ret == expected_size);
	TEST_RES(correct, _ret == 1);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(read_fragment_file)
{
	const char *expected = "fragment_test\n";
	char buf[64] = { 0 };

	int fd = TEST_SUCC(open(BASE "/fragment.txt", O_RDONLY));
	TEST_RES(read(fd, buf, sizeof(buf)), _ret == (ssize_t)strlen(expected));
	TEST_RES(memcmp(buf, expected, strlen(expected)), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(read_symlink)
{
	char buf[PATH_MAX] = { 0 };
	const char *target = "small.txt";

	TEST_RES(readlink(BASE "/link.txt", buf, sizeof(buf)),
		 _ret == (ssize_t)strlen(target));
	buf[strlen(target)] = '\0';
	TEST_RES(strcmp(buf, target), _ret == 0);

	char data[64] = { 0 };
	int fd = TEST_SUCC(open(BASE "/link.txt", O_RDONLY));
	TEST_RES(read(fd, data, sizeof(data)), _ret == 15);
	TEST_RES(memcmp(data, "hello squashfs\n", 15), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(read_long_target_symlink)
{
	char buf[PATH_MAX] = { 0 };
	const char *target = "a/b/c/d/e/f/g/h/deep.txt";

	TEST_RES(readlink(BASE "/long_target_link", buf, sizeof(buf)),
		 _ret == (ssize_t)strlen(target));
	buf[strlen(target)] = '\0';
	TEST_RES(strcmp(buf, target), _ret == 0);

	char data[64] = { 0 };
	int fd = TEST_SUCC(open(BASE "/long_target_link", O_RDONLY));
	TEST_RES(read(fd, data, sizeof(data)), _ret == 10);
	TEST_RES(memcmp(data, "deep file\n", 10), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(deep_path_access)
{
	struct stat st;
	TEST_SUCC(stat(BASE "/a/b/c/d/e/f/g/h/deep.txt", &st));
	TEST_RES(S_ISREG(st.st_mode), _ret != 0);
	TEST_RES(st.st_size, _ret == 10);

	for (int i = 0; i < 8; i++) {
		const char *dirs[] = {
			BASE "/a",
			BASE "/a/b",
			BASE "/a/b/c",
			BASE "/a/b/c/d",
			BASE "/a/b/c/d/e",
			BASE "/a/b/c/d/e/f",
			BASE "/a/b/c/d/e/f/g",
			BASE "/a/b/c/d/e/f/g/h",
		};
		TEST_SUCC(stat(dirs[i], &st));
		TEST_RES(S_ISDIR(st.st_mode), _ret != 0);
	}
}
END_TEST()

FN_TEST(readdir_many_entries)
{
	DIR *dp = TEST_SUCC(opendir(BASE "/many_entries"));
	int count = 0;
	while (readdir(dp) != NULL)
		count++;
	closedir(dp);
	TEST_RES(count, _ret == 200 + 2);
}
END_TEST()

FN_TEST(readdir_dot_dotdot)
{
	DIR *dp = TEST_SUCC(opendir(BASE "/a"));
	struct dirent *ent;
	int found_dot = 0, found_dotdot = 0;
	while ((ent = readdir(dp)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0)
			found_dot = 1;
		else if (strcmp(ent->d_name, "..") == 0)
			found_dotdot = 1;
	}
	closedir(dp);
	TEST_RES(found_dot, _ret == 1);
	TEST_RES(found_dotdot, _ret == 1);
}
END_TEST()

FN_TEST(readdir_root)
{
	DIR *dp = TEST_SUCC(opendir(BASE));
	int count = 0;
	int found_small = 0, found_empty = 0, found_a = 0, found_link = 0;
	struct dirent *ent;
	while ((ent = readdir(dp)) != NULL) {
		if (strcmp(ent->d_name, "small.txt") == 0)
			found_small = 1;
		else if (strcmp(ent->d_name, "empty.txt") == 0)
			found_empty = 1;
		else if (strcmp(ent->d_name, "a") == 0)
			found_a = 1;
		else if (strcmp(ent->d_name, "link.txt") == 0)
			found_link = 1;
		count++;
	}
	closedir(dp);
	TEST_RES(found_small, _ret == 1);
	TEST_RES(found_empty, _ret == 1);
	TEST_RES(found_a, _ret == 1);
	TEST_RES(found_link, _ret == 1);
}
END_TEST()

FN_TEST(long_filename)
{
	struct stat st;
	TEST_SUCC(stat(BASE "/" LONG_FILENAME, &st));
	TEST_RES(S_ISREG(st.st_mode), _ret != 0);
}
END_TEST()

FN_TEST(check_permissions)
{
	struct stat st;

	TEST_SUCC(stat(BASE "/permissions/readonly.txt", &st));
	TEST_RES(st.st_mode & 0777, _ret == 0444);

	TEST_SUCC(stat(BASE "/permissions/executable.sh", &st));
	TEST_RES(st.st_mode & 0777, _ret == 0755);

	TEST_SUCC(stat(BASE "/permissions/noperm.txt", &st));
	TEST_RES(st.st_mode & 0777, _ret == 0000);
}
END_TEST()

FN_TEST(stat_metadata_types)
{
	struct stat st;

	TEST_SUCC(stat(BASE "/small.txt", &st));
	TEST_RES(S_ISREG(st.st_mode), _ret != 0);

	TEST_SUCC(stat(BASE "/a", &st));
	TEST_RES(S_ISDIR(st.st_mode), _ret != 0);

	TEST_SUCC(lstat(BASE "/link.txt", &st));
	TEST_RES(S_ISLNK(st.st_mode), _ret != 0);
}
END_TEST()

FN_TEST(mixed_types_dir)
{
	struct stat st;

	TEST_SUCC(stat(BASE "/mixed_types/regular.txt", &st));
	TEST_RES(S_ISREG(st.st_mode), _ret != 0);

	TEST_SUCC(stat(BASE "/mixed_types/subdir", &st));
	TEST_RES(S_ISDIR(st.st_mode), _ret != 0);

	TEST_SUCC(lstat(BASE "/mixed_types/symlink", &st));
	TEST_RES(S_ISLNK(st.st_mode), _ret != 0);

	char data[64] = { 0 };
	int fd = TEST_SUCC(open(BASE "/mixed_types/symlink", O_RDONLY));
	TEST_RES(read(fd, data, sizeof(data)), _ret == 8);
	TEST_RES(memcmp(data, "regular\n", 8), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(write_returns_erofs)
{
	int fd;

	fd = TEST_SUCC(open(BASE "/small.txt", O_WRONLY));
	TEST_ERRNO(write(fd, "x", 1), EROFS);
	TEST_SUCC(close(fd));

	fd = TEST_SUCC(open(BASE "/small.txt", O_RDWR));
	TEST_ERRNO(write(fd, "x", 1), EROFS);
	TEST_SUCC(close(fd));

	TEST_ERRNO(mkdir(BASE "/newdir", 0755), EROFS);
	TEST_ERRNO(unlink(BASE "/small.txt"), EROFS);
	TEST_ERRNO(symlink("target", BASE "/new_link"), EROFS);
	TEST_ERRNO(rename(BASE "/small.txt", BASE "/renamed.txt"), EROFS);
}
END_TEST()

FN_TEST(seek_and_read)
{
	int fd = TEST_SUCC(open(BASE "/large.bin", O_RDONLY));

	TEST_SUCC(lseek(fd, 4096, SEEK_SET));
	unsigned char buf[4];
	TEST_RES(read(fd, buf, sizeof(buf)), _ret == 4);
	TEST_RES(buf[0], _ret == (4096 % 256));
	TEST_RES(buf[1], _ret == (4097 % 256));

	TEST_SUCC(lseek(fd, -4, SEEK_END));
	TEST_RES(read(fd, buf, sizeof(buf)), _ret == 4);
	int base = 128 * 1024 - 4;
	TEST_RES(buf[0], _ret == (base % 256));

	TEST_SUCC(close(fd));
}
END_TEST()
