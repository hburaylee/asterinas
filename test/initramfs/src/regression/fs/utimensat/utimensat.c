// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define TEST_FILE "/tmp/utimensat_at_empty_path"

static int fd = -1;

FN_SETUP(prepare)
{
	fd = CHECK(open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644));
}
END_SETUP()

FN_TEST(both_omitted_ignores_path_and_flags)
{
	struct timespec times[2] = {
		{ .tv_sec = 1234567899, .tv_nsec = UTIME_OMIT },
		{ .tv_sec = 1234567898, .tv_nsec = UTIME_OMIT },
	};
	TEST_SUCC(utimensat(AT_FDCWD, TEST_FILE, times, 0xdeadbeef));
	TEST_SUCC(utimensat(AT_FDCWD, "/tmp/nonexistent_file", times, 0));
}
END_TEST()

FN_TEST(at_empty_path_updates_times)
{
	struct timespec times[2] = {
		{ .tv_sec = 1234567890, .tv_nsec = 0 },
		{ .tv_sec = 1234567891, .tv_nsec = 0 },
	};
	TEST_SUCC(utimensat(fd, "", times, AT_EMPTY_PATH));

	struct stat st;
	TEST_RES(fstat(fd, &st), st.st_atim.tv_sec == 1234567890 &&
					 st.st_mtim.tv_sec == 1234567891);
}
END_TEST()

FN_TEST(empty_path_without_flag_returns_enoent)
{
	struct timespec times[2] = {
		{ .tv_sec = 1, .tv_nsec = 0 },
		{ .tv_sec = 1, .tv_nsec = 0 },
	};
	TEST_ERRNO(utimensat(fd, "", times, 0), ENOENT);
}
END_TEST()

FN_TEST(legacy_null_pathname)
{
	struct timespec times[2] = {
		{ .tv_sec = 1000000000, .tv_nsec = 0 },
		{ .tv_sec = 1000000001, .tv_nsec = 0 },
	};
	TEST_SUCC(syscall(SYS_utimensat, fd, NULL, times, 0));

	struct stat st;
	TEST_RES(fstat(fd, &st), st.st_atim.tv_sec == 1000000000 &&
					 st.st_mtim.tv_sec == 1000000001);
}
END_TEST()

FN_TEST(legacy_null_pathname_with_nonzero_flag_returns_einval)
{
	struct timespec times[2] = {
		{ .tv_sec = 1, .tv_nsec = 0 },
		{ .tv_sec = 1, .tv_nsec = 0 },
	};
	TEST_ERRNO(syscall(SYS_utimensat, fd, NULL, times, AT_SYMLINK_NOFOLLOW),
		   EINVAL);
}
END_TEST()

FN_TEST(legacy_null_pathname_with_o_path_returns_ebadf)
{
	int opath_fd = TEST_SUCC(open(TEST_FILE, O_PATH));
	struct timespec times[2] = {
		{ .tv_sec = 10, .tv_nsec = 0 },
		{ .tv_sec = 20, .tv_nsec = 0 },
	};

	TEST_ERRNO(syscall(SYS_utimensat, opath_fd, NULL, times, 0), EBADF);
	TEST_SUCC(syscall(SYS_utimensat, opath_fd, "", times, AT_EMPTY_PATH));

	TEST_SUCC(close(opath_fd));
}
END_TEST()

FN_TEST(at_empty_path_on_o_path_symlink_updates_symlink)
{
	const char *symlink_path = "/tmp/utimensat_symlink";
	TEST_SUCC(symlink(TEST_FILE, symlink_path));
	int sym_fd = TEST_SUCC(open(symlink_path, O_PATH | O_NOFOLLOW));

	struct timespec times[2] = {
		{ .tv_sec = 1500000000, .tv_nsec = 0 },
		{ .tv_sec = 1500000001, .tv_nsec = 0 },
	};
	TEST_SUCC(utimensat(sym_fd, "", times,
			    AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));

	struct stat sym_st;
	TEST_RES(fstatat(AT_FDCWD, symlink_path, &sym_st, AT_SYMLINK_NOFOLLOW),
		 sym_st.st_atim.tv_sec == 1500000000 &&
			 sym_st.st_mtim.tv_sec == 1500000001);

	TEST_SUCC(close(sym_fd));
	TEST_SUCC(unlink(symlink_path));
}
END_TEST()

/* Explicit times require ownership even when a non-owner can write. */
FN_TEST(nonowner_timestamp_permissions)
{
	SKIP_TEST_IF(geteuid() != 0);
	CHECK(fchmod(fd, 0666));
	pid_t child = CHECK(fork());
	if (child == 0) {
		CHECK(setresuid(65534, 65534, 65534));
		struct timespec explicit[2] = { { 100, 0 }, { 101, 0 } };
		struct timespec now[2] = { { 0, UTIME_NOW }, { 0, UTIME_NOW } };
		struct timespec mixed[2] = { { 0, UTIME_NOW }, { 0, UTIME_OMIT } };
		TEST_ERRNO(futimens(fd, explicit), EPERM);
		TEST_ERRNO(futimens(fd, mixed), EPERM);
		TEST_SUCC(futimens(fd, now));
		TEST_SUCC(futimens(fd, NULL));
		_exit(__tests_failed != 0);
	}
	int status;
	CHECK(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(fchmod(fd, 0644));
}
END_TEST()

FN_TEST(nonowner_without_write_cannot_set_current_time)
{
	SKIP_TEST_IF(geteuid() != 0);
	pid_t child = CHECK(fork());
	if (child == 0) {
		CHECK(setresuid(65534, 65534, 65534));
		TEST_ERRNO(futimens(fd, NULL), EACCES);
		_exit(__tests_failed != 0);
	}
	int status;
	CHECK(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(owner_without_write_can_set_explicit_times)
{
	SKIP_TEST_IF(geteuid() != 0);
	CHECK(fchown(fd, 65534, -1));
	CHECK(fchmod(fd, 0000));
	pid_t child = CHECK(fork());
	if (child == 0) {
		CHECK(setresuid(65534, 65534, 65534));
		struct timespec explicit[2] = { { 100, 0 }, { 101, 0 } };
		TEST_SUCC(futimens(fd, explicit));
		TEST_SUCC(futimens(fd, NULL));
		_exit(__tests_failed != 0);
	}
	int status;
	CHECK(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(fchown(fd, 0, -1));
	CHECK(fchmod(fd, 0644));
}
END_TEST()

FN_TEST(readonly_mount_rejects_timestamp_updates)
{
	SKIP_TEST_IF(geteuid() != 0);
	const char *target = "/tmp/utimensat_readonly";
	CHECK(mkdir(target, 0700));
	pid_t child = CHECK(fork());
	if (child == 0) {
		CHECK(unshare(CLONE_NEWNS));
		CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
		CHECK(mount("tmpfs", target, "tmpfs", 0, NULL));
		char path[128];
		snprintf(path, sizeof(path), "%s/file", target);
		int ro_fd = CHECK(open(path, O_CREAT | O_RDWR, 0600));
		CHECK(close(ro_fd));
		CHECK(mount(NULL, target, NULL, MS_REMOUNT | MS_RDONLY, NULL));
		ro_fd = CHECK(open(path, O_RDONLY));
		struct timespec explicit[2] = { { 100, 0 }, { 101, 0 } };
		TEST_ERRNO(futimens(ro_fd, explicit), EROFS);
		TEST_ERRNO(futimens(ro_fd, NULL), EROFS);
		CHECK(close(ro_fd));
		CHECK(umount(target));
		_exit(__tests_failed != 0);
	}
	int status;
	CHECK(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(rmdir(target));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(fd));
	CHECK(unlink(TEST_FILE));
}
END_SETUP()
