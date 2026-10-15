// SPDX-License-Identifier: MPL-2.0

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __x86_64__

static _Thread_local uint64_t cookie;
static _Thread_local volatile sig_atomic_t signals;

static unsigned int read_mxcsr(void)
{
	unsigned int value;
	__asm__ volatile("stmxcsr %0" : "=m"(value));
	return value;
}

static void write_mxcsr(unsigned int value)
{
	__asm__ volatile("ldmxcsr %0" : : "m"(value));
}

static void handle_signal(int signum)
{
	(void)signum;
	++signals;
	// Signal return must restore the interrupted thread's control state.
	write_mxcsr(0x1f80);
}

static void check_state(uint64_t expected_cookie, unsigned int expected_mxcsr)
{
	assert(cookie == expected_cookie);
	assert((read_mxcsr() & 0xffc0) == expected_mxcsr);
}

static void *worker(void *argument)
{
	uintptr_t index = (uintptr_t)argument;
	uint64_t expected_cookie = 0xabcdef0000000000ULL + index;
	unsigned int expected_mxcsr = 0x1f80 | ((index & 3) << 13);
	cookie = expected_cookie;
	write_mxcsr(expected_mxcsr);
	for (unsigned int i = 0; i < 500000; ++i) {
		assert(syscall(SYS_getpid) > 0);
		if (i % 1024 == 0)
			assert(raise(SIGUSR1) == 0);
		check_state(expected_cookie, expected_mxcsr);
	}
	assert(signals != 0);
	return NULL;
}

int main(void)
{
	struct sigaction action = { .sa_handler = handle_signal };
	assert(sigemptyset(&action.sa_mask) == 0);
	assert(sigaction(SIGUSR1, &action, NULL) == 0);
	pthread_t threads[4];
	for (uintptr_t i = 0; i < 4; ++i)
		assert(pthread_create(&threads[i], NULL, worker,
				      (void *)(i + 1)) == 0);

	const uint64_t expected_cookie = 0x123456789abcdef0ULL;
	const unsigned int expected_mxcsr = 0x5f80;
	cookie = expected_cookie;
	write_mxcsr(expected_mxcsr);
	// clone and signal handling access the saved FPU/TLS state while the
	// other threads keep timer-driven scheduling active.
	for (unsigned int i = 0; i < 1024; ++i) {
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			check_state(expected_cookie, expected_mxcsr);
			_exit(0);
		}
		assert(raise(SIGUSR1) == 0);
		int status;
		pid_t waited;
		do {
			waited = waitpid(child, &status, 0);
		} while (waited < 0 && errno == EINTR);
		assert(waited == child);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		check_state(expected_cookie, expected_mxcsr);
	}
	for (unsigned int i = 0; i < 4; ++i)
		assert(pthread_join(threads[i], NULL) == 0);
	check_state(expected_cookie, expected_mxcsr);
	puts("PASS: TLS and FPU state survived clone, signals and preemption");
	return 0;
}

#else

int main(void)
{
	puts("SKIP: x86 MXCSR regression");
	return 0;
}

#endif
