// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define WORKER_STACK_SIZE (2 * 1024 * 1024)
#define ROUNDS_PER_OPERATION 64
#define NUM_OPERATIONS 4

struct round_control {
	atomic_int ready;
	atomic_int forked;
	atomic_int cow_ready;
	atomic_int run;
	atomic_int finished;
	atomic_int release;
	atomic_int observed_expected_access;
};

static volatile unsigned char *page;
static struct round_control *control;
static sigjmp_buf fault_return;
static volatile sig_atomic_t expecting_fault;

static void pin_cpu(int cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	assert(sched_setaffinity(0, sizeof(mask), &mask) == 0);
}

static void fault_handler(int signal, siginfo_t *info, void *context)
{
	(void)context;
	if (signal != SIGSEGV || !expecting_fault ||
	    info->si_addr != (void *)page) {
		_exit(2);
	}
	siglongjmp(fault_return, 1);
}

static void wait_for_round(atomic_int *counter, int round)
{
	while (atomic_load_explicit(counter, memory_order_acquire) < round) {
		// Keep the remote CPU in user mode with its cached translation.
		// A syscall here could reload CR3 and hide a missing shootdown.
	}
}

static void privatize_stack(void *bottom, void *top)
{
	// Write one byte in each page of the caller's active stack frame before
	// the remote CPU caches the old mapping. Preserve all stack contents.
	for (uintptr_t address = (uintptr_t)bottom; address < (uintptr_t)top;
	     address = (address & ~(uintptr_t)(PAGE_SIZE - 1)) + PAGE_SIZE) {
		volatile unsigned char *byte =
			(volatile unsigned char *)address;
		*byte = *byte;
	}
}

static int attempt_access(int round)
{
	if (round > 3 * ROUNDS_PER_OPERATION) {
		return *page == 2;
	}
	expecting_fault = 1;
	int faulted = sigsetjmp(fault_return, 1);
	if (!faulted) {
		if (round <= ROUNDS_PER_OPERATION) {
			*page = 2;
		} else {
			volatile unsigned char value = *page;
			(void)value;
		}
	}
	expecting_fault = 0;
	return faulted != 0;
}

static void *access_remote_page(void *arg)
{
	pin_cpu(*(int *)arg);
	for (int round = 1; round <= ROUNDS_PER_OPERATION * NUM_OPERATIONS;
	     ++round) {
		// Warm a writable translation before the other CPU changes the PTE.
		*page = 1;
		atomic_store_explicit(&control->ready, round,
				      memory_order_release);
		if (round > 3 * ROUNDS_PER_OPERATION) {
			wait_for_round(&control->forked, round);
			// Fork invalidates the writable translation. Cache the old
			// read-only mapping again before the parent replaces it.
			assert(*page == 1);
			atomic_store_explicit(&control->cow_ready, round,
					      memory_order_release);
		}
		wait_for_round(&control->run, round);

		int expected = attempt_access(round);
		atomic_store_explicit(&control->observed_expected_access,
				      expected, memory_order_relaxed);
		atomic_store_explicit(&control->finished, round,
				      memory_order_release);
		wait_for_round(&control->release, round);
	}
	return NULL;
}

int main(void)
{
	// Keep a known lower bound below this function's local stack slots.
	void *stack_floor = __builtin_alloca(PAGE_SIZE);
	cpu_set_t allowed;
	assert(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
	int cpus[2] = { -1, -1 };
	for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
		if (!CPU_ISSET(cpu, &allowed)) {
			continue;
		}
		if (cpus[0] < 0) {
			cpus[0] = cpu;
		} else {
			cpus[1] = cpu;
			break;
		}
	}
	if (cpus[1] < 0) {
		puts("SKIP: TLB shootdown test requires two CPUs");
		return 0;
	}

	// Keep the file and its cached frame alive during munmap. A stale access
	// must fail this test without depending on reuse of a freed physical page.
	char path[] = "/tmp/tlb-shootdown-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	assert(unlink(path) == 0);
	assert(ftruncate(fd, 2 * PAGE_SIZE + WORKER_STACK_SIZE) == 0);
	page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	assert(page != MAP_FAILED);
	// Shared counters and a shared worker stack cannot cause unrelated COW
	// faults that would invalidate the warmed translation during the check.
	control = mmap(NULL, PAGE_SIZE + WORKER_STACK_SIZE,
		       PROT_READ | PROT_WRITE, MAP_SHARED, fd, PAGE_SIZE);
	assert(control != MAP_FAILED);
	atomic_init(&control->ready, 0);
	atomic_init(&control->forked, 0);
	atomic_init(&control->cow_ready, 0);
	atomic_init(&control->run, 0);
	atomic_init(&control->finished, 0);
	atomic_init(&control->release, 0);
	atomic_init(&control->observed_expected_access, 0);

	struct sigaction action = { .sa_sigaction = fault_handler,
				    .sa_flags = SA_SIGINFO };
	assert(sigemptyset(&action.sa_mask) == 0);
	assert(sigaction(SIGSEGV, &action, NULL) == 0);
	alarm(20);
	pin_cpu(cpus[0]);
	pthread_attr_t attr;
	assert(pthread_attr_init(&attr) == 0);
	assert(pthread_attr_setstack(&attr, (char *)control + PAGE_SIZE,
				     WORKER_STACK_SIZE) == 0);
	pthread_t worker;
	assert(pthread_create(&worker, &attr, access_remote_page, &cpus[1]) ==
	       0);
	assert(pthread_attr_destroy(&attr) == 0);

	for (int round = 1; round <= ROUNDS_PER_OPERATION * NUM_OPERATIONS;
	     ++round) {
		wait_for_round(&control->ready, round);
		pid_t child = -1;
		int sync_pipe[2];
		if (round <= ROUNDS_PER_OPERATION) {
			assert(mprotect((void *)page, PAGE_SIZE, PROT_READ) ==
			       0);
		} else if (round <= 2 * ROUNDS_PER_OPERATION) {
			assert(mprotect((void *)page, PAGE_SIZE, PROT_NONE) ==
			       0);
		} else if (round <= 3 * ROUNDS_PER_OPERATION) {
			assert(munmap((void *)page, PAGE_SIZE) == 0);
		} else {
			assert(pipe(sync_pipe) == 0);
			child = fork();
			assert(child >= 0);
			if (child == 0) {
				assert(close(sync_pipe[1]) == 0);
				char released;
				assert(read(sync_pipe[0], &released, 1) == 1);
				// Keep the old frame alive until the remote parent
				// thread has checked the replacement COW mapping.
				assert(*page == 1);
				_exit(0);
			}
			assert(close(sync_pipe[0]) == 0);
			privatize_stack(stack_floor,
					__builtin_frame_address(0));
			atomic_store_explicit(&control->forked, round,
					      memory_order_release);
			while (atomic_load_explicit(&control->cow_ready,
						    memory_order_acquire) <
			       round) {
			}
			*page = 2;
		}
		atomic_store_explicit(&control->run, round,
				      memory_order_release);
		// Do not call a function between replacing the COW page and checking
		// the remote result: another parent-stack COW could hide a missed flush.
		while (atomic_load_explicit(&control->finished,
					    memory_order_acquire) < round) {
		}
		assert(atomic_load_explicit(&control->observed_expected_access,
					    memory_order_relaxed));
		if (child > 0) {
			assert(write(sync_pipe[1], "x", 1) == 1);
			assert(close(sync_pipe[1]) == 0);
			int status;
			assert(waitpid(child, &status, 0) == child);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		}

		if (round <= 2 * ROUNDS_PER_OPERATION) {
			assert(mprotect((void *)page, PAGE_SIZE,
					PROT_READ | PROT_WRITE) == 0);
		} else {
			void *mapped = mmap((void *)page, PAGE_SIZE,
					    PROT_READ | PROT_WRITE,
					    (round < 3 * ROUNDS_PER_OPERATION ?
						     MAP_SHARED :
						     MAP_PRIVATE) |
						    MAP_FIXED,
					    fd, 0);
			assert(mapped == (void *)page);
		}
		atomic_store_explicit(&control->release, round,
				      memory_order_release);
	}
	assert(pthread_join(worker, NULL) == 0);
	alarm(0);
	assert(munmap((void *)page, PAGE_SIZE) == 0);
	assert(munmap(control, PAGE_SIZE + WORKER_STACK_SIZE) == 0);
	assert(close(fd) == 0);
	puts("PASS: remote mprotect, munmap and COW translations are invalidated");
	return 0;
}
