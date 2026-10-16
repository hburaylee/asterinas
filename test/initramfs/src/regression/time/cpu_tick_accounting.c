// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NSEC_PER_SEC UINT64_C(1000000000)
#define CPU_TARGET_NS UINT64_C(150000000)
#define MIN_BUSY_WALL_NS UINT64_C(350000000)
#define PROGRESS_LIMIT_NS (UINT64_C(10) * NSEC_PER_SEC)
#define ACCOUNTING_TOLERANCE_NS UINT64_C(100000000)
#define BUSY_THREADS 2
#define WORKER_THREADS (BUSY_THREADS + 1)

struct cpu_sample {
	uint64_t cpu_ns;
	uint64_t wall_ns;
};

static atomic_int ready;
static atomic_int start;
static atomic_int busy_finished;
static atomic_int all_finished;
static struct cpu_sample samples[WORKER_THREADS];
static volatile sig_atomic_t virtual_expired;
static volatile sig_atomic_t prof_expired;

static void fail(const char *message)
{
	fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
	exit(EXIT_FAILURE);
}

static void timeout(int signal)
{
	(void)signal;
	static const char message[] = "FAIL: CPU accounting timed out\n";
	ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
	(void)written;
	_exit(2);
}

static void cpu_timer_expired(int signal)
{
	if (signal == SIGVTALRM)
		virtual_expired = 1;
	else if (signal == SIGPROF)
		prof_expired = 1;
}

static uint64_t now_ns(clockid_t clock)
{
	struct timespec value;
	if (clock_gettime(clock, &value) != 0)
		fail("clock_gettime");
	if (value.tv_sec < 0 || value.tv_nsec < 0 ||
	    value.tv_nsec >= (long)NSEC_PER_SEC ||
	    (uint64_t)value.tv_sec >
		    (UINT64_MAX - (uint64_t)value.tv_nsec) / NSEC_PER_SEC)
		fail("invalid CPU or monotonic clock value");
	return (uint64_t)value.tv_sec * NSEC_PER_SEC + value.tv_nsec;
}

static uint64_t sample_forward(clockid_t clock, uint64_t previous)
{
	uint64_t current = now_ns(clock);
	if (current < previous)
		fail("CPU or monotonic clock moved backwards");
	return current;
}

static void sleep_ns(long nanos)
{
	struct timespec remaining = { .tv_nsec = nanos };
	while (nanosleep(&remaining, &remaining) != 0) {
		if (errno != EINTR)
			fail("nanosleep");
	}
}

/* This checks visible progress and broad bounds, not tick-perfect attribution. */
static struct cpu_sample burn_cpu(void)
{
	uint64_t wall_start = now_ns(CLOCK_MONOTONIC);
	uint64_t cpu_start = now_ns(CLOCK_THREAD_CPUTIME_ID);
	uint64_t wall = wall_start;
	uint64_t cpu = cpu_start;
	uint64_t process = now_ns(CLOCK_PROCESS_CPUTIME_ID);
	volatile uint64_t work = UINT64_C(0x123456789abcdef);
	unsigned int rounds = 0;
	while (cpu - cpu_start < CPU_TARGET_NS ||
	       wall - wall_start < MIN_BUSY_WALL_NS) {
		for (unsigned int i = 0; i < 32768; ++i)
			work = work * UINT64_C(6364136223846793005) + 1;
		if (++rounds % 16 == 0 && sched_yield() != 0)
			fail("sched_yield");
		if (rounds % 32 == 0)
			sleep_ns(1000000);
		cpu = sample_forward(CLOCK_THREAD_CPUTIME_ID, cpu);
		process = sample_forward(CLOCK_PROCESS_CPUTIME_ID, process);
		wall = sample_forward(CLOCK_MONOTONIC, wall);
		if (wall - wall_start > PROGRESS_LIMIT_NS)
			fail("busy thread CPU clock did not make progress");
	}
	struct cpu_sample result = { .cpu_ns = cpu - cpu_start,
				     .wall_ns = wall - wall_start };
	if (result.cpu_ns > result.wall_ns + ACCOUNTING_TOLERANCE_NS)
		fail("thread CPU time exceeds elapsed wall time");
	return result;
}

static void await_start(void)
{
	atomic_fetch_add_explicit(&ready, 1, memory_order_release);
	while (!atomic_load_explicit(&start, memory_order_acquire))
		sleep_ns(1000000);
}

static void *busy_worker(void *argument)
{
	size_t index = (size_t)(uintptr_t)argument;
	await_start();
	samples[index] = burn_cpu();
	atomic_fetch_add_explicit(&busy_finished, 1, memory_order_release);
	atomic_fetch_add_explicit(&all_finished, 1, memory_order_release);
	return NULL;
}

static void *sleeping_worker(void *argument)
{
	(void)argument;
	await_start();
	uint64_t wall_start = now_ns(CLOCK_MONOTONIC);
	uint64_t cpu_start = now_ns(CLOCK_THREAD_CPUTIME_ID);
	uint64_t wall = wall_start;
	uint64_t cpu = cpu_start;
	while (atomic_load_explicit(&busy_finished, memory_order_acquire) <
	       BUSY_THREADS) {
		sleep_ns(20000000);
		cpu = sample_forward(CLOCK_THREAD_CPUTIME_ID, cpu);
		wall = sample_forward(CLOCK_MONOTONIC, wall);
		if (wall - wall_start > PROGRESS_LIMIT_NS + NSEC_PER_SEC)
			fail("sleeping worker waited too long");
	}
	samples[BUSY_THREADS] =
		(struct cpu_sample){ .cpu_ns = cpu - cpu_start,
				     .wall_ns = wall - wall_start };
	atomic_fetch_add_explicit(&all_finished, 1, memory_order_release);
	return NULL;
}

int main(void)
{
	struct sigaction action = { .sa_handler = timeout };
	if (sigemptyset(&action.sa_mask) != 0 ||
	    sigaction(SIGALRM, &action, NULL) != 0)
		fail("install timeout handler");
	alarm(20);
	action.sa_handler = cpu_timer_expired;
	if (sigaction(SIGVTALRM, &action, NULL) != 0 ||
	    sigaction(SIGPROF, &action, NULL) != 0)
		fail("install CPU timer handlers");
	struct itimerval virtual_timer = { .it_value = { .tv_usec = 20000 } };
	struct itimerval prof_timer = { .it_value = { .tv_usec = 30000 } };
	if (setitimer(ITIMER_VIRTUAL, &virtual_timer, NULL) != 0 ||
	    setitimer(ITIMER_PROF, &prof_timer, NULL) != 0)
		fail("arm CPU timers");

	uint64_t process_start = now_ns(CLOCK_PROCESS_CPUTIME_ID);
	struct cpu_sample single = burn_cpu();
	uint64_t process_end =
		sample_forward(CLOCK_PROCESS_CPUTIME_ID, process_start);
	uint64_t single_process = process_end - process_start;
	struct itimerval disarmed = { 0 };
	if (setitimer(ITIMER_VIRTUAL, &disarmed, NULL) != 0 ||
	    setitimer(ITIMER_PROF, &disarmed, NULL) != 0)
		fail("disarm CPU timers");
	printf("single: thread=%" PRIu64 " process=%" PRIu64 " wall=%" PRIu64
	       " ns virtual=%d prof=%d\n",
	       single.cpu_ns, single_process, single.wall_ns,
	       (int)virtual_expired, (int)prof_expired);
	if (!virtual_expired || !prof_expired)
		fail("CPU timers did not expire during busy execution");
	if (single_process + ACCOUNTING_TOLERANCE_NS < single.cpu_ns ||
	    single_process > single.wall_ns + ACCOUNTING_TOLERANCE_NS)
		fail("single-thread process CPU time is inconsistent");

	pthread_t workers[WORKER_THREADS];
	uint64_t wall_start = now_ns(CLOCK_MONOTONIC);
	uint64_t coordinator_start = now_ns(CLOCK_THREAD_CPUTIME_ID);
	process_start = now_ns(CLOCK_PROCESS_CPUTIME_ID);
	for (size_t i = 0; i < WORKER_THREADS; ++i) {
		int error = pthread_create(&workers[i], NULL,
					   i < BUSY_THREADS ? busy_worker :
							      sleeping_worker,
					   (void *)(uintptr_t)i);
		if (error != 0) {
			errno = error;
			fail("pthread_create");
		}
	}
	while (atomic_load_explicit(&ready, memory_order_acquire) <
	       WORKER_THREADS)
		sleep_ns(1000000);
	atomic_store_explicit(&start, 1, memory_order_release);
	uint64_t process = process_start;
	uint64_t wall = wall_start;
	while (atomic_load_explicit(&all_finished, memory_order_acquire) <
	       WORKER_THREADS) {
		sleep_ns(2000000);
		process = sample_forward(CLOCK_PROCESS_CPUTIME_ID, process);
		wall = sample_forward(CLOCK_MONOTONIC, wall);
		if (wall - wall_start > PROGRESS_LIMIT_NS + NSEC_PER_SEC)
			fail("workers did not finish");
	}
	for (size_t i = 0; i < WORKER_THREADS; ++i) {
		int error = pthread_join(workers[i], NULL);
		if (error != 0) {
			errno = error;
			fail("pthread_join");
		}
	}
	process_end = sample_forward(CLOCK_PROCESS_CPUTIME_ID, process);
	uint64_t coordinator_delta =
		sample_forward(CLOCK_THREAD_CPUTIME_ID, coordinator_start) -
		coordinator_start;
	uint64_t wall_end = sample_forward(CLOCK_MONOTONIC, wall);
	uint64_t elapsed = wall_end - wall_start;
	uint64_t process_delta = process_end - process_start;
	uint64_t busy_sum = 0;
	uint64_t thread_sum = 0;
	for (size_t i = 0; i < WORKER_THREADS; ++i) {
		printf("worker %zu (%s): cpu=%" PRIu64 " wall=%" PRIu64 " ns\n",
		       i, i < BUSY_THREADS ? "busy" : "sleeping",
		       samples[i].cpu_ns, samples[i].wall_ns);
		thread_sum += samples[i].cpu_ns;
		if (i < BUSY_THREADS)
			busy_sum += samples[i].cpu_ns;
	}
	printf("multi: process=%" PRIu64 " measured_threads=%" PRIu64
	       " coordinator=%" PRIu64 " wall=%" PRIu64 " ns\n",
	       process_delta, thread_sum, coordinator_delta, elapsed);
	if (process_delta + ACCOUNTING_TOLERANCE_NS < thread_sum)
		fail("process CPU time is below measured worker CPU time");
	/* Worker startup/exit and tick quantization may fall outside their samples. */
	if (process_delta >
	    thread_sum + coordinator_delta + ACCOUNTING_TOLERANCE_NS)
		fail("process CPU time repeats measured execution time");
	/* Include the coordinator thread in this deliberately broad upper bound. */
	if (process_delta >
	    elapsed * (WORKER_THREADS + 1) + ACCOUNTING_TOLERANCE_NS)
		fail("process CPU time exceeds all threads' wall-time bound");
	if (samples[BUSY_THREADS].cpu_ns >
	    busy_sum / 3 + ACCOUNTING_TOLERANCE_NS)
		fail("sleeping thread received excessive busy-thread CPU time");
	alarm(0);
	puts("PASS: thread and process CPU clocks progress across task switches");
	return 0;
}
