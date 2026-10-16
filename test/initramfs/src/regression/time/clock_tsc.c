// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define NSEC_PER_SEC UINT64_C(1000000000)
#define WAIT_NS UINT64_C(100000000)
#define OFFSET_TOLERANCE_NS INT64_C(5000000)
#define HANDOFFS 128
#define MAX_CANDIDATES 16

static int64_t offset_low;
static int64_t offset_high;
static uint64_t last_monotonic;
static uint64_t last_realtime;

static void fail(const char *message)
{
	fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
	exit(EXIT_FAILURE);
}

static void timeout(int signal)
{
	(void)signal;
	static const char message[] = "FAIL: clock regression timed out\n";
	ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
	(void)written;
	_exit(2);
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
		fail("invalid clock value");
	return (uint64_t)value.tv_sec * NSEC_PER_SEC + value.tv_nsec;
}

static struct timespec as_timespec(uint64_t nanos)
{
	return (struct timespec){ .tv_sec = nanos / NSEC_PER_SEC,
				  .tv_nsec = nanos % NSEC_PER_SEC };
}

/* Bracket realtime with monotonic reads to allow time spent descheduled. */
static void sample_clocks(int initialize)
{
	uint64_t before = now_ns(CLOCK_MONOTONIC);
	uint64_t realtime = now_ns(CLOCK_REALTIME);
	uint64_t after = now_ns(CLOCK_MONOTONIC);
	if (before < last_monotonic || after < before)
		fail("CLOCK_MONOTONIC moved backwards");
	if (realtime < last_realtime)
		fail("CLOCK_REALTIME moved backwards without a clock adjustment");
	last_monotonic = after;
	last_realtime = realtime;
	if (realtime > INT64_MAX || after > INT64_MAX)
		fail("clock values exceed offset test range");
	int64_t low = (int64_t)realtime - (int64_t)after;
	int64_t high = (int64_t)realtime - (int64_t)before;
	if (initialize) {
		offset_low = low;
		offset_high = high;
	} else if (low > offset_high + OFFSET_TOLERANCE_NS ||
		   high < offset_low - OFFSET_TOLERANCE_NS) {
		fail("realtime-minus-monotonic offset changed");
	}
}

static void check_sleep(clockid_t clock, int absolute)
{
	uint64_t before = now_ns(clock);
	uint64_t monotonic_before = now_ns(CLOCK_MONOTONIC);
	uint64_t deadline = before + WAIT_NS;
	struct timespec request = as_timespec(absolute ? deadline : WAIT_NS);
	for (;;) {
		struct timespec remaining;
		int result = clock_nanosleep(clock,
					     absolute ? TIMER_ABSTIME : 0,
					     &request, &remaining);
		if (result == 0)
			break;
		if (result != EINTR) {
			errno = result;
			fail("clock_nanosleep");
		}
		if (!absolute)
			request = remaining;
	}
	uint64_t after = now_ns(clock);
	uint64_t monotonic_after = now_ns(CLOCK_MONOTONIC);
	if (after < deadline || monotonic_after <= monotonic_before)
		fail("clock_nanosleep returned before its deadline");
	sample_clocks(0);
	printf("PASS: %s %s sleep elapsed=%" PRIu64 " ns\n",
	       clock == CLOCK_MONOTONIC ? "monotonic" : "realtime",
	       absolute ? "absolute" : "relative", after - before);
}

static void check_timerfd(void)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (fd < 0)
		fail("timerfd_create");
	uint64_t deadline = now_ns(CLOCK_MONOTONIC) + WAIT_NS;
	struct itimerspec timer = { .it_value = as_timespec(deadline) };
	if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &timer, NULL) != 0)
		fail("timerfd_settime");
	struct pollfd ready = { .fd = fd, .events = POLLIN };
	int result;
	do {
		result = poll(&ready, 1, 2000);
	} while (result < 0 && errno == EINTR);
	if (result != 1 || !(ready.revents & POLLIN))
		fail("timerfd did not become readable within 2 seconds");
	uint64_t observed = now_ns(CLOCK_MONOTONIC);
	uint64_t expirations;
	if (read(fd, &expirations, sizeof(expirations)) !=
		    sizeof(expirations) ||
	    expirations != 1)
		fail("timerfd expiration count");
	if (observed < deadline)
		fail("timerfd became readable before its deadline");
	if (close(fd) != 0)
		fail("close timerfd");
	sample_clocks(0);
	puts("PASS: timerfd absolute deadline");
}

struct handoff {
	int report[2];
	int control[2];
	pthread_t thread;
};

static void transfer(int fd, uint64_t *value, int writing)
{
	size_t done = 0;
	while (done < sizeof(*value)) {
		ssize_t count = writing ? write(fd, (char *)value + done,
						sizeof(*value) - done) :
					  read(fd, (char *)value + done,
					       sizeof(*value) - done);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			fail("CPU handoff pipe");
		done += (size_t)count;
	}
}

static unsigned int current_cpu(void)
{
	unsigned int cpu;
	/* The Linux vDSO getcpu ABI is separate from the clock under test. */
	if (syscall(SYS_getcpu, &cpu, NULL, NULL) != 0)
		fail("SYS_getcpu");
	return cpu;
}

static void *handoff_worker(void *argument)
{
	struct handoff *handoff = argument;
	uint64_t initial_cpu = current_cpu();
	transfer(handoff->report[1], &initial_cpu, 1);
	uint64_t command;
	transfer(handoff->control[0], &command, 0);
	if (command == 0)
		return NULL;
	uint64_t cpu, input, output;
	transfer(handoff->control[0], &cpu, 0);
	transfer(handoff->control[0], &input, 0);
	transfer(handoff->control[0], &output, 0);
	cpu_set_t affinity;
	CPU_ZERO(&affinity);
	CPU_SET(cpu, &affinity);
	if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0)
		fail("worker sched_setaffinity");
	for (int iteration = 0; iteration < HANDOFFS; iteration++) {
		uint64_t previous;
		transfer((int)input, &previous, 0);
		if (current_cpu() != cpu)
			fail("worker did not execute on its selected CPU");
		uint64_t current = now_ns(CLOCK_MONOTONIC);
		if (current_cpu() != cpu)
			fail("worker changed CPU during its clock read");
		if (current < previous)
			fail("monotonic time moved backwards across CPU handoff");
		transfer((int)output, &current, 1);
	}
	return NULL;
}

static void join_candidate(struct handoff *candidate)
{
	int result = pthread_join(candidate->thread, NULL);
	if (result != 0) {
		errno = result;
		fail("pthread_join");
	}
	if (close(candidate->report[0]) != 0 ||
	    close(candidate->report[1]) != 0 ||
	    close(candidate->control[0]) != 0 ||
	    close(candidate->control[1]) != 0)
		fail("close candidate pipes");
}

static void check_cpu_handoffs(void)
{
	cpu_set_t available;
	CPU_ZERO(&available);
	if (sched_getaffinity(0, sizeof(available), &available) != 0)
		fail("sched_getaffinity");
	if (CPU_COUNT(&available) < 2) {
		puts("SKIP: cross-CPU handoff requires two available CPUs");
		return;
	}
	if (!CPU_ISSET(0, &available) || !CPU_ISSET(1, &available))
		fail("two-CPU handoff requires available CPU0 and CPU1");

	/*
	 * Asterinas assigns a CPU at first enqueue and does not migrate a running
	 * thread when its affinity changes. Recruit workers already on CPU0/CPU1
	 * instead of assuming that pthread creation order determines placement.
	 * Every candidate reports its actual CPU, then blocks on its own pipe.
	 */
	struct handoff candidates[MAX_CANDIDATES];
	int selected[2] = { -1, -1 };
	int count = 0;
	while (count < MAX_CANDIDATES && (selected[0] < 0 || selected[1] < 0)) {
		struct handoff *candidate = &candidates[count];
		if (pipe(candidate->report) != 0 ||
		    pipe(candidate->control) != 0)
			fail("candidate pipe");
		int result = pthread_create(&candidate->thread, NULL,
					    handoff_worker, candidate);
		if (result != 0) {
			errno = result;
			fail("pthread_create");
		}
		uint64_t cpu;
		transfer(candidate->report[0], &cpu, 0);
		printf("CPU candidate %d started on CPU%" PRIu64 "\n", count,
		       cpu);
		if (cpu < 2 && selected[cpu] < 0)
			selected[cpu] = count;
		count++;
	}
	for (int index = 0; index < count; index++) {
		if (index == selected[0] || index == selected[1])
			continue;
		uint64_t stop = 0;
		transfer(candidates[index].control[1], &stop, 1);
		join_candidate(&candidates[index]);
	}
	if (selected[0] < 0 || selected[1] < 0) {
		for (int cpu = 0; cpu < 2; cpu++) {
			if (selected[cpu] >= 0) {
				uint64_t stop = 0;
				struct handoff *candidate =
					&candidates[selected[cpu]];
				transfer(candidate->control[1], &stop, 1);
				join_candidate(candidate);
			}
		}
		fail("could not recruit workers on both CPU0 and CPU1");
	}
	int pipes[2][2];
	if (pipe(pipes[0]) != 0 || pipe(pipes[1]) != 0)
		fail("pipe");
	for (int cpu = 0; cpu < 2; cpu++) {
		int control = candidates[selected[cpu]].control[1];
		uint64_t command = 1;
		uint64_t target = cpu;
		uint64_t input = pipes[cpu][0];
		uint64_t output = pipes[1 - cpu][1];
		transfer(control, &command, 1);
		transfer(control, &target, 1);
		transfer(control, &input, 1);
		transfer(control, &output, 1);
	}
	uint64_t token = now_ns(CLOCK_MONOTONIC);
	transfer(pipes[0][1], &token, 1);
	for (int cpu = 0; cpu < 2; cpu++)
		join_candidate(&candidates[selected[cpu]]);
	transfer(pipes[0][0], &token, 0);
	if (now_ns(CLOCK_MONOTONIC) < token)
		fail("monotonic time moved backwards after CPU handoff");
	for (int index = 0; index < 2; index++) {
		if (close(pipes[index][0]) != 0 || close(pipes[index][1]) != 0)
			fail("close handoff pipe");
	}
	printf("PASS: %d ordered handoffs across CPU0 and CPU1\n",
	       2 * HANDOFFS);
}

int main(int argc, char **argv)
{
	if (signal(SIGALRM, timeout) == SIG_ERR)
		fail("signal");
	alarm(20);
	if (argc == 2 && strcmp(argv[1], "--cross-cpu") == 0) {
		check_cpu_handoffs();
		alarm(0);
		return EXIT_SUCCESS;
	}
	if (argc != 1)
		fail("usage: clock_tsc [--cross-cpu]");
	sample_clocks(1);
	for (int iteration = 0; iteration < 2000; iteration++)
		sample_clocks(0);
	puts("PASS: consecutive monotonic/realtime reads and stable offset");
	check_sleep(CLOCK_MONOTONIC, 0);
	check_sleep(CLOCK_MONOTONIC, 1);
	check_sleep(CLOCK_REALTIME, 1);
	check_timerfd();
	sample_clocks(0);
	alarm(0);
	puts("PASS: local TSC clock regression");
	return EXIT_SUCCESS;
}
