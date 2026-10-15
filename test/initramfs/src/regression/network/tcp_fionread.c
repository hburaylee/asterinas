// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Nginx queries FIONREAD on its connected upstream TCP socket. Returning ENOTTY
 * prevents it from reading the response. Check Linux's queued unread byte count,
 * including LISTEN's EINVAL and a drained FIN, without consuming data via ioctl.
 * Reference: https://man7.org/linux/man-pages/man7/tcp.7.html
 */
static int failures;

static void require(int condition, const char *operation)
{
	if (!condition) {
		fprintf(stderr,
			"PROBE_SETUP_ERROR operation=%s errno=%d message=%s\n",
			operation, errno, strerror(errno));
		exit(2);
	}
}

static void check_available(int fd, const char *name, int expected_bytes,
			    int expected_errno)
{
	const int sentinel = 0x55555555;
	int available = sentinel;
	errno = 0;
	int result = ioctl(fd, FIONREAD, &available);
	int error = errno;
	int ok = expected_errno ? result == -1 && error == expected_errno &&
					  available == sentinel :
				  result == 0 && available == expected_bytes;
	printf("FIONREAD_RESULT {\"case\":\"%s\",\"rc\":%d,\"errno\":%d,"
	       "\"bytes\":%d,\"expected_bytes\":%d,\"expected_errno\":%d,\"ok\":%s}\n",
	       name, result, error, available, expected_bytes, expected_errno,
	       ok ? "true" : "false");
	fflush(stdout);
	failures += !ok;
}

static void readable(int fd)
{
	struct pollfd item = { .fd = fd, .events = POLLIN };
	int result;
	do {
		result = poll(&item, 1, 3000);
	} while (result < 0 && errno == EINTR);
	require(result == 1 && (item.revents & (POLLIN | POLLHUP)),
		"poll-readable");
}

static void receive_exact(int fd, unsigned char *bytes, size_t size)
{
	size_t offset = 0;
	while (offset < size) {
		readable(fd);
		ssize_t count = read(fd, bytes + offset, size - offset);
		if (count < 0 && errno == EINTR)
			continue;
		require(count > 0, "read-payload");
		offset += (size_t)count;
	}
}

static void check_bad_pointer(int fd)
{
	errno = 0;
	int result = ioctl(fd, FIONREAD, NULL);
	int error = errno;
	int ok = result == -1 && error == EFAULT;
	printf("FIONREAD_RESULT {\"case\":\"connected_bad_pointer\",\"rc\":%d,"
	       "\"errno\":%d,\"expected_errno\":%d,\"ok\":%s}\n",
	       result, error, EFAULT, ok ? "true" : "false");
	fflush(stdout);
	failures += !ok;
}

int main(void)
{
	unsigned char payload[37];
	unsigned char received[37];
	for (size_t index = 0; index < sizeof(payload); index++)
		payload[index] = (unsigned char)('A' + index % 26);

	int unused = socket(AF_INET, SOCK_STREAM, 0);
	require(unused >= 0, "socket-unconnected");
	check_available(unused, "not_connected", 0, 0);
	require(close(unused) == 0, "close-unconnected");

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	require(listener >= 0, "socket-listener");
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	require(bind(listener, (struct sockaddr *)&address, sizeof(address)) ==
			0,
		"bind");
	require(listen(listener, 1) == 0, "listen");
	socklen_t address_size = sizeof(address);
	require(getsockname(listener, (struct sockaddr *)&address,
			    &address_size) == 0,
		"getsockname");
	check_available(listener, "listening", 0, EINVAL);

	int sender = socket(AF_INET, SOCK_STREAM, 0);
	require(sender >= 0, "socket-sender");
	require(connect(sender, (struct sockaddr *)&address, sizeof(address)) ==
			0,
		"connect");
	int receiver = accept(listener, NULL, NULL);
	require(receiver >= 0, "accept");
	check_available(receiver, "connected_empty", 0, 0);

	size_t sent = 0;
	while (sent < sizeof(payload)) {
		ssize_t count =
			write(sender, payload + sent, sizeof(payload) - sent);
		if (count < 0 && errno == EINTR)
			continue;
		require(count > 0, "write-payload");
		sent += (size_t)count;
	}
	readable(receiver);
	check_bad_pointer(receiver);
	check_available(receiver, "queued_37", 37, 0);
	receive_exact(receiver, received, 7);
	check_available(receiver, "partial_drain_30", 30, 0);
	require(shutdown(sender, SHUT_WR) == 0, "shutdown-writer");
	receive_exact(receiver, received + 7, sizeof(received) - 7);
	require(memcmp(payload, received, sizeof(payload)) == 0,
		"payload-contents");
	readable(receiver);
	unsigned char byte;
	require(read(receiver, &byte, 1) == 0, "read-eof");
	check_available(receiver, "eof_drained", 0, 0);

	require(close(receiver) == 0, "close-receiver");
	require(close(sender) == 0, "close-sender");
	require(close(listener) == 0, "close-listener");
	printf("FIONREAD_SUMMARY {\"cases\":7,\"failed\":%d,\"payload_verified\":true}\n",
	       failures);
	return failures ? 1 : 0;
}
