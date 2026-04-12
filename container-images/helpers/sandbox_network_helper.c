/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * sandbox_network_helper.so — LD_PRELOAD guidance for firewalled agents.
 *
 * Intercepts connect() and getsockopt() to print actionable messages when
 * the sandbox firewall blocks outbound connections. Stateless — no mutable
 * state, no fd tracking.
 *
 * Build: gcc -shared -fPIC -Os -s -o sandbox_network_helper.so sandbox_network_helper.c
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char guidance[] =
	"  podman run --rm -v \"$PWD\":\"$PWD\" -w \"$PWD\" IMAGE COMMAND\n"
	"For detailed guidance: /clampdown\n";

static int is_blocked_error(int err)
{
	return err == ECONNREFUSED || err == ETIMEDOUT || err == ENETUNREACH;
}

/* Extract printable address and port from a sockaddr. Returns 1 for
 * non-loopback inet/inet6 addresses, 0 otherwise (loopback or unknown). */
static int fmt_addr(const struct sockaddr *addr, char *buf, size_t bufsz,
		    uint16_t *port)
{
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *sa = (const struct sockaddr_in *)addr;
		uint32_t ip = ntohl(sa->sin_addr.s_addr);
		if ((ip >> 24) == 127)
			return 0;
		inet_ntop(AF_INET, &sa->sin_addr, buf, bufsz);
		*port = ntohs(sa->sin_port);
		return 1;
	}
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa6 =
			(const struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			return 0;
		inet_ntop(AF_INET6, &sa6->sin6_addr, buf, bufsz);
		*port = ntohs(sa6->sin6_port);
		return 1;
	}
	return 0;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	long ret = syscall(SYS_connect, fd, addr, len);
	if (ret == -1 && is_blocked_error(errno)) {
		char buf[INET6_ADDRSTRLEN];
		uint16_t port;
		if (fmt_addr(addr, buf, sizeof(buf), &port))
			fprintf(stderr,
				"sandbox: connection to %s:%u blocked by firewall."
				" Route through a container:\n%s",
				buf, port, guidance);
	}
	return ret;
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	long ret = syscall(SYS_getsockopt, fd, level, optname, optval, optlen);
	if (ret == 0 && level == SOL_SOCKET && optname == SO_ERROR
	    && optlen && *optlen >= (socklen_t)sizeof(int)) {
		int err = *(int *)optval;
		if (is_blocked_error(err))
			fprintf(stderr,
				"sandbox: connection blocked by firewall."
				" Route through a container:\n%s", guidance);
	}
	return ret;
}
