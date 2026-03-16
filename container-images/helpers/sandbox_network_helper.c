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
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char guidance[] =
	"  podman run --rm -v \"$PWD\":\"$PWD\" -w \"$PWD\" IMAGE COMMAND\n";

static int is_inet_nonloopback(const struct sockaddr *addr)
{
	if (addr->sa_family != AF_INET)
		return 0;
	uint32_t ip = ntohl(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
	return (ip >> 24) != 127;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	long ret = syscall(SYS_connect, fd, addr, len);
	if (ret == -1 && (errno == ECONNREFUSED || errno == ETIMEDOUT)
	    && is_inet_nonloopback(addr)) {
		const struct sockaddr_in *sa = (const struct sockaddr_in *)addr;
		uint32_t ip = ntohl(sa->sin_addr.s_addr);
		fprintf(stderr,
			"sandbox: connection to %u.%u.%u.%u:%u blocked by firewall."
			" Route through a container:\n%s",
			(ip >> 24) & 0xff, (ip >> 16) & 0xff,
			(ip >> 8) & 0xff, ip & 0xff,
			ntohs(sa->sin_port), guidance);
	}
	return ret;
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	long ret = syscall(SYS_getsockopt, fd, level, optname, optval, optlen);
	if (ret == 0 && level == SOL_SOCKET && optname == SO_ERROR
	    && optlen && *optlen >= (socklen_t)sizeof(int)) {
		int err = *(int *)optval;
		if (err == ECONNREFUSED || err == ETIMEDOUT)
			fprintf(stderr,
				"sandbox: connection blocked by firewall."
				" Route through a container:\n%s", guidance);
	}
	return ret;
}
