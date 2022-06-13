/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

// Allow SOCK_NONBLOCK on BSD
#define __BSD_VISIBLE 1

// Allow in_pktinfo on linux
#define _GNU_SOURCE 1

#include <sys/socket.h>
#include <netinet/in.h>

#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <assert.h>

#include "../log.h"
#include "../allocator.h"
#include "ip.h"
#include "ip_accept_data.h"
#include "ip_util.h"
#include "../read.h"
#include "../array.h"
#include "../rrr_strerror.h"
#include "../read_constants.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_common.h"
#include "../socket/rrr_socket_read.h"
#include "../socket/rrr_socket_constants.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"
#include "../util/crc32.h"

#define RRR_IP_TCP_NONBLOCK_CONNECT_TIMEOUT_MS	250

void rrr_ip_network_reset_hard (
		void *arg
) {
	struct rrr_ip_data *data = arg;
	memset(data, '\0', sizeof(*data));
}

void rrr_ip_network_cleanup (
		void *arg
) {
	struct rrr_ip_data *data = arg;
	if (data->fd != 0) {
		rrr_socket_close(data->fd);
		data->fd = 0;
	}
}

int rrr_ip_network_start_udp_nobind (
		struct rrr_ip_data *data,
		int do_ipv6
) {
	int fd = rrr_socket (
			(do_ipv6 ? AF_INET6 : AF_INET),
			SOCK_DGRAM|SOCK_NONBLOCK,
			IPPROTO_UDP,
			"ip_network_start_udp_nobind",
			NULL,
			0
	);
	if (fd == -1) {
		RRR_MSG_0 ("Could not create socket: %s\n", rrr_strerror(errno));
		return 1;
	}

	data->fd = fd;
	data->is_ipv6 = do_ipv6;

	return 0;
}

int rrr_ip_network_start_udp (
		struct rrr_ip_data *data,
		int do_ipv6
) {
	int fd = rrr_socket (
			(do_ipv6 ? AF_INET6 : AF_INET),
			SOCK_DGRAM|SOCK_NONBLOCK,
			IPPROTO_UDP,
			"ip_network_start_udp_ipv4",
			NULL,
			0
	);
	if (fd == -1) {
		RRR_MSG_0 ("Could not create socket: %s\n", rrr_strerror(errno));
		goto out_error;
	}

	if (data->port < 1) {
		RRR_MSG_0 ("ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_close_socket;
	}

	struct sockaddr_storage s;
	memset(&s, '\0', sizeof(s));

	socklen_t size = 0;
	if (do_ipv6) {
		struct sockaddr_in6 *si = (struct sockaddr_in6 *) &s;
		si->sin6_family = AF_INET6;
		si->sin6_port = htons(data->port);
		memset (&si->sin6_addr, 0, sizeof(si->sin6_addr));
		size = sizeof(*si);
	}
	else {
		struct sockaddr_in *si = (struct sockaddr_in *) &s;
		si->sin_family = AF_INET;
		si->sin_port = htons(data->port);
		si->sin_addr.s_addr = INADDR_ANY;
		size = sizeof(*si);
	}

	if (bind (fd, (struct sockaddr *) &s, size) == -1) {
		RRR_DBG_1 ("Note: Could not bind to port %d %s: %s\n",
				data->port, (do_ipv6 ? "IPv6" : "IPv4"), rrr_strerror(errno));
		goto out_close_socket;
	}

	data->fd = fd;
	data->is_ipv6 = do_ipv6;

	return 0;

	out_close_socket:
	rrr_socket_close(fd);

	out_error:
	return 1;
}

int rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
		rrr_biglength *written_bytes,
		struct rrr_ip_data *ip_data,
		unsigned int port,
		const char *host,
		void *data,
		rrr_biglength size
) {
	int ret = 0;

	if (port < 1 || port > 65535) {
		RRR_BUG ("rrr_ip_network_udp_sendto: port was not in the range 1-65535 (got '%d')\n", port);
	}

	char port_str[16];
	sprintf(port_str, "%u", port);

	struct addrinfo hints;
	struct addrinfo *result;

	memset (&hints, '\0', sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	int s = getaddrinfo(host, port_str, &hints, &result);
	if (s != 0) {
		RRR_MSG_0("Failed to get address of '%s': %s\n", host, gai_strerror(s));
		ret = 1;
		goto out;
	}

	struct addrinfo *rp;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int err;
		if (rrr_socket_sendto_nonblock (
				&err,
				written_bytes,
				ip_data->fd,
				data,
				size,
				(struct sockaddr *) rp->ai_addr,
				rp->ai_addrlen
		) == 0) {
			break;
		}
	}

	freeaddrinfo(result);

	out:
	return ret;
}

int rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw_nonblock (
		int *result_fd,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = RRR_SOCKET_OK;

	int fd = 0;

	*result_fd = -1;

	fd = rrr_socket (
			addr->sa_family,
			SOCK_STREAM|SOCK_NONBLOCK,
			IPPROTO_TCP,
			"ip_network_connect_tcp_ipv4_or_ipv6_raw_nonblock",
			NULL,
			0
	);
	if (fd == -1) {
		RRR_MSG_0("Error while creating socket (raw nonblock): %s\n", rrr_strerror(errno));
		ret = RRR_SOCKET_HARD_ERROR;
		goto out;
	}

	if (rrr_socket_connect_nonblock(fd, addr, addr_len) != 0) {
		RRR_DBG_3("Could not connect in in ip_network_connect_tcp_ipv4_or_ipv6\n");
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out_close;
	}

	*result_fd = fd;

	goto out;

	out_close:
		rrr_socket_close(fd);
	out:
		return ret;
}

static void __rrr_ip_freeaddrinfo_void_dbl_ptr (void *arg) {
	struct addrinfo **addrinfo = arg;
	if (*addrinfo != NULL) {
		freeaddrinfo(*addrinfo);
	}
}

int rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
		uint16_t port,
		const char *host,
		int (*callback)(const char *host, uint16_t port, const struct sockaddr *addr, socklen_t addr_len, void *arg),
		void *callback_arg
) {
	int ret = 0;

	if (port < 1) {
		RRR_BUG ("rrr_ip_network_resolve_ipv4_or_ipv6_with_callback: port was not in the range 1-65535 (got '%d')\n", port);
	}

	char port_str[16];
	sprintf(port_str, "%u", port);

	struct addrinfo hints;
	struct addrinfo *addrinfo_result = NULL;

	pthread_cleanup_push(__rrr_ip_freeaddrinfo_void_dbl_ptr, &addrinfo_result);

	memset (&hints, '\0', sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int s = getaddrinfo(host, port_str, &hints, &addrinfo_result);
	if (s != 0) {
		RRR_DBG_7("IP failed to get address of '%s': %s\n", host, gai_strerror(s));
		ret = 1;
		goto out;
	}

	int i = 1;
	struct addrinfo *rp;
	for (rp = addrinfo_result; rp != NULL; rp = rp->ai_next) {
		RRR_DBG_7("IP resolve address suggestion #%i to %s:%u address family %u\n",
				i, host, port, rp->ai_addr->sa_family);

		if ((ret = callback(host, port, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen, callback_arg)) != 0) {
			goto out;
		}

		i++;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

int rrr_ip_network_connect_tcp_ipv4_or_ipv6 (
		struct rrr_ip_accept_data **accept_data,
		uint16_t port,
		const char *host
) {
	int ret = 0;

	int fd = 0;

	*accept_data = NULL;

	if (port < 1) {
		RRR_BUG ("rrr_ip_network_connect_tcp_ipv4_or_ipv6: port was not in the range 1-65535 (got '%d')\n", port);
	}

	char port_str[16];
	sprintf(port_str, "%u", port);

	struct addrinfo hints;
	struct addrinfo *addrinfo_result = NULL;

	pthread_cleanup_push(__rrr_ip_freeaddrinfo_void_dbl_ptr, &addrinfo_result);

	memset (&hints, '\0', sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int s = getaddrinfo(host, port_str, &hints, &addrinfo_result);
	if (s != 0) {
		RRR_MSG_0("Failed to get address of '%s': %s\n", host, gai_strerror(s));
		ret = 1;
		goto out;
	}

	int i = 1;
	struct addrinfo *rp;
	for (rp = addrinfo_result; rp != NULL; rp = rp->ai_next) {
		fd = rrr_socket (
				rp->ai_family,
				rp->ai_socktype|SOCK_NONBLOCK,
				rp->ai_protocol,
				"ip_network_connect_tcp_ipv4_or_ipv6",
				NULL,
				0
		);
		if (fd == -1) {
			RRR_MSG_0("Error while creating socket (resolve loop): %s\n", rrr_strerror(errno));
			continue;
		}

	    	RRR_DBG_3("Connect attempt with address suggestion #%i to %s:%u address family %u\n",
	    			i, host, port, rp->ai_addr->sa_family);

		if (rrr_socket_connect_nonblock(fd, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == 0) {
			uint64_t timeout = RRR_IP_TCP_NONBLOCK_CONNECT_TIMEOUT_MS * 1000;
			if (rrr_socket_connect_nonblock_postcheck_loop(fd, timeout) == 0) {
				break;
			}
		}

		// This means connection refused or some other error, skip to next address suggestion

		rrr_socket_close(fd);
		i++;
	}

	if (fd <= 0 || rp == NULL) {
		RRR_DBG_3 ("Could not connect to host '%s': %s\n", host, (errno != 0 ? rrr_strerror(errno) : "unknown"));
		ret = 1;
		goto out;
	}

	struct rrr_ip_accept_data *accept_result = rrr_allocate(sizeof(*accept_result));
	if (accept_result == NULL) {
		RRR_MSG_0("Could not allocate memory in ip_network_connect_tcp_ipv4_or_ipv6\n");
		goto out_error_close_socket;
	}

	memset(accept_result, '\0', sizeof(*accept_result));

	accept_result->ip_data.fd = fd;
	accept_result->ip_data.port = port;
	accept_result->len = sizeof(accept_result->addr);
	if (getsockname(fd, (struct sockaddr *) &accept_result->addr, &accept_result->len) != 0) {
		RRR_MSG_0("getsockname failed: %s\n", rrr_strerror(errno));
		goto out_error_free_accept;
	}
	accept_result->ip_data.is_ipv6 = accept_result->addr.ss_family == AF_INET6;

	*accept_data = accept_result;

	goto out;
	out_error_free_accept:
		rrr_free(accept_result);
	out_error_close_socket:
		rrr_socket_close(fd);
	out:
		pthread_cleanup_pop(1);
		return ret;
}

int rrr_ip_network_start_tcp (
		struct rrr_ip_data *data,
		int max_connections,
		int do_ipv6
) {
	int fd = rrr_socket (
			(do_ipv6 ? AF_INET6 : AF_INET),
			SOCK_NONBLOCK|SOCK_STREAM,
			0,
			"ip_network_start",
			NULL,
			0
	);
	if (fd == -1) {
		RRR_MSG_0 ("Could not create socket: %s\n", rrr_strerror(errno));
		goto out_error;
	}

	if (data->port < 1) {
		RRR_MSG_0 ("ip_network_start: port was not in the range 1-65535 (got '%d')\n", data->port);
		goto out_close_socket;
	}

	struct sockaddr_in6 si;
	memset(&si, '\0', sizeof(si));
	si.sin6_family = (do_ipv6 ? AF_INET6 : AF_INET);
	si.sin6_port = htons(data->port);
	si.sin6_addr = in6addr_any;

	if (rrr_socket_bind_and_listen(fd, (struct sockaddr *) &si, sizeof(si), SO_REUSEADDR, max_connections) != 0) {
		RRR_DBG_1 ("Note: Could not listen on port %d %s: %s\n", data->port, (do_ipv6 ? "IPv6" : "IPv4"), rrr_strerror(errno));
		goto out_close_socket;
	}

	data->fd = fd;
	data->is_ipv6 = do_ipv6;

	return 0;

	out_close_socket:
	rrr_socket_close(fd);

	out_error:
	return 1;
}

int rrr_ip_close (
		struct rrr_ip_data *data
) {
	if (data->fd == 0) {
		RRR_BUG("Received zero-value FD in ip_close\n");
	}
	int ret = rrr_socket_close(data->fd);

	data->fd = 0;

	return ret;
}

int rrr_ip_accept (
		struct rrr_ip_accept_data **accept_data,
		struct rrr_ip_data *listen_data,
		const char *creator,
		int tcp_nodelay
) {
	int ret = 0;

	struct sockaddr_storage sockaddr_tmp = {0};
	socklen_t socklen_tmp = sizeof(sockaddr_tmp);
	struct rrr_ip_accept_data *res = NULL;

	*accept_data = NULL;

	ret = rrr_socket_accept(listen_data->fd, (struct sockaddr *) &sockaddr_tmp, &socklen_tmp, creator);
	if (ret == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
			goto out;
		}
		else {
			RRR_MSG_0("Error in ip_accept: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}

//	char buf[256];
//	rrr_ip_to_str(buf, sizeof(buf), (struct sockaddr *) &sockaddr_tmp, socklen_tmp);
//	printf("ip accept: %s family %i\n", buf, sockaddr_tmp.ss_family);

	int fd = ret;
	ret = 0;

	int enable = 1;
	if (tcp_nodelay == 1) {
		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) != 0) {
			RRR_MSG_0("Could not set TCP_NODELAY for socket in ip_accept: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_close_socket;
		}
	}

	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		RRR_MSG_0 ("Could not set SO_REUSEADDR for accepted connection: %s\n", rrr_strerror(errno));
		goto out_close_socket;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		RRR_MSG_0("Error while getting flags with fcntl for socket: %s\n", rrr_strerror(errno));
		goto out_close_socket;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		RRR_MSG_0("Error while setting O_NONBLOCK on socket: %s\n", rrr_strerror(errno));
		goto out_close_socket;
	}

	res = rrr_allocate(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate memory in ip_accept\n");
		ret = 1;
		goto out;
	}
	memset (res, '\0', sizeof(*res));

	if (	((struct sockaddr *) &sockaddr_tmp)->sa_family != AF_INET &&
			((struct sockaddr *) &sockaddr_tmp)->sa_family != AF_INET6
	) {
		RRR_BUG("Non AF_INET/AF_INET6 from accept() in ip_accept\n");
	}

	res->ip_data.fd = fd;
	res->addr = sockaddr_tmp;
	res->len = socklen_tmp;
	res->ip_data.is_ipv6 = sockaddr_tmp.ss_family == AF_INET6;

	{
		struct sockaddr_in client_tmp;
		socklen_t len_tmp = sizeof(client_tmp);
		getpeername(res->ip_data.fd, (struct sockaddr *) &client_tmp, &len_tmp);
		res->ip_data.port = ntohs (client_tmp.sin_port);
	}

	*accept_data = res;
	res = NULL;

	goto out;

	out_close_socket:
		rrr_socket_close(fd);

	out:
		RRR_FREE_IF_NOT_NULL(res);
		return ret;
}

static int __rrr_ip_recvmsg_get_local_addr (
		struct rrr_socket_datagram *datagram
) {
	int ret = RRR_SOCKET_READ_INCOMPLETE;

	if (datagram->addr_remote.ss_family == AF_INET) {
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&datagram->msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&datagram->msg, cmsg)) {
			struct sockaddr_in *addr_local = (struct sockaddr_in *) &datagram->addr_local;
			addr_local->sin_family = AF_INET;
#ifdef RRR_HAVE_IP_PKTINFO
			if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_PKTINFO)
				continue;

			const struct in_pktinfo *pktinfo = (const struct in_pktinfo *) CMSG_DATA(cmsg);
			assert(sizeof(addr_local->sin_addr) >= sizeof(pktinfo->ipi_addr));
			addr_local->sin_addr = pktinfo->ipi_addr;
			datagram->interface_index = rrr_length_from_ssize_bug_const(pktinfo->ipi_ifindex);
#else
			if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_RECVDSTADDR)
				continue;

			addr_local->sin_addr = * ((struct in_addr *) CMSG_DATA(cmsg));
#endif
			datagram->addr_local_len = sizeof(*addr_local);
			ret = RRR_SOCKET_OK;
			break;
		}
	}
	else if (datagram->addr_remote.ss_family == AF_INET6) {
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&datagram->msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&datagram->msg, cmsg)) {
			if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_PKTINFO)
				continue;

			const struct in6_pktinfo *pktinfo = (const struct in6_pktinfo *) CMSG_DATA(cmsg);
			struct sockaddr_in6 *addr_local = (struct sockaddr_in6 *) &datagram->addr_local;
			assert(sizeof(addr_local->sin6_addr) >= sizeof(pktinfo->ipi6_addr));
			addr_local->sin6_family = AF_INET6;
			addr_local->sin6_addr = pktinfo->ipi6_addr;
			datagram->addr_local_len = sizeof(*addr_local);
			ret = RRR_SOCKET_OK;
			break;
		}
	}
	else {
		RRR_MSG_0("Unknown family %u in %s\n", datagram->addr_remote.ss_family, __func__);
	}

	if (ret != RRR_SOCKET_OK) {
		RRR_MSG_0("Unable to get local address in %s\n", __func__);
	}

	return ret;
}

static void __rrr_ip_recvmsg_get_tos (
		struct rrr_socket_datagram *datagram
) {
	if (datagram->addr_remote.ss_family == AF_INET) {
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&datagram->msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&datagram->msg, cmsg)) {
			if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_TOS || cmsg->cmsg_len == 0)
				continue;
			datagram->tos = * (uint8_t *) CMSG_DATA(cmsg);
			break;
		}
	}
	else if (datagram->addr_remote.ss_family == AF_INET6) {
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&datagram->msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&datagram->msg, cmsg)) {
			if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_TCLASS || cmsg->cmsg_len == 0)
				continue;
			datagram->tos = * (uint8_t *) CMSG_DATA(cmsg);
			break;
		}
	}
	else {
		RRR_BUG("Unknown family %u in %s\n", datagram->addr_remote.ss_family, __func__);
	}
}

int rrr_ip_recvmsg (
		struct rrr_socket_datagram *datagram,
		struct rrr_ip_data *data
) {
	int ret = RRR_SOCKET_OK;

	uint8_t ctrl_buf[CMSG_SPACE(sizeof(uint8_t)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];

	rrr_socket_datagram_reset(datagram);

	datagram->msg.msg_control = ctrl_buf;
	datagram->msg.msg_controllen = sizeof(ctrl_buf);

	if ((ret = rrr_socket_recvmsg(datagram, data->fd)) != 0) {
		goto out;
	}

	if ((ret = __rrr_ip_recvmsg_get_local_addr(datagram)) != 0) {
		goto out;
	}

	__rrr_ip_recvmsg_get_tos(datagram);

	out:
	datagram->msg.msg_control = NULL;
	datagram->msg.msg_controllen = 0;
	return ret;
}

#define SET(name,ip6,ip)       \
    int enabled = 1;           \
    if (setsockopt(data->fd, data->is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP, data->is_ipv6 ? ip6 : ip, &enabled, sizeof(enabled)) != 0) {  \
	RRR_MSG_0("Failed to set option %s on socket in %s: %s\n", name, __func__, rrr_strerror(errno));                  \
	return RRR_SOCKET_HARD_ERROR;                                                                                     \
    }

#define TEST_AND_SET(name,ip6,ip)                    \
    do {if (flags & name) {                          \
        SET(RRR_QUOTE(name), ip6, ip);               \
        flags &= ~(RRR_IP_SOCKOPT_RECV_TOS);         \
    }} while (0)

int rrr_ip_setsockopts (
		struct rrr_ip_data *data,
		int flags
) {
	TEST_AND_SET(RRR_IP_SOCKOPT_RECV_TOS, IPV6_RECVTCLASS, IP_RECVTOS);
#ifdef RRR_HAVE_IP_PKTINFO
	TEST_AND_SET(RRR_IP_SOCKOPT_RECV_PKTINFO, IPV6_RECVPKTINFO, IP_PKTINFO);
#else
	TEST_AND_SET(RRR_IP_SOCKOPT_RECV_DSTADDR, IPV6_RECVPKTINFO, IP_RECVDSTADDR);
#endif

	return 0;
}
