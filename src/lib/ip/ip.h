/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_IP_H
#define RRR_IP_H

#include <sys/socket.h>

#include "ip_defines.h"

#include "../rrr_types.h"
#include "../socket/rrr_socket.h"
#include "../util/linked_list.h"

#define RRR_IP_SOCKOPT_RECV_TOS            (1<<0)
#ifdef RRR_HAVE_IP_PKTINFO
#    define RRR_IP_SOCKOPT_RECV_PKTINFO    (1<<1)
#else
#    define RRR_IP_SOCKOPT_RECV_DSTADDR    (1<<1)
#endif

struct rrr_msg_msg;
struct rrr_array;
struct rrr_array_tree;
struct rrr_read_session_collection;
struct rrr_read_session;
struct rrr_msg_holder;
struct rrr_ip_accept_data;

struct rrr_ip_send_packet_info {
	void *data;
	int fd;
	struct addrinfo *res;
	int packet_counter;
};

struct rrr_ip_data {
	int fd;
	uint16_t port;
	int is_ipv6;
};

void rrr_ip_network_reset_hard (
		void *arg
);
void rrr_ip_network_cleanup (
		void *arg
);
int rrr_ip_network_start_udp_nobind (
		struct rrr_ip_data *data,
		int do_ipv6
);
int rrr_ip_network_start_udp (
		struct rrr_ip_data *data,
		int do_ipv6
);
int rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
		rrr_biglength *written_bytes,
		struct rrr_ip_data *ip_data,
		unsigned int port,
		const char *host,
		void *data,
		rrr_biglength size
);
int rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw_nonblock (
		int *result_fd,
		const struct sockaddr *addr,
		socklen_t addr_len
);
int rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
		uint16_t port,
		const char *host,
		int (*callback)(const char *host, uint16_t port, const struct sockaddr *addr, socklen_t addr_len, void *arg),
		void *callback_arg
);
int rrr_ip_network_connect_tcp_ipv4_or_ipv6 (
		struct rrr_ip_accept_data **accept_data,
		uint16_t port,
		const char *host
);
int rrr_ip_network_start_tcp (
		struct rrr_ip_data *data,
		int max_connections,
		int do_ipv6
);
int rrr_ip_close (
		struct rrr_ip_data *data
);
int rrr_ip_accept (
		struct rrr_ip_accept_data **accept_data,
		struct rrr_ip_data *listen_data,
		const char *creator,
		int tcp_nodelay
);
int rrr_ip_recvmsg (
		struct rrr_socket_datagram *datagram,
		struct rrr_ip_data *data,
		uint8_t *buf,
		size_t buf_size
);
int rrr_ip_setsockopts (
		struct rrr_ip_data *data,
		int flags
);

#endif
