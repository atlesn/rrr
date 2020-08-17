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
#include <stdint.h>

#include "ip_defines.h"

#include "../socket/rrr_socket.h"
#include "../util/linked_list.h"

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
	unsigned int port;
};

struct rrr_ip_graylist_entry {
	RRR_LL_NODE(struct rrr_ip_graylist_entry);
	struct sockaddr_storage addr;
	socklen_t addr_len;
	uint64_t expire_time;
};

struct rrr_ip_graylist {
	RRR_LL_HEAD(struct rrr_ip_graylist_entry);
};

void rrr_ip_graylist_clear (
		struct rrr_ip_graylist *target
);
void rrr_ip_graylist_clear_void (
		void *target
);
int rrr_ip_receive_array_tree (
		struct rrr_msg_holder *target_entry,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		struct rrr_array *array_final,
		const struct rrr_array_tree *tree,
		int do_sync_byte_by_byte,
		unsigned int message_max_size,
		int (*callback)(struct rrr_msg_holder *entry, struct rrr_array *array, void *arg),
		void *arg
);
int rrr_ip_send (
		int *err,
		int fd,
		const struct sockaddr *sockaddr,
		socklen_t addrlen,
		void *data,
		ssize_t data_size
);
void rrr_ip_network_cleanup (
		void *arg
);
int rrr_ip_network_start_udp_ipv4_nobind (
		struct rrr_ip_data *data
);
int rrr_ip_network_start_udp_ipv4 (
		struct rrr_ip_data *data
);
int rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
		struct rrr_ip_data *ip_data,
		unsigned int port,
		const char *host,
		void *data,
		ssize_t size
);
int rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw (
		struct rrr_ip_accept_data **accept_data,
		struct sockaddr *addr,
		socklen_t addr_len,
		struct rrr_ip_graylist *graylist
);
int rrr_ip_network_connect_tcp_ipv4_or_ipv6 (
		struct rrr_ip_accept_data **accept_data,
		unsigned int port,
		const char *host,
		struct rrr_ip_graylist *graylist
);
int rrr_ip_network_start_tcp_ipv4_and_ipv6 (
		struct rrr_ip_data *data, int max_connections
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

#endif
