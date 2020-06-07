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

#include "rrr_socket.h"
#include "linked_list.h"

#define RRR_IP_RECEIVE_OK 0
#define RRR_IP_RECEIVE_ERR 1
#define RRR_IP_RECEIVE_STOP 2

#define RRR_IP_RECEIVE_MAX_STEP_SIZE 8096

// Print/reset stats every X seconds
#define RRR_IP_STATS_DEFAULT_PERIOD 3

#define RRR_IP_AUTO	0
#define RRR_IP_UDP	1
#define RRR_IP_TCP	2

struct rrr_message;
struct rrr_array;
struct rrr_read_session_collection;
struct rrr_read_session;
struct rrr_ip_buffer_entry;
struct rrr_ip_accept_data;

struct ip_stats {
	pthread_mutex_t lock;
	unsigned int period;
	uint64_t time_from;
	unsigned long int packets;
	unsigned long int bytes;
	const char *type;
	const char *name;
};

struct ip_stats_twoway {
	struct ip_stats send;
	struct ip_stats receive;
};

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
	struct sockaddr addr;
	socklen_t addr_len;
	uint64_t expire_time;
};

struct rrr_ip_graylist {
	RRR_LL_HEAD(struct rrr_ip_graylist_entry);
};

#define RRR_IP_STATS_UPDATE_OK 0		// Stats was updated
#define RRR_IP_STATS_UPDATE_ERR 1	// Error
#define RRR_IP_STATS_UPDATE_READY 2	// Limit is reached, we should print

int rrr_ip_graylist_exists (
		struct rrr_ip_graylist *list, const struct sockaddr *addr, socklen_t len
);
int rrr_ip_graylist_push (
		struct rrr_ip_graylist *target, const struct sockaddr *addr, socklen_t len, int timeout_ms
);
void rrr_ip_graylist_clear (
		struct rrr_ip_graylist *target
);
static inline void rrr_ip_graylist_clear_void (
		void *target
) {
	return rrr_ip_graylist_clear(target);
}

void rrr_ip_to_str (
		char *dest, size_t dest_size, const struct sockaddr *addr, socklen_t addr_len
);
int rrr_ip_stats_init (
		struct ip_stats *stats, unsigned int period, const char *type, const char *name
);
int rrr_ip_stats_init_twoway (
		struct ip_stats_twoway *stats, unsigned int period, const char *name
);
int rrr_ip_stats_update (
		struct ip_stats *stats, unsigned long int packets, unsigned long int bytes
);
int rrr_ip_stats_print_reset (
		struct ip_stats *stats, int do_reset
);
int rrr_ip_receive_array (
		struct rrr_ip_buffer_entry *target_entry,
		struct rrr_read_session_collection *read_session_collection,
		int fd,
		int read_flags,
		const struct rrr_array *definition,
		int do_sync_byte_by_byte,
		int (*callback)(struct rrr_ip_buffer_entry *entry, void *arg),
		void *arg,
		struct ip_stats *stats
);
int rrr_ip_send (
	int *err,
	int fd,
	const struct sockaddr *sockaddr,
	socklen_t addrlen,
	void *data,
	ssize_t data_size
);

// TODO : Rename functions

void rrr_ip_network_cleanup (void *arg);
int rrr_ip_network_start_udp_ipv4_nobind (struct rrr_ip_data *data);
int rrr_ip_network_start_udp_ipv4 (struct rrr_ip_data *data);
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
int rrr_ip_network_start_tcp_ipv4_and_ipv6 (struct rrr_ip_data *data, int max_connections);
int rrr_ip_close (struct rrr_ip_data *data);
int rrr_ip_accept(struct rrr_ip_accept_data **accept_data,
		struct rrr_ip_data *listen_data, const char *creator, int tcp_nodelay);

#endif
