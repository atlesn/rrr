/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <sys/socket.h>
#include <stdint.h>

#include "../../lib/messages.h"

#ifdef VL_WITH_OPENSSL
#include "../../lib/module_crypt.h"
#endif

#define VL_IP_DEFAULT_PORT 5555

#define VL_IP_RECEIVE_OK 0
#define VL_IP_RECEIVE_ERR 1
#define VL_IP_RECEIVE_STOP 2

// Print/reset stats every X seconds
#define VL_IP_STATS_DEFAULT_PERIOD 3

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

struct ip_buffer_entry {
	struct vl_message message; // Must be first, we do dangerous casts :)
	struct sockaddr addr;
	socklen_t addr_len;
	uint64_t time;
};

struct ip_send_packet_info {
	void *data;
	int fd;
	struct addrinfo *res;
	int packet_counter;
};

struct ip_data {
	int fd;
};

#define VL_IP_STATS_UPDATE_OK 0		// Stats was updated
#define VL_IP_STATS_UPDATE_ERR 1	// Error
#define VL_IP_STATS_UPDATE_READY 2	// Limit is reached, we should print

void ip_stats_init (
		struct ip_stats *stats, unsigned int period, const char *type, const char *name
);
void ip_stats_init_twoway (
		struct ip_stats_twoway *stats, unsigned int period, const char *name
);
int ip_stats_update(
		struct ip_stats *stats, unsigned long int packets, unsigned long int bytes
);
int ip_stats_print_reset(
		struct ip_stats *stats, int do_reset
);

int ip_receive_packets (
		int fd,
#ifdef VL_WITH_OPENSSL
		struct module_crypt_data *crypt_data,
#endif
		int (*callback)(struct ip_buffer_entry *ip, void *arg),
		void *arg,
		struct ip_stats *stats
);
int ip_send_packet (
		struct vl_message* message,
#ifdef VL_WITH_OPENSSL
		struct module_crypt_data *crypt_data,
#endif
		struct ip_send_packet_info* info,
		struct ip_stats *stats
);
void ip_network_cleanup (void *arg);
int ip_network_start (struct ip_data *data);
