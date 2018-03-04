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

#define VL_IP_DEFAULT_PORT 5555

#define VL_IP_RECEIVE_OK 0
#define VL_IP_RECEIVE_ERR 1
#define VL_IP_RECEIVE_STOP 2

struct ip_buffer_entry {
	struct vl_message message; // Must be first, we do dangerous casts :)
	struct sockaddr addr;
	socklen_t addr_len;
	uint64_t time;
};

struct ip_data {
	int fd;
};

int ip_receive_packets(int fd, int (*callback)(struct ip_buffer_entry *ip, void *arg), void *arg);
void ip_network_cleanup (void *arg);
int ip_network_start (struct ip_data *data);
