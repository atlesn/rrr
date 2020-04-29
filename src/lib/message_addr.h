/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MESSAGE_ADDR_H
#define RRR_MESSAGE_ADDR_H

#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "rrr_endian.h"

#include <sys/socket.h>
#include <unistd.h>

struct rrr_message_addr {
	RRR_SOCKET_MSG_HEAD;
	uint64_t addr_len;
	uint8_t protocol;
	union {
		struct rrr_sockaddr addr;
	};
} __attribute((packed));

static inline void rrr_message_addr_prepare_for_network (struct rrr_message_addr *msg) {
	msg->addr_len = htobe64(msg->addr_len);
}

int rrr_message_addr_to_host (struct rrr_message_addr *msg);
void rrr_message_addr_init (struct rrr_message_addr *target);
int rrr_message_addr_new (struct rrr_message_addr **target);

#endif /* RRR_MESSAGE_ADDR_H */
