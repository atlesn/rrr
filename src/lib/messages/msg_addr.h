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

#include "msg.h"
#include "../socket/rrr_socket.h"
#include "../util/rrr_endian.h"

#include <sys/socket.h>
#include <unistd.h>

struct rrr_msg_addr {
	RRR_MSG_HEAD;
	uint8_t protocol;
	char addr[128];
} __attribute((__packed__));

#define RRR_MSG_ADDR_SIZE_OK(msg) \
	((msg)->msg_size >= sizeof(*(msg)) - sizeof ((msg)->addr))

// NOTE ! This will underflow and wrap around if msg_size is small. We only check for 0 here.
#define RRR_MSG_ADDR_GET_ADDR_LEN(msg) \
	((msg)->msg_size == 0 ? 0 : (msg)->msg_size - sizeof(*(msg)) + sizeof ((msg)->addr))

#define RRR_MSG_ADDR_SET_ADDR_LEN(msg, len) \
	(msg)->msg_size = sizeof(*(msg)) - sizeof((msg)->addr) + (len)

static inline void rrr_msg_addr_prepare_for_network (struct rrr_msg_addr *msg) {
	// Nothing to flip
	(void)(msg);
}

int rrr_msg_addr_to_host (struct rrr_msg_addr *msg);
void rrr_msg_addr_init_head (struct rrr_msg_addr *target, rrr_u32 addr_len);
void rrr_msg_addr_init (struct rrr_msg_addr *target);
int rrr_msg_addr_new (struct rrr_msg_addr **target);
int rrr_msg_addr_clone (
		struct rrr_msg_addr **target,
		const struct rrr_msg_addr *source
);
void rrr_msg_addr_to_str (
		char *target,
		rrr_biglength target_size,
		const struct rrr_msg_addr *msg
);

#endif /* RRR_MESSAGE_ADDR_H */
