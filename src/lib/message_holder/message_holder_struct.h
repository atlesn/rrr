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

#ifndef RRR_MESSAGE_HOLDER_STRUCT_H
#define RRR_MESSAGE_HOLDER_STRUCT_H

#include <sys/socket.h>
#include <stdint.h>
#include <pthread.h>

#include "../socket/rrr_socket.h"
#include "../util/linked_list.h"

//#define RRR_MESSAGE_HOLDER_DEBUG_REFCOUNT
//#define RRR_MESSAGE_HOLDER_DEBUG_LOCK_RECURSION

struct rrr_msg_holder {
	RRR_LL_NODE(struct rrr_msg_holder);
	pthread_mutex_t lock;
#ifdef RRR_MESSAGE_HOLDER_DEBUG_LOCK_RECURSION
	int lock_recursion_count;
#endif
	int usercount;
	rrr_biglength data_length;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	uint8_t protocol;
	const void *source;
	void *message;

	// Message broker updates this on writes to buffer
	uint64_t buffer_time;

	// Available for modules
	uint64_t send_time;

	// Used by higher levels to control partial sends
	rrr_biglength bytes_sent;
	rrr_biglength bytes_to_send;
	int endian_indicator;

	// Available for modules
	void *private_data;
	void (*private_data_destroy)(void *private_data);
};

#endif /* RRR_MESSAGE_HOLDER_STRUCT_H */
