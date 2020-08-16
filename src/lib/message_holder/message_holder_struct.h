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

// TODO : Make this smaller
// TODO : Change data_length to unsigned

struct rrr_msg_holder {
	RRR_LL_NODE(struct rrr_msg_holder);
	pthread_mutex_t lock;
	int usercount;
	ssize_t data_length;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	int protocol;
	uint64_t send_time;
	void *message;
};

#endif /* RRR_MESSAGE_HOLDER_STRUCT_H */
