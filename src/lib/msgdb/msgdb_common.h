/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MSGDB_COMMON_H
#define RRR_MSGDB_COMMON_H

#include <stdio.h>

#include "../messages/msg_head.h"
#include "../read_constants.h"

#define RRR_MSGDB_OK             RRR_READ_OK
#define RRR_MSGDB_HARD_ERROR     RRR_READ_HARD_ERROR
#define RRR_MSGDB_SOFT_ERROR     RRR_READ_SOFT_ERROR
#define RRR_MSGDB_EOF            RRR_READ_EOF

#define RRR_MSGDB_CTRL_F_ACK     RRR_MSG_CTRL_F_ACK
#define RRR_MSGDB_CTRL_F_NACK    RRR_MSG_CTRL_F_NACK
#define RRR_MSGDB_CTRL_F_PING    RRR_MSG_CTRL_F_PING
#define RRR_MSGDB_CTRL_F_PONG    RRR_MSG_CTRL_F_PONG

struct rrr_msg_msg;

int rrr_msgdb_common_ctrl_msg_send (
		int fd,
		int flags,
		int (*send_callback)(int fd, void **data, ssize_t data_size, void *arg),
		void *callback_arg
);
int rrr_msgdb_common_msg_send (
		int fd,
		const struct rrr_msg_msg *msg,
		int (*send_callback)(int fd, void **data, ssize_t data_size, void *arg),
		void *callback_arg
);

#endif /* RRR_MSGDB_COMMON_H */
