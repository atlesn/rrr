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

#include <stdlib.h>
#include <string.h>

#include "msgdb_common.h"
#include "../log.h"
#include "../allocator.h"
#include "../rrr_strerror.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../socket/rrr_socket.h"

static int __rrr_msgdb_common_ctrl_msg_send (
		int fd,
		rrr_u16 flags,
		rrr_u32 arg,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_msg *msg_tmp;

	RRR_DBG_3("msgdb fd %i send CTRL flags %i\n", fd, flags);

	if ((msg_tmp = rrr_allocate(sizeof(*msg_tmp)))== NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_msgdb_common_ctrl_msg_send\n");
		ret = 1;
		goto out;
	}

	rrr_msg_populate_control_msg (msg_tmp, flags, arg);
	rrr_msg_checksum_and_to_network_endian (msg_tmp);

	ret = send_callback(fd, (void**) &msg_tmp, sizeof(*msg_tmp), callback_arg);

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

int rrr_msgdb_common_ctrl_msg_send_ack (
		int fd,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_ACK, 0, send_callback, callback_arg);
}

int rrr_msgdb_common_ctrl_msg_send_nack (
		int fd,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_NACK, 0, send_callback, callback_arg);
}

int rrr_msgdb_common_ctrl_msg_send_ping (
		int fd,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_PING, 0, send_callback, callback_arg);
}

int rrr_msgdb_common_ctrl_msg_send_pong (
		int fd,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_PONG, 0, send_callback, callback_arg);
}

int rrr_msgdb_common_ctrl_msg_send_tidy (
		int fd,
		uint32_t max_age_s,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	return __rrr_msgdb_common_ctrl_msg_send(fd, RRR_MSGDB_CTRL_F_TIDY, max_age_s, send_callback, callback_arg);
}

int rrr_msgdb_common_msg_send (
		int fd,
		const struct rrr_msg_msg *msg,
		int (*send_callback)(int fd, void **data, rrr_length data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_msg_msg *msg_tmp;

	RRR_DBG_3("msgdb fd %i send MSG size %" PRIrrrl "\n", fd, MSG_TOTAL_SIZE(msg));

	if ((msg_tmp = rrr_allocate(MSG_TOTAL_SIZE(msg))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_msgdb_common_msg_send\n");
		ret = 1;
		goto out;
	}

	memcpy(msg_tmp, msg, MSG_TOTAL_SIZE(msg));

	rrr_msg_msg_prepare_for_network(msg_tmp);
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg_tmp);

	ret = send_callback(fd, (void **) &msg_tmp, MSG_TOTAL_SIZE(msg), callback_arg);

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}
