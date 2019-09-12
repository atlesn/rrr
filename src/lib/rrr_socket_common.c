/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>

#include "../global.h"
#include "rrr_socket.h"
#include "rrr_socket_msg.h"
#include "rrr_socket_common.h"
#include "array.h"

int rrr_socket_common_get_session_target_length_from_message_and_checksum (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	if (arg != NULL) {
		VL_BUG("arg was not NULL in rrr_socket_get_target_length_from_msg\n");
	}

	ssize_t target_size = 0;
	int ret = rrr_socket_msg_get_target_size_and_check_checksum(
			&target_size,
			(struct rrr_socket_msg *) read_session->rx_buf_ptr,
			read_session->rx_buf_wpos
	);

	if (ret != 0) {
		if (ret != RRR_SOCKET_READ_INCOMPLETE) {
			VL_MSG_ERR("Warning: Header checksum of message failed in rrr_socket_get_target_length_from_msg\n");
		}
		goto out;
	}

	read_session->target_size = target_size;

	out:
	return ret;
}

int rrr_socket_common_read_raw_array_from_read_session_callback (
		struct rrr_socket_read_session *read_session,
		void *arg
) {
	struct  rrr_socket_common_read_raw_array_from_read_session_callback_data *data = arg;

	return rrr_array_new_message_from_buffer (
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			data->definitions,
			data->callback,
			data->callback_arg
	);
}
