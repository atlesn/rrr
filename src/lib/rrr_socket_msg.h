/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_SOCKET_MSG_H
#define RRR_SOCKET_MSG_H

#include <stdio.h>

#include "../global.h"
#include "rrr_socket_msg_checksum.h"
#include "rrr_socket_msg_head.h"

void rrr_socket_msg_populate_head (
		struct rrr_socket_msg *message,
		rrr_u16 type,
		rrr_u32 msg_size,
		rrr_u64 value
);
void rrr_socket_msg_populate_control_msg (
		struct rrr_socket_msg *message,
		rrr_u16 flags,
		rrr_u64 value
);
void rrr_socket_msg_checksum_and_to_network_endian (
		struct rrr_socket_msg *message
);
int rrr_socket_msg_head_to_host_and_verify (
		struct rrr_socket_msg *message,
		ssize_t expected_size
);
int rrr_socket_msg_get_target_size_and_check_checksum (
		ssize_t *target_size,
		struct rrr_socket_msg *socket_msg,
		ssize_t buf_size
);
int rrr_socket_msg_check_data_checksum_and_length (
		struct rrr_socket_msg *message,
		ssize_t data_size
);

#endif /* RRR_SOCKET_MSG_H */
