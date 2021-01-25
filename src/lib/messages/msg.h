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

#ifndef RRR_MSG_H
#define RRR_MSG_H

#include "msg_checksum.h"
#include "msg_head.h"
#include "../rrr_types.h"
#include "../read_constants.h"

#define RRR_MSG_READ_OK				RRR_READ_OK
#define RRR_MSG_READ_INCOMPLETE		RRR_READ_INCOMPLETE
#define RRR_MSG_READ_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_MSG_READ_HARD_ERROR		RRR_READ_HARD_ERROR

struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_msg_log;

void rrr_msg_populate_head (
		struct rrr_msg *message,
		rrr_u16 type,
		rrr_u32 msg_size,
		rrr_u64 value
);
void rrr_msg_populate_control_msg (
		struct rrr_msg *message,
		rrr_u16 flags,
		rrr_u64 value
);
void rrr_msg_checksum_and_to_network_endian (
		struct rrr_msg *message
);
int rrr_msg_head_to_host_and_verify (
		struct rrr_msg *message,
		rrr_length expected_size
);
int rrr_msg_get_target_size_and_check_checksum (
		rrr_length *target_size,
		const struct rrr_msg *msg,
		rrr_length buf_size
);
int rrr_msg_check_data_checksum_and_length (
		struct rrr_msg *message,
		rrr_length data_size
);
int rrr_msg_to_host_and_verify_with_callback (
		struct rrr_msg **msg,
		rrr_length expected_size,
		int (*callback_msg)(struct rrr_msg_msg **message, void *arg1, void *arg2),
		int (*callback_addr_msg)(const struct rrr_msg_addr *message, void *arg1, void *arg2),
		int (*callback_log_msg)(const struct rrr_msg_log *message, void *arg1, void *arg2),
		int (*callback_ctrl_msg)(const struct rrr_msg *message, void *arg1, void *arg2),
		void *callback_arg1,
		void *callback_arg2
);

#endif /* RRR_MSG_H */
