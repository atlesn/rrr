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

#ifndef RRR_SOCKET_MSG_H
#define RRR_SOCKET_MSG_H

#include "../global.h"

// The header_crc32 is calculated AFTER conversion to network
// byte order (big endian). The crc32 is then converted itself.

#define RRR_SOCKET_MSG_HEAD		\
	rrr_u32 header_crc32;		\
	rrr_u32 network_size;		\
	rrr_u16 msg_type;			\
	rrr_u32 msg_size;			\
	rrr_u64 msg_value;			\
	rrr_u32 data_crc32;

struct rrr_socket_msg {
	RRR_SOCKET_MSG_HEAD;
} __attribute((packed));

// All odd numbers are reserved for the control type where bits 1-15 are flags
#define RRR_SOCKET_MSG_TYPE_CTRL			1
#define RRR_SOCKET_MSG_TYPE_RRR_MESSAGE		2
#define RRR_SOCKET_MSG_TYPE_SETTING			4

// This bit is reserved for holding the type=control number
#define RRR_SOCKET_MSG_CTRL_F_RESERVED		(1<<0)

// These bits are used by higher level structures. If more flags are needed,
// reserve more USR-bits here to avoid collisions and only refer to them by
// these names
#define RRR_SOCKET_MSG_CTRL_F_USR_A			(1<<15)
#define RRR_SOCKET_MSG_CTRL_F_USR_B			(1<<14)
#define RRR_SOCKET_MSG_CTRL_F_USR_C			(1<<13)
#define RRR_SOCKET_MSG_CTRL_F_USR_D			(1<<12)

#define RRR_SOCKET_MSG_CTRL_F_ALL			(RRR_SOCKET_MSG_CTRL_F_RESERVED|0xF000)
#define RRR_SOCKET_MSG_CTRL_F_HAS(msg,flag)	(((msg)->msg_type & (flag)) == (flag))
#define RRR_SOCKET_MSG_CTRL_FLAGS(msg)		((msg)->msg_type & RRR_SOCKET_MSG_CTRL_F_ALL)

// The control messages contain flags in the type field
#define RRR_SOCKET_MSG_IS_CTRL(msg) \
	(((msg)->msg_type & RRR_SOCKET_MSG_TYPE_CTRL) == RRR_SOCKET_MSG_TYPE_CTRL)
#define RRR_SOCKET_MSG_IS_RRR_MESSAGE(msg) \
	((msg)->msg_type == RRR_SOCKET_MSG_TYPE_RRR_MESSAGE)
#define RRR_SOCKET_MSG_IS_SETTING(msg) \
	((msg)->msg_type == RRR_SOCKET_MSG_TYPE_SETTING)

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
