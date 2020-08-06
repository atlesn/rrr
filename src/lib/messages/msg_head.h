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

#ifndef RRR_MSG_HEAD_H
#define RRR_MSG_HEAD_H

#include "../rrr_inttypes.h"

// All odd numbers are reserved for the control type where bits 1-15 are flags
#define RRR_MSG_TYPE_CTRL			1
#define RRR_MSG_TYPE_MESSAGE			2
#define RRR_MSG_TYPE_SETTING			4
#define RRR_MSG_TYPE_TREE_DATA		6
#define RRR_MSG_TYPE_MESSAGE_ADDR	8
#define RRR_MSG_TYPE_MESSAGE_LOG		16

// This bit is reserved for holding the type=control number
#define RRR_MSG_CTRL_F_RESERVED		(1<<0)
#define RRR_MSG_CTRL_F_ACK			(1<<1)

// These bits are used by higher level structures. If more flags are needed,
// reserve more USR-bits here to avoid collisions and only refer to them by
// these names
#define RRR_MSG_CTRL_F_USR_A			(1<<15)
#define RRR_MSG_CTRL_F_USR_B			(1<<14)
#define RRR_MSG_CTRL_F_USR_C			(1<<13)
#define RRR_MSG_CTRL_F_USR_D			(1<<12)

#define RRR_MSG_CTRL_F_ALL				(RRR_MSG_CTRL_F_RESERVED|RRR_MSG_CTRL_F_ACK|0xF000)
#define RRR_MSG_CTRL_F_HAS(msg,flag)		(((msg)->msg_type & (flag)) == (flag))
#define RRR_MSG_CTRL_F_CLEAR(msg,flag)	((msg)->msg_type &= ~(flag))
#define RRR_MSG_CTRL_FLAGS(msg)			((msg)->msg_type & RRR_MSG_CTRL_F_ALL)

// The control messages contain flags in the type field
#define RRR_MSG_IS_CTRL(msg) \
	(((msg)->msg_type & RRR_MSG_TYPE_CTRL) == RRR_MSG_TYPE_CTRL)
#define RRR_MSG_IS_CTRL_NETWORK_ENDIAN(msg) \
	((be16toh((msg)->msg_type) & RRR_MSG_TYPE_CTRL) == RRR_MSG_TYPE_CTRL)
#define RRR_MSG_IS_RRR_MESSAGE(msg) \
	((msg)->msg_type == RRR_MSG_TYPE_MESSAGE)
#define RRR_MSG_IS_RRR_MESSAGE_ADDR(msg) \
	((msg)->msg_type == RRR_MSG_TYPE_MESSAGE_ADDR)
#define RRR_MSG_IS_SETTING(msg) \
	((msg)->msg_type == RRR_MSG_TYPE_SETTING)
#define RRR_MSG_IS_RRR_MESSAGE_LOG(msg) \
	((msg)->msg_type == RRR_MSG_TYPE_MESSAGE_LOG)

// The header_crc32 is calculated AFTER conversion to network
// byte order (big endian). The crc32 is then converted itself.

#define RRR_MSG_HEAD			\
	rrr_u32 header_crc32;		\
	rrr_u32 msg_size;			\
	rrr_u16 msg_type;			\
	rrr_u32 msg_value;			\
	rrr_u32 data_crc32;

struct rrr_msg {
	RRR_MSG_HEAD;
} __attribute((packed));

#endif /* RRR_MSG_HEAD */
