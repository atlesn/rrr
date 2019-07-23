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

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>

#ifndef VL_SOCKET_H
#define VL_SOCKET_H

/* Common structures */
#if UCHAR_MAX == 0xff
typedef unsigned char vl_u8;
#endif

#if USHRT_MAX == 0xffff
typedef unsigned short vl_u16;
#endif

#if UINT_MAX == 0xffffffff
typedef unsigned int vl_u32;
#elif ULONG_MAX == 0xffffffff
typedef unsigned long int vl_u32;
#define RRR_SOCKET_32_IS_LONG 1
#endif

#if ULONG_MAX == 0xffffffffffffffff
typedef unsigned long int vl_u64;
#define RRR_SOCKET_64_IS_LONG 1
#elif ULLONG_MAX == 0xffffffffffffffff
typedef unsigned long long int vl_u64;
#endif

#define RRR_SOCKET_MSG_ENDIAN_BYTES		0x0102
#define RRR_SOCKET_MSG_ENDIAN_LE		0x02
#define RRR_SOCKET_MSG_ENDIAN_BE		0x01

#define RRR_SOCKET_MSG_IS_LE(msg)		(msg->endian_one == RRR_SOCKET_MSG_ENDIAN_LE)
#define RRR_SOCKET_MSG_IS_BE(msg)		(msg->endian_one == RRR_SOCKET_MSG_ENDIAN_BE)

#define RRR_SOCKET_MSG_TYPE_VL_MESSAGE	1
#define RRR_SOCKET_MSG_TYPE_SETTING		2

#define RRR_SOCKET_MSG_IS_VL_MESSAGE(msg) \
	((msg)->msg_type == RRR_SOCKET_MSG_TYPE_VL_MESSAGE)
#define RRR_SOCKET_MSG_IS_SETTING(msg) \
	((msg)->msg_type == RRR_SOCKET_MSG_TYPE_SETTING)

#define RRR_SOCKET_MSG_HEAD \
	vl_u32 crc32; \
	union { \
		vl_u16 endian_two; \
		vl_u8 endian_one; \
	}; \
	vl_u16 msg_type; \
	vl_u32 msg_size

struct rrr_socket_msg {
	RRR_SOCKET_MSG_HEAD;
};

int rrr_socket_msg_head_to_host (struct rrr_socket_msg *message);
void rrr_socket_msg_head_to_network (struct rrr_socket_msg *message, vl_u16 type, vl_u32 msg_size);
void rrr_socket_msg_checksum (
	struct rrr_socket_msg *message,
	ssize_t total_size
);
int rrr_socket_msg_checksum_check (
	struct rrr_socket_msg *message,
	ssize_t total_size
);

#endif /* VL_SOCKET_H */
