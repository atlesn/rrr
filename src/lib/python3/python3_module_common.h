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

#ifndef RRR_PYTHON3_MODULE_COMMON_H
#define RRR_PYTHON3_MODULE_COMMON_H

#include "python3_headers.h"

#include "../messages/rrr_msg_head.h"
#include "../util/macro_utils.h"

#define RRR_PYTHON3_MODULE_NAME	"rrr_helper"
#define RRR_PYTHON3_SOCKET_TYPE_NAME "rrr_socket"
#define RRR_PYTHON3_RRR_MESSAGE_TYPE_NAME "rrr_msg_msg"
#define RRR_PYTHON3_ARRAY_TYPE_NAME "rrr_array"
#define RRR_PYTHON3_ARRAY_VALUE_TYPE_NAME "rrr_array_value"
#define RRR_PYTHON3_CONFIG_TYPE_NAME "rrr_config"

#define RRR_PY_8 T_UBYTE
#define RRR_PY_16 T_USHORT

#ifdef RRR_SOCKET_64_IS_LONG
	#define RRR_PY_64 T_ULONG
	#define RRR_PY_LONG_AS_64 PyLong_AsUnsignedLong
#elif RRR_SOCKET_64_IS_LONG_LONG
	#define RRR_PY_64 T_ULONGLONG
	#define RRR_PY_LONG_AS_64 PyLong_AsUnsignedLongLong
#endif

#ifdef RRR_SOCKET_32_IS_UINT
	#define RRR_PY_32 T_UINT
	#define RRR_PY_LONG_AS_32 (unsigned int) PyLong_AsLong
#elif RRR_SOCKET_32_IS_LONG
	#define RRR_PY_32 T_ULONG
	#define RRR_PY_LONG_AS_32 PyLong_AsUnsignedLong
#endif

#define RRR_PY_QUOTE(str) \
	"\"" #str "\""

#define RRR_PY_PASTE(a,b) \
	a ## b

#define RRR_PY_ASSERT_IN_BOUNDS(name,bits) \
	do {if (name > RRR_PY_PASTE(max_,bits)) { RRR_MSG_0("Value of parameter " RRR_PY_QUOTE(name) " exceeds maximum in .set()\n"); ret = 1; }}while(0)

#define RRR_PY_DECLARE_GET_TEST_32(idx,name) \
		unsigned long long name = RRR_PY_LONG_AS_32(args[idx]); \
		do { RRR_PY_ASSERT_IN_BOUNDS(name,32);}while(0)

#define RRR_PY_DECLARE_GET_TEST_64(idx,name) \
		unsigned long long name = RRR_PY_LONG_AS_64(args[idx]); \
		do { RRR_PY_ASSERT_IN_BOUNDS(name,64);}while(0)

#endif /* RRR_PYTHON3_MODULE_COMMON_H */
