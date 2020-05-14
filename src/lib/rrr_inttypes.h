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

#ifndef RRR_INTTYPES_H
#define RRR_INTTYPES_H

#include <stdint.h>
#include <limits.h>

/* Common structures */
#if UCHAR_MAX == 0xff
typedef unsigned char rrr_u8;
#endif

#if USHRT_MAX == 0xffff
typedef unsigned short rrr_u16;
#endif

#if UINT_MAX == 4294967295UL
typedef unsigned int rrr_u32;
#define RRR_SOCKET_32_IS_UINT 1
#elif ULONG_MAX == 4294967295UL
typedef unsigned long int rrr_u32;
#define RRR_SOCKET_32_IS_LONG 1
#endif

#if ULONG_MAX == 18446744073709551615ULL
typedef unsigned long int rrr_u64;
#define RRR_SOCKET_64_IS_LONG 1
#elif ULLONG_MAX == 18446744073709551615ULL
typedef unsigned long long int rrr_u64;
#define RRR_SOCKET_64_IS_LONG_LONG 1
#endif

#ifdef RRR_SOCKET_32_IS_UINT
    typedef unsigned int rrr_u32;
#elif defined (RRR_SOCKET_32_IS_LONG)
    typedef unsigned long int rrr_u32;
#else
#  error "Could not get size of 32 bit unsigned integer"
#endif

#ifdef RRR_SOCKET_64_IS_LONG
    typedef unsigned long int rrr_u64;
#elif defined (RRR_SOCKET_64_IS_LONG_LONG)
    typedef unsigned long long int rrr_u64;
#else
#  error "Could not get size of 64 bit unsigned integer"
#endif

#endif /* RRR_INTTYPES_H */
