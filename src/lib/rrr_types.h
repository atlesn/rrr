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

#ifndef RRR_TYPES_H
#define RRR_TYPES_H

#include <stdint.h>

#define RRR_TYPE_LENGTH_MAX 0xffffffff

typedef uint8_t rrr_type;
typedef uint8_t rrr_type_flags;
typedef uint32_t rrr_type_length;
typedef uint32_t rrr_def_count;
typedef uint32_t rrr_type_array_size;
typedef uint32_t rrr_size;
typedef uint64_t rrr_type_le;
typedef uint64_t rrr_type_be;
typedef uint64_t rrr_type_h;
typedef uint64_t rrr_type_istr;
typedef uint64_t rrr_type_ustr;

#endif /* RRR_TYPES_H */
