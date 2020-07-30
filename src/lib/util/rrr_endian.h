/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_ENDIAN_H
#define RRR_ENDIAN_H

#include <inttypes.h>

uint16_t rrr_htobe16(uint16_t x);
uint16_t rrr_htole16(uint16_t x);
uint16_t rrr_be16toh(uint16_t x);
uint16_t rrr_le16toh(uint16_t x);

uint32_t rrr_htobe32(uint32_t x);
uint32_t rrr_htole32(uint32_t x);
uint32_t rrr_be32toh(uint32_t x);
uint32_t rrr_le32toh(uint32_t x);

uint64_t rrr_htobe64(uint64_t x);
uint64_t rrr_htole64(uint64_t x);
uint64_t rrr_be64toh(uint64_t x);
uint64_t rrr_le64toh(uint64_t x);

#endif /* RRR_ENDIAN_H */
