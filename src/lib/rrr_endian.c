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

#define _DEFAULT_SOURCE

#include <stdint.h>

#if defined(__linux__)
#include <endian.h>
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
#include <sys/endian.h>
#endif

#include "rrr_endian.h"

uint16_t rrr_htobe16(uint16_t x) {
	return htobe16(x);
}
uint16_t rrr_htole16(uint16_t x) {
	return htole16(x);
}
uint16_t rrr_be16toh(uint16_t x) {
	return be16toh(x);
}
uint16_t rrr_le16toh(uint16_t x) {
	return le16toh(x);
}

uint32_t rrr_htobe32(uint32_t x) {
	return htobe32(x);
}
uint32_t rrr_htole32(uint32_t x) {
	return htole32(x);
}
uint32_t rrr_be32toh(uint32_t x) {
	return be32toh(x);
}
uint32_t rrr_le32toh(uint32_t x) {
	return le32toh(x);
}

uint64_t rrr_htobe64(uint64_t x) {
	return htobe64(x);
}
uint64_t rrr_htole64(uint64_t x) {
	return htole64(x);
}
uint64_t rrr_be64toh(uint64_t x) {
	return be64toh(x);
}
uint64_t rrr_le64toh(uint64_t x) {
	return le64toh(x);
}
