/*

Block Device Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#ifndef BDL_CRYPT_H
#define BDL_CRYPT_H

#include <stdint.h>

#define BDL_HASH_ALGORITHM_CRC32 0

#define BDL_HASH_ALGORITHM_MAX 0

#define BDL_DEFAULT_HASH_ALGORITHM BDL_HASH_ALGORITHM_CRC32

#define BDL_HASH_ALGORITHM_NAMES {	\
		"CRC32",					\
		""							\
}

typedef uint8_t BDL_HASH_ALGORITHM;

int crypt_hash_data(const char *data, int length, BDL_HASH_ALGORITHM algorithm, uint32_t *dest);
int crypt_check_hash(const char *data, int length, BDL_HASH_ALGORITHM algorithm, uint32_t hash, int *result);

#endif
