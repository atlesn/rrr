/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_ATOMIC_H
#define RRR_ATOMIC_H

#include <stdint.h>

typedef struct rrr_atomic_u32_s {
	int32_t value;
} rrr_atomic_u32_t;

typedef struct rrr_atomic_u64_s {
	uint64_t value;
} rrr_atomic_u64_t;

static inline int rrr_atomic_u32_load(rrr_atomic_u32_t *atomic) {
	int res;
	__atomic_load(&atomic->value, &res, __ATOMIC_SEQ_CST);
	return res;
}

static inline int rrr_atomic_u32_or_fetch(rrr_atomic_u32_t *atomic, int32_t value) {
	return __atomic_or_fetch(&atomic->value, value, __ATOMIC_SEQ_CST);
}

static inline int rrr_atomic_u32_fetch_xor(rrr_atomic_u32_t *atomic, int32_t value) {
	return __atomic_fetch_xor(&atomic->value, value, __ATOMIC_SEQ_CST);
}

static inline uint64_t rrr_atomic_u64_load_relaxed(rrr_atomic_u64_t *atomic) {
	uint64_t res;
	__atomic_load(&atomic->value, &res, __ATOMIC_RELAXED);
	return res;
}

static inline void rrr_atomic_u64_store_relaxed(rrr_atomic_u64_t *atomic, uint64_t value) {
	__atomic_store(&atomic->value, &value, __ATOMIC_RELAXED);
}

#endif /* RRR_ATOMIC_H */
