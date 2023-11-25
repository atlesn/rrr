/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_TIME_H
#define RRR_TIME_H

#include <inttypes.h>

#include "../rrr_types.h"

static inline rrr_time_s_t rrr_time_s_from_ms (rrr_time_ms_t ms) {
	rrr_time_s_t s = { ms.ms / 1000 };
	return s;
}

static inline rrr_time_s_t rrr_time_s_from_us (rrr_time_us_t us) {
	rrr_time_s_t s = { us.us / 1000 / 1000 };
	return s;
}

static inline rrr_time_ms_t rrr_time_ms_from_s (rrr_time_s_t s) {
	rrr_time_ms_t ms = { s.s * 1000 };
	assert(ms.ms >= s.s && "Overflow in rrr_time_ms_from_s");
	return ms;
}

static inline rrr_time_ms_t rrr_time_ms_from_us (rrr_time_us_t us) {
	rrr_time_ms_t ms = { us.us / 1000 };
	return ms;
}

static inline rrr_time_us_t rrr_time_us_from_ms (rrr_time_ms_t ms) {
	rrr_time_us_t us = { ms.ms * 1000 };
	assert(us.us >= ms.ms && "Overflow in rrr_time_us_from_ms");
	return us;
}

static inline rrr_time_us_t rrr_time_us_from_s (rrr_time_s_t s) {
	rrr_time_us_t us = { s.s * 1000 * 1000 };
	assert(us.us >= s.s && "Overflow in rrr_time_us_from_s");
	return us;
}

static inline rrr_time_us_t rrr_time_us_sub (rrr_time_us_t a, rrr_time_us_t b) {
	rrr_time_us_t us = { a.us - b.us };
	assert(us.us <= a.us && "Underflow in rrr_time_us_sub");
	return us;
}

static inline int rrr_time_us_lt (rrr_time_us_t a, rrr_time_us_t b) {
	return a.us < b.us;
}

static inline int rrr_time_us_eq (rrr_time_us_t a, rrr_time_us_t b) {
	return a.us == b.us;
}

static inline int rrr_time_ms_eq (rrr_time_ms_t a, rrr_time_ms_t b) {
	return a.ms == b.ms;
}

static inline int rrr_time_s_eq (rrr_time_s_t a, rrr_time_s_t b) {
	return a.s == b.s;
}

static inline int rrr_time_us_zero (rrr_time_us_t a) {
	return a.us == 0;
}

struct timeval;
struct timespec;

uint64_t rrr_time_get_64(void);
rrr_time_us_t rrr_time_get_us(void);
void rrr_time_gettimeofday (struct timeval *__restrict __tv, uint64_t usec_add);
void rrr_time_gettimeofday_timespec (struct timespec *tspec, uint64_t usec_add);
void rrr_time_from_usec (struct timeval *__restrict __tv, uint64_t usec);

#endif /* RRR_TIME_H */
