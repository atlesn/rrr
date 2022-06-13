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

#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "rrr_time.h"

#include "../log.h"
#include "../rrr_strerror.h"

// Allow gettimeofday on BSD

#undef __XSI_VISIBLE
#undef _XOPEN_SOURCE

#define _XOPEN_SOURCE 500
#define __XSI_VISIBLE 1

#include <sys/time.h>

uint64_t rrr_time_get_64(void) {
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0) {
		RRR_BUG("Error while getting time in rrr_time_get_64, cannot recover from this: %s\n", rrr_strerror(errno));
	}

	uint64_t tv_sec = (uint64_t) tv.tv_sec;
	uint64_t tv_factor = 1000000;
	uint64_t tv_usec = (uint64_t) tv.tv_usec;

	return (tv_sec * tv_factor) + (tv_usec);
}

int rrr_time_get_64_nano(uint64_t *result, uint64_t s_factor) {
	struct timespec tp;

	*result = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		RRR_MSG_0("Failed to get time in %s: %s\n", __func__, rrr_strerror(errno));
		return 1;
	}

	*result = (uint64_t) tp.tv_sec * s_factor + (uint64_t) tp.tv_nsec;

	return 0;
}

void rrr_time_gettimeofday (struct timeval *__restrict __tv, uint64_t usec_add) {
	if (gettimeofday(__tv, NULL) != 0) {
		RRR_BUG("Error while getting time in rrr_time_gettimeofday, cannot recover from this: %s\n", rrr_strerror(errno));
	}
	if (usec_add > 0) {
		uint64_t new_usec = (uint64_t) __tv->tv_usec + usec_add;
		uint64_t sec_add = new_usec / 1000000;
		new_usec -= (sec_add * 1000000);
		__tv->tv_sec += (long) sec_add;
		__tv->tv_usec = (long) new_usec;
	}
}

void rrr_time_gettimeofday_timespec (struct timespec *tspec, uint64_t usec_add) {
	struct timeval tval;
	rrr_time_gettimeofday(&tval, usec_add);
	tspec->tv_sec = tval.tv_sec;
	tspec->tv_nsec = tval.tv_usec * 1000;
}

void rrr_time_from_usec (struct timeval *__restrict __tv, uint64_t usec) {
	struct timeval result = {0};

	const uint64_t usec_part = usec % 1000000;

	result.tv_usec = (useconds_t) usec_part;
	result.tv_sec = (time_t) ((usec - usec_part) / 1000000);

	*__tv = result;
}
