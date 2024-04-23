/*

Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <inttypes.h>
#include <stdio.h>

#include "test.h"
#include "test_time.h"
#include "../lib/log.h"
#include "../lib/util/posix.h"
#include "../lib/util/rrr_time.h"

// Six zeros = 1s
#define SLEEPTIME_US 1000000

// Four zeros = 50ms
#define SLEEPTIME_TOLERANCE_US 50000

static int __test_time_usleep (void) {
	int ret = 0;

	uint64_t time_start = rrr_time_get_64();

	rrr_posix_usleep(SLEEPTIME_US);

	uint64_t time_end = rrr_time_get_64();

	uint64_t sleeptime_us = (time_end - time_start);

	// We only care about problems with conversion between 1000's
	// On FreeBSD, the timer is very inaccurate. Allow the double in
	// positive direction.
	if (	sleeptime_us < SLEEPTIME_US - SLEEPTIME_TOLERANCE_US ||
		sleeptime_us > (SLEEPTIME_US * 2) + SLEEPTIME_TOLERANCE_US
	) {
		RRR_MSG_0("Sleep time out of range, slept for %" PRIu64 " usecs expected %i +/- %i usecs\n",
			sleeptime_us, SLEEPTIME_US, SLEEPTIME_TOLERANCE_US);	
		ret = 1;
	}

	return ret;
}

static int __test_time_conversions (void) {
	int ret = 0;

	rrr_time_us_t us = { 1000000 };
	rrr_time_ms_t ms = { 1000 };
	rrr_time_s_t s = { 1 };

	rrr_time_us_t us2 = rrr_time_us_from_ms(ms);
	rrr_time_us_t us3 = rrr_time_us_from_s(s);

	rrr_time_ms_t ms2 = rrr_time_ms_from_us(us);
	rrr_time_ms_t ms3 = rrr_time_ms_from_s(s);

	rrr_time_s_t s2 = rrr_time_s_from_us(us);
	rrr_time_s_t s3 = rrr_time_s_from_ms(ms);

	if (rrr_time_us_eq(us, us2) == 0) {
		RRR_MSG_0("rrr_time_us_from_ms failed\n");
		ret = 1;
	}

	if (rrr_time_us_eq(us, us3) == 0) {
		RRR_MSG_0("rrr_time_us_from_s failed\n");
		ret = 1;
	}

	if (rrr_time_ms_eq(ms, ms2) == 0) {
		RRR_MSG_0("rrr_time_ms_from_us failed\n");
		ret = 1;
	}

	if (rrr_time_ms_eq(ms, ms3) == 0) {
		RRR_MSG_0("rrr_time_ms_from_s failed\n");
		ret = 1;
	}

	if (rrr_time_s_eq(s, s2) == 0) {
		RRR_MSG_0("rrr_time_s_from_us failed\n");
		ret = 1;
	}

	if (rrr_time_s_eq(s, s3) == 0) {
		RRR_MSG_0("rrr_time_s_from_ms failed\n");
		ret = 1;
	}

	rrr_time_us_t us4 = { 1 };
	rrr_time_us_t us5 = rrr_time_us_sub(us, us4);

	if (us5.us != 999999) {
		RRR_MSG_0("rrr_time_us_sub failed\n");
		ret = 1;
	}

	if (!rrr_time_us_lt(us4, us)) {
		RRR_MSG_0("rrr_time_us_lt failed\n");
		ret = 1;
	}

	rrr_time_us_t us6 = { 0 };

	if (!rrr_time_us_zero(us6)) {
		RRR_MSG_0("rrr_time_us_zero failed\n");
		ret = 1;
	}

	return ret;
}

int rrr_test_time (void) {
	int ret = 0;

	ret |= __test_time_usleep();
	ret |= __test_time_conversions();

	return ret;
}
