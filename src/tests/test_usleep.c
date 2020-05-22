/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include "test_usleep.h"
#include "../lib/log.h"
#include "../lib/posix.h"
#include "../lib/vl_time.h"

// Six zeros = 1s
#define SLEEPTIME_US 1000000

// Four zeros = 50ms
#define SLEEPTIME_TOLERANCE_US 50000

int rrr_test_usleep (void) {
	int ret = 0;

	uint64_t time_start = rrr_time_get_64();

	rrr_posix_usleep(SLEEPTIME_US);

	uint64_t time_end = rrr_time_get_64();

	uint64_t sleeptime_us = (time_end - time_start);

	// We only care about problems with conversion between 1000's
	// On FreeBSD, the timer is very inacurate. Allow the double in
	// positive direction.
	if (	sleeptime_us < SLEEPTIME_US - SLEEPTIME_TOLERANCE_US ||
		sleeptime_us > (SLEEPTIME_US * 2) + SLEEPTIME_TOLERANCE_US
	) {
		RRR_MSG_ERR ("Sleep time out of range, slept for %" PRIu64 " usecs expected %i +/- %i usecs\n",
			sleeptime_us, SLEEPTIME_US, SLEEPTIME_TOLERANCE_US);	
		ret = 1;
	}

	return ret;
}
