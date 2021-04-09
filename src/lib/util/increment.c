/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include <stdint.h>
#include <stdlib.h>

#include "../log.h"
#include "increment.h"

int rrr_increment_verify (
		const uint64_t step_or_mod,
		const uint64_t min,
		const uint64_t max,
		const uint64_t position_or_zero
) {
	if (step_or_mod > 0xff) {
		RRR_MSG_0("step_or_mod was above max value %lu\n", (long unsigned int) 0xff);
		return 1;
	}
	if (min > 0xffffffff) {
		RRR_MSG_0("min was above max value %lu\n", (long unsigned int) 0xffffffff);
		return 1;
	}
	if (max > 0xffffffff) {
		RRR_MSG_0("max was above max value %lu\n", (long unsigned int) 0xffffffff);
		return 1;
	}
	if (position_or_zero > 0xffffffff) {
		RRR_MSG_0("position was above max value %lu\n", (long unsigned int) 0xff);
		return 1;
	}
	if (min > max) {
		RRR_MSG_0("min was > max in incrementer\n");
		return 1;
	}
	if (step_or_mod == 0) {
		RRR_MSG_0("BUG: mod was 0 in incrementer\n");
		return 1;
	}
	// If min is 5 and max is 10, there are 6 possible numbers
	if (max - min + 1 < step_or_mod) {
		RRR_MSG_0("BUG: max - min was < mod in incrementer\n");
		return 1;
	}
	if (position_or_zero > step_or_mod - 1) {
		RRR_MSG_0("BUG: position was > mod - 1 in incrementer\n");
		return 1;
	}

	return 0;
}

uint32_t rrr_increment_basic (
		const uint32_t value,
		const uint32_t step,
		const uint32_t min,
		const uint32_t max
) {
	uint64_t value_tmp = value + step;
	if (value_tmp > max || value_tmp < min) {
		value_tmp = min;
	}

	return value_tmp;
}

uint32_t rrr_increment_mod (
		const uint32_t value,
		const uint8_t mod,
		const uint32_t min,
		const uint32_t max,
		const uint8_t position
) {
	uint64_t value_tmp = (uint64_t) value - ((uint64_t) value % mod) + mod + position;
	if (value_tmp > max || value_tmp < min) {
		value_tmp = (uint64_t) min - ((uint64_t) min % mod) + position;
		if (value_tmp < min) {
			value_tmp += mod;
		}
	}

	return value_tmp;
}
