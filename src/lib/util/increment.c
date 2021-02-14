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
	if (min > max) {
		RRR_BUG("BUG: min was > max in incrementer\n");
	}
	if (mod == 0) {
		RRR_BUG("BUG: mod was 0 in incrementer\n");
	}
	// If min is 5 and max is 10, there are 6 possible numbers
	if (max - min + 1 < mod) {
		RRR_BUG("BUG: max - min was < mod in incrementer\n");
	}
	if (position > mod - 1) {
		RRR_BUG("BUG: position was > mod - 1 in incrementer\n");
	}

	uint64_t value_tmp = (uint64_t) value - ((uint64_t) value % mod) + mod + position;
	if (value_tmp > max || value_tmp < min) {
		value_tmp = (uint64_t) min - ((uint64_t) min % mod) + position;
		if (value_tmp < min) {
			value_tmp += mod;
		}
	}

	return value_tmp;
}
