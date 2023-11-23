/*

Read Route Record

Copyright (C) 2021-2023 Atle Solbakken atle@goliathdns.no

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

static int __rrr_increment_calculate_bit_requirement (
		uint64_t n
) {
	int bits = 0;
	while (n > 0) {
		bits++;
		n >>= 1;
	}
	return bits;
}

uint64_t rrr_increment_bits_to_max (
		uint8_t bits
) {
	assert(bits <= 64);

	uint64_t max = 0;
	while (bits > 0) {
		max <<= 1;
		max |= 1;
		bits--;
	}
	return max;
}

int rrr_increment_verify_prefix (
		uint64_t prefix_max,
		uint64_t prefix_bits
) {
	if (prefix_max > rrr_increment_bits_to_max(prefix_bits)) {
		RRR_MSG_0("Prefix max %" PRIu64 " cannot fit within the given number of prefix bits %" PRIu64 "\n", prefix_max, prefix_bits);
		return 1;
	}
	return 0;
}

int rrr_increment_verify (
		uint64_t step_or_mod,
		uint64_t min,
		uint64_t max,
		uint64_t position_or_zero,
		uint64_t prefix_max
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

	// Check that the number of bits required for prefix + the number of bits required for max does not exceed 64.
	// The prefix may exceed 32 bits as long as the total number of bits do not exceed 64.
	uint64_t bits_required_for_max = __rrr_increment_calculate_bit_requirement(max);
	uint64_t bits_required_for_prefix = __rrr_increment_calculate_bit_requirement(prefix_max);
	printf("%" PRIu64 " %" PRIu64 "\n", bits_required_for_max, bits_required_for_prefix);
	if (bits_required_for_max + bits_required_for_prefix > 64) {
		RRR_MSG_0("Bits required for max + bits required for prefix exceeds 64 in incrementer\n");
		return 1;
	}

	return 0;
}

uint32_t rrr_increment_basic (
		uint32_t value,
		uint32_t step,
		uint32_t min,
		uint32_t max
) {
	uint64_t value_tmp = value + step;
	if (value_tmp > max || value_tmp < min) {
		value_tmp = min;
	}

	return (uint32_t) value_tmp;
}

uint32_t rrr_increment_mod (
		uint32_t value,
		uint8_t mod,
		uint32_t min,
		uint32_t max,
		uint8_t position
) {
	uint64_t value_tmp = (uint64_t) value - ((uint64_t) value % mod) + mod + position;
	if (value_tmp > max || value_tmp < min) {
		value_tmp = (uint64_t) min - ((uint64_t) min % mod) + position;
		if (value_tmp < min) {
			value_tmp += mod;
		}
	}

	return (uint32_t) value_tmp;
}
