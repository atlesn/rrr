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

static uint8_t __rrr_increment_calculate_bit_requirement (
		uint64_t n
) {
	int bits = 0;
	while (n) {
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

static uint64_t __rrr_increment_prefix_bits_to_mask_wide (
		uint32_t max
) {
	uint64_t mask = 0xffffffffffffffff;
	mask <<= __rrr_increment_calculate_bit_requirement(max);
	return mask;
}

uint64_t rrr_increment_prefix_bits_to_mask (
		uint8_t prefix_bits,
		uint32_t max
) {
	assert(prefix_bits < 64);

	uint64_t mask = 0xffffffffffffffff;
	mask >>= (64 - prefix_bits);
	mask <<= __rrr_increment_calculate_bit_requirement(max);
	return mask;
}

int rrr_increment_verify_value_prefix (
		uint64_t value,
		uint32_t max,
		uint64_t prefix
) {
	uint8_t bits = __rrr_increment_calculate_bit_requirement (max);

	if ((prefix << bits) != (value & __rrr_increment_prefix_bits_to_mask_wide(max))) {
		RRR_MSG_0("Prefix mismatch, given prefix from value 0x%" PRIx64 " does not match configured prefix 0x%" PRIx64 ". Max value is 0x%" PRIx32 ".\n",
			value, prefix, max);
		return 1;
	}

	return 0;
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

uint32_t rrr_increment_strip_prefix (
		uint64_t value,
		uint32_t max,
		uint8_t prefix_bits
) {
	uint64_t res = value & ~(rrr_increment_prefix_bits_to_mask(prefix_bits, max));
	assert(res <= 0xffffffff && "Value was not completely masked");
	return (uint32_t) res;
}

uint64_t rrr_increment_apply_prefix (
		uint32_t value,
		uint32_t max,
		uint64_t prefix,
		uint8_t prefix_bits
) {
	return ((uint64_t) value) | (prefix << (__rrr_increment_calculate_bit_requirement(max) + prefix_bits));
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
	uint8_t bits_required_for_max = __rrr_increment_calculate_bit_requirement(max);
	uint8_t bits_required_for_prefix = __rrr_increment_calculate_bit_requirement(prefix_max);
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

uint64_t rrr_increment_prefix_apply (
		uint32_t value,
		uint32_t max,
		uint64_t prefix
) {
	uint8_t bits = __rrr_increment_calculate_bit_requirement (max);

	return ((uint64_t) value) | (prefix << bits);
}
