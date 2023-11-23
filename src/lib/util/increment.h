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

#ifndef RRR_INCREMENT_H
#define RRR_INCREMENT_H

#include <stdint.h>

uint64_t rrr_increment_bits_to_max (
		uint8_t bits
);
uint64_t rrr_increment_max_to_prefix_mask (
		uint32_t max
);
int rrr_increment_verify_value_prefix (
		uint64_t value,
		uint32_t max,
		uint64_t prefix
);
uint32_t rrr_increment_strip_prefix (
		uint64_t value,
		uint32_t max
);
uint64_t rrr_increment_apply_prefix (
		uint32_t value,
		uint32_t max,
		uint64_t prefix
);
int rrr_increment_verify (
		uint64_t step_or_mod,
		uint64_t min,
		uint64_t max,
		uint64_t position_or_zero,
		uint64_t prefix
);
uint32_t rrr_increment_basic (
		uint32_t value,
		uint32_t step,
		uint32_t min,
		uint32_t max
);
uint32_t rrr_increment_mod (
		uint32_t value,
		uint8_t mod,
		uint32_t min,
		uint32_t max,
		uint8_t position
);

#endif /* RRR_INCREMENT_H */
