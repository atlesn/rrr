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

#ifndef RRR_INCREMENT_H
#define RRR_INCREMENT_H

#include <stdint.h>

uint32_t rrr_increment_basic (
		const uint32_t value,
		const uint32_t step,
		const uint32_t min,
		const uint32_t max
);
uint32_t rrr_increment_mod (
		const uint32_t value,
		const uint8_t mod,
		const uint32_t min,
		const uint32_t max,
		const uint8_t position
);

#endif /* RRR_INCREMENT_H */
