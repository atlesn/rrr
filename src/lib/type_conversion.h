/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_TYPE_CONVERSION_H
#define RRR_TYPE_CONVERSION_H

#include <stdint.h>

#include "read_constants.h"

#define RRR_TYPE_CONVERSION_OK				RRR_READ_OK
#define RRR_TYPE_CONVERSION_HARD_ERROR		RRR_READ_HARD_ERROR
#define RRR_TYPE_CONVERSION_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_TYPE_CONVERSION_NOT_POSSIBLE	RRR_READ_INCOMPLETE

struct rrr_map;
struct rrr_type_conversion_collection;

void rrr_type_conversion_collection_destroy (
		struct rrr_type_conversion_collection *target
);
int rrr_type_conversion_collection_new_from_map (
		struct rrr_type_conversion_collection **target,
		const struct rrr_map *map
);

#endif /* RRR_TYPE_CONVERSION_H */
