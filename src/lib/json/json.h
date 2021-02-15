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

#ifndef RRR_JSON_H
#define RRR_JSON_H

#include "../read_constants.h"

#define RRR_JSON_OK                RRR_READ_OK
#define RRR_JSON_HARD_ERROR        RRR_READ_HARD_ERROR
#define RRR_JSON_PARSE_ERROR       RRR_READ_SOFT_ERROR
#define RRR_JSON_PARSE_INCOMPLETE  RRR_READ_INCOMPLETE

struct rrr_map;
struct rrr_array;

int rrr_json_to_arrays (
		const char *data,
		size_t data_size,
		const int max_levels,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
);
int rrr_json_from_array (
		char **target,
		int *found_tags,
		const struct rrr_array *source,
		const struct rrr_map *tags
);

#endif /* RRR_JSON_H */
