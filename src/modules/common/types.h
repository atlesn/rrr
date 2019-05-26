/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_TYPES_H
#define RRR_TYPES_H

#include <stdint.h>

// Highest possible ID is 255 (uint8_t)
#define RRR_TYPE_LE			1
#define RRR_TYPE_BE			2
#define RRR_TYPE_BLOB		200

typedef uint8_t rrr_type;
typedef uint8_t rrr_type_length;

struct rrr_type_definition {
	rrr_type		type;
	rrr_type_length	length;
};

struct rrr_data_collection {
	unsigned int count;
	struct rrr_type_definition *definitions;
	char **data;
};

struct rrr_data_collection *rrr_types_parse_data (
		const char *data, const ssize_t length,
		const struct rrr_type_definition definitions[], const unsigned int definition_length
);

void rrr_types_destroy_data(struct rrr_data_collection *collection);

#endif /* RRR_TYPES_H */
