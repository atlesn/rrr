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

#include "cmdlineparser/cmdline.h"
#include "messages.h"

#define RRR_TYPES_MAX_DEFINITIONS CMD_ARGUMENT_MAX

typedef uint8_t rrr_type;
typedef cmd_arg_size rrr_type_length;
typedef cmd_arg_size rrr_def_count;
typedef ssize_t rrr_size;
typedef uint64_t rrr_type_le;
typedef uint64_t rrr_type_be;

// Remember to update convert function pointers in types.c
// Highest possible ID is 255 (uint8_t)
#define RRR_TYPE_LE			1
#define RRR_TYPE_BE			2
#define RRR_TYPE_BLOB		3

#define RRR_TYPE_NAME_LE	"le"
#define RRR_TYPE_NAME_BE	"be"
#define RRR_TYPE_NAME_BLOB	"blob"

#define RRR_TYPE_MAX_LE		sizeof(rrr_type_le)
#define RRR_TYPE_MAX_BE		sizeof(rrr_type_be)
#define RRR_TYPE_MAX_BLOB	CMD_ARGUMENT_SIZE

struct rrr_type_definition {
	rrr_type		type;
	rrr_type_length	length;
	rrr_type_length max_length;
};

struct rrr_type_definition_collection {
	rrr_def_count count;
	struct rrr_type_definition definitions[RRR_TYPES_MAX_DEFINITIONS];
};

struct rrr_data_collection {
	struct rrr_type_definition_collection definitions;
	char *data[RRR_TYPES_MAX_DEFINITIONS];
};

//static int (*rrr_types_convert_functions[]) (char *target, const char *data, rrr_type_length length);

int rrr_types_parse_definition (
		struct rrr_type_definition_collection *target,
		struct cmd_data *cmd,
		const char *cmd_key
);

int rrr_types_parse_data (
		const char *data, const rrr_type_length length,
		struct rrr_data_collection *target
);
struct rrr_data_collection *rrr_types_allocate_data (
		const struct rrr_type_definition_collection *definitions
);

void rrr_types_destroy_data(struct rrr_data_collection *collection);

struct vl_message *rrr_types_create_message(const struct rrr_data_collection *data);

#endif /* RRR_TYPES_H */
