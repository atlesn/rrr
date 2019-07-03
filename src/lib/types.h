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
#include "instance_config.h"

typedef uint8_t rrr_type;
typedef uint32_t rrr_type_length;
typedef uint32_t rrr_def_count;
typedef uint32_t rrr_array_size;
typedef ssize_t rrr_size;
typedef uint64_t rrr_type_le;
typedef uint64_t rrr_type_be;
typedef uint16_t rrr_version;

#define RRR_VERSION 1

// Remember to update convert function pointers in types.c
// Highest possible ID is 255 (uint8_t)
#define RRR_TYPE_LE			1
#define RRR_TYPE_BE			2
#define RRR_TYPE_BLOB		3
#define RRR_TYPE_MAX		3

#define RRR_TYPE_NAME_LE	"le"
#define RRR_TYPE_NAME_BE	"be"
#define RRR_TYPE_NAME_BLOB	"blob"
#define RRR_TYPE_NAME_ARRAY	"array" // Not an actual type, used to make other types arrays

#define RRR_TYPE_MAX_LE		sizeof(rrr_type_le)
#define RRR_TYPE_MAX_BE		sizeof(rrr_type_be)
#define RRR_TYPE_MAX_BLOB	RRR_TYPE_MAX_BLOB_LENGTH
#define RRR_TYPE_MAX_ARRAY	65535

#define RRR_TYPE_IS_64(type) 	(type == RRR_TYPE_LE || type == RRR_TYPE_BE)
#define RRR_TYPE_IS_BLOB(type)	(type == RRR_TYPE_BLOB)
#define RRR_TYPE_OK(type)		(type > 0 && type <= RRR_TYPE_MAX)

#define RRR_TYPE_ENDIAN_BYTES	0x0102
#define RRR_TYPE_ENDIAN_LE		0x02
#define RRR_TYPE_ENDIAN_BE		0x01

#define RRR_TYPE_DEF_IS_LE(def)	(def->endian_one == RRR_TYPE_ENDIAN_LE)
#define RRR_TYPE_DEF_IS_BE(def)	(def->endian_one == RRR_TYPE_ENDIAN_BE)

struct rrr_type_definition {
	rrr_type		type;
	rrr_type_length		length;
	rrr_type_length 	max_length;
	rrr_array_size		array_size; // 1 = no array
};

/*
 * The collection header is always converted to host endianess. The endianess
 * of the data is not touched until extracted with extractor functions.-
 */
struct rrr_type_definition_collection {
	rrr_version version;
	rrr_def_count count;
	union {
		uint16_t endian_two;
		uint8_t endian_one;
	};
	struct rrr_type_definition definitions[RRR_TYPE_MAX_DEFINITIONS];
};

struct rrr_data_collection {
	struct rrr_type_definition_collection definitions;
	char *data[RRR_TYPE_MAX_DEFINITIONS];
};

//static int (*rrr_types_convert_functions[]) (char *target, const char *data, rrr_type_length length);

int rrr_types_parse_definition (
		struct rrr_type_definition_collection *target,
		struct rrr_instance_config *config,
		const char *cmd_key
);

int rrr_types_parse_data (
		struct rrr_data_collection *target,
		const char *data, const rrr_type_length length
);
struct rrr_data_collection *rrr_types_allocate_data (
		const struct rrr_type_definition_collection *definitions
);

void rrr_types_destroy_data(struct rrr_data_collection *collection);

struct vl_message *rrr_types_create_message(const struct rrr_data_collection *data, uint64_t time);

int rrr_types_message_to_collection(struct rrr_data_collection **target, const struct vl_message *message_orig);
int rrr_types_definition_to_host(struct rrr_type_definition_collection *definition);

int rrr_types_extract_blob (char **target, rrr_size *size, const struct rrr_data_collection *collection, rrr_def_count pos, rrr_def_count array_pos, int do_zero_terminate);
int rrr_types_extract_host_64 (uint64_t *target, const struct rrr_data_collection *collection, rrr_def_count pos, rrr_def_count array_pos);

int rrr_types_extract_raw_from_collection_static(char *target, rrr_size target_size, rrr_size *return_size, const struct rrr_data_collection *data);
int rrr_types_extract_raw_from_collection(char **target, rrr_size *size, const struct rrr_data_collection *data);


rrr_type_length rrr_get_total_integer_max_length(const struct rrr_data_collection *data);
rrr_type_length rrr_get_total_blob_length(const struct rrr_data_collection *data);
rrr_type_length rrr_get_raw_length(const struct rrr_data_collection *data);

#endif /* RRR_TYPES_H */
