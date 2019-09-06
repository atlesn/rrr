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
#include "linked_list.h"

typedef uint8_t rrr_type;
typedef uint32_t rrr_type_length;
typedef uint32_t rrr_def_count;
typedef uint32_t rrr_array_size;
typedef uint32_t rrr_size;
typedef uint64_t rrr_type_le;
typedef uint64_t rrr_type_be;
typedef uint64_t rrr_type_h;
typedef uint64_t rrr_type_istr;
typedef uint64_t rrr_type_ustr;

static const union type_system_endian {
	uint16_t two;
	uint8_t one;
} type_system_endian = {0x1};

#define RRR_TYPE_SYSTEM_ENDIAN_IS_LE (type_system_endian.one == 1)
#define RRR_TYPE_SYSTEM_ENDIAN_IS_BE (type_system_endian.one == 0)

#define RRR_TYPE_VERSION 3

#define RRR_TYPE_PARSE_OK			0
#define RRR_TYPE_PARSE_ERR			1
#define RRR_TYPE_PARSE_INCOMPLETE	2

// Remember to update convert function pointers in types.c
// Highest possible ID is 255 (uint8_t)
#define RRR_TYPE_LE			1 // Little endian number
#define RRR_TYPE_BE			2 // Big endian number
#define RRR_TYPE_H			3 // Host endian number (can be both)
#define RRR_TYPE_BLOB		4
#define RRR_TYPE_USTR		5 // Unsigned int given as a string
#define RRR_TYPE_ISTR		6 // Signed int given as a string
#define RRR_TYPE_SEP		7 // Separator character ;,.-_*+\/=$@%#!|§ etc. No brackets.
#define RRR_TYPE_ARRAY		8 // Type which holds many of another type
#define RRR_TYPE_MAX		8

#define RRR_TYPE_NAME_LE	"le"
#define RRR_TYPE_NAME_BE	"be"
#define RRR_TYPE_NAME_H		"h"
#define RRR_TYPE_NAME_BLOB	"blob"
#define RRR_TYPE_NAME_USTR	"ustr"
#define RRR_TYPE_NAME_ISTR	"istr"
#define RRR_TYPE_NAME_SEP	"sep"
#define RRR_TYPE_NAME_ARRAY	"array" // Not an actual type, used to make other types arrays

#define RRR_TYPE_MAX_LE		sizeof(rrr_type_le)
#define RRR_TYPE_MAX_BE		sizeof(rrr_type_be)
#define RRR_TYPE_MAX_H		sizeof(rrr_type_h)
#define RRR_TYPE_MAX_BLOB	RRR_TYPE_MAX_BLOB_LENGTH
#define RRR_TYPE_MAX_USTR	0
#define RRR_TYPE_MAX_ISTR	0
#define RRR_TYPE_MAX_SEP	64
#define RRR_TYPE_MAX_ARRAY	65535

#define RRR_TYPE_IS_64(type) 	(														\
			(type) == RRR_TYPE_LE || (type) == RRR_TYPE_BE || (type) == RRR_TYPE_H ||	\
			(type) == RRR_TYPE_USTR || (type) == RRR_TYPE_ISTR							\
		)
#define RRR_TYPE_IS_BLOB(type)	((type) == RRR_TYPE_BLOB || RRR_TYPE_SEP)
#define RRR_TYPE_OK(type)		((type) > 0 && (type) <= RRR_TYPE_MAX)

#define RRR_TYPE_ENDIAN_BYTES	0x0102
#define RRR_TYPE_ENDIAN_LE		0x02
#define RRR_TYPE_ENDIAN_BE		0x01

#define RRR_TYPE_DEF_IS_LE(def)	((def)->endian_one == RRR_TYPE_ENDIAN_LE)
#define RRR_TYPE_DEF_IS_BE(def)	((def)->endian_one == RRR_TYPE_ENDIAN_BE)

struct rrr_type_template;

struct rrr_type_definition {
	rrr_type type;
	rrr_type_length max_length;
	int (*import)(
			struct rrr_type_template *node,
			ssize_t *parsed_bytes,
			const char *start,
			const char *end
	);
	int (*to_host)(
			struct rrr_type_template *node
	);
	const char *identifier;
};

struct rrr_type_template {
	RRR_LINKED_LIST_NODE(struct rrr_type_template);
	const struct rrr_type_definition *definition;
	rrr_type_length length;
	rrr_array_size array_size; // 1 = no array
	char *data;
};

struct rrr_type_data_packed {
	rrr_type type;
	rrr_type_length length;
	rrr_array_size array_size;
	char data[1];
} __attribute((packed));

/*
 * The collection header is always converted to host endianess. The endianess
 * of the data is not touched until extracted with extractor functions.-
 */
struct rrr_type_template_collection {
		RRR_LINKED_LIST_HEAD(struct rrr_type_template);
};
const struct rrr_type_definition *rrr_type_get_from_identifier (
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
);
const struct rrr_type_definition *rrr_type_get_from_type (uint8_t type_in);
int rrr_type_parse_definition (
		struct rrr_type_template_collection *target,
		struct rrr_instance_config *config,
		const char *cmd_key
);
int rrr_type_parse_data_from_definition (
		struct rrr_type_template_collection *target,
		const char *data,
		const rrr_type_length length
);
int rrr_type_definition_collection_clone (
		struct rrr_type_template_collection *target,
		const struct rrr_type_template_collection *source
);
void rrr_type_template_collection_clear (struct rrr_type_template_collection *collection);
struct rrr_type_template *rrr_type_template_collection_get_by_idx (
		struct rrr_type_template_collection *definition,
		int idx
);
int rrr_type_new_message (
		struct vl_message **final_message,
		const struct rrr_type_template_collection *definition,
		uint64_t time
);
int rrr_types_message_to_collection (
		struct rrr_type_template_collection *target,
		const struct vl_message *message_orig
);

#endif /* RRR_TYPES_H */
