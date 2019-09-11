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

#ifndef RRR_TYPE_HEADER
#define RRR_TYPE_HEADER

#include <stdint.h>

#include "linked_list.h"

typedef uint8_t rrr_type;
typedef uint32_t rrr_type_length;
typedef uint32_t rrr_def_count;
typedef uint32_t rrr_type_array_size;
typedef uint32_t rrr_size;
typedef uint64_t rrr_type_le;
typedef uint64_t rrr_type_be;
typedef uint64_t rrr_type_h;
typedef uint64_t rrr_type_istr;
typedef uint64_t rrr_type_ustr;

struct rrr_type_value;

struct rrr_type_definition {
	rrr_type type;
	rrr_type_length max_length;
	int (*import)(
			struct rrr_type_value *node,
			ssize_t *parsed_bytes,
			const char *start,
			const char *end
	);
	int (*to_host)(
			struct rrr_type_value *node
	);
	const char *identifier;
};

struct rrr_type_value {
	RRR_LINKED_LIST_NODE(struct rrr_type_value);
	const struct rrr_type_definition *definition;
	rrr_type_length length;
	rrr_type_array_size array_size; // 1 = no array
	char *data;
};

static const union type_system_endian {
	uint16_t two;
	uint8_t one;
} type_system_endian = {0x1};

#define RRR_TYPE_SYSTEM_ENDIAN_IS_LE (type_system_endian.one == 1)
#define RRR_TYPE_SYSTEM_ENDIAN_IS_BE (type_system_endian.one == 0)

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
#define RRR_TYPE_IS_BLOB(type)	((type) == RRR_TYPE_BLOB || (type) ==  RRR_TYPE_SEP)
#define RRR_TYPE_OK(type)		((type) > 0 && (type) <= RRR_TYPE_MAX)

const struct rrr_type_definition *rrr_type_parse_from_string (
		ssize_t *parsed_bytes,
		const char *start,
		const char *end
);
const struct rrr_type_definition *rrr_type_get_from_id (
		uint8_t type_in
);
void rrr_type_value_destroy (
		struct rrr_type_value *template
);
int rrr_type_value_new (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_length length,
		rrr_type_array_size array_size
);

#endif /* RRR_TYPE_HEADER */
