/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include "rrr_types.h"
#include "util/linked_list.h"
#include "util/macro_utils.h"
#include "read_constants.h"

static const union type_system_endian {
	uint16_t two;
	uint8_t one;
} type_system_endian = {0x1};

#define RRR_TYPE_SYSTEM_ENDIAN_IS_LE (type_system_endian.one == 1)
#define RRR_TYPE_SYSTEM_ENDIAN_IS_BE (type_system_endian.one == 0)

#define RRR_TYPE_PARSE_OK			RRR_READ_OK
#define RRR_TYPE_PARSE_HARD_ERR		RRR_READ_HARD_ERROR
#define RRR_TYPE_PARSE_SOFT_ERR		RRR_READ_SOFT_ERROR
#define RRR_TYPE_PARSE_INCOMPLETE	RRR_READ_INCOMPLETE

// Remember to update convert function pointers in type.c
// Highest possible ID is 255 (uint8_t)
#define RRR_TYPE_MIN		2
#define RRR_TYPE_LE			2  // Little endian number
#define RRR_TYPE_BE			3  // Big endian number
#define RRR_TYPE_H			4  // Host endian number (can be both)
#define RRR_TYPE_BLOB		5  // Type which holds arbitary data
#define RRR_TYPE_USTR		6  // Unsigned int given as a string
#define RRR_TYPE_ISTR		7  // Signed int given as a string
#define RRR_TYPE_SEP		8  // Separator character ;,.-_*+\/=$@%#!|§ etc. No brackets.
#define RRR_TYPE_MSG		9  // Type which holds an RRR message
#define RRR_TYPE_FIXP		10 // Signed 64 type of which 24 bits are fraction given as string in base10 or base16
#define RRR_TYPE_STR		11 // Dynamic length string quoted with "
#define RRR_TYPE_NSEP		12 // Group of any byte not being a separator byte
#define RRR_TYPE_STX		13 // STX or SOH, start of transmission or start of header
#define RRR_TYPE_ERR		14 // Always produces soft error when being parsed, used to abort branched parsing
#define RRR_TYPE_MAX		14

#define RRR_TYPE_NAME_LE	"le"
#define RRR_TYPE_NAME_BE	"be"
#define RRR_TYPE_NAME_H		"h"
#define RRR_TYPE_NAME_BLOB	"blob"
#define RRR_TYPE_NAME_USTR	"ustr"
#define RRR_TYPE_NAME_ISTR	"istr"
#define RRR_TYPE_NAME_SEP	"sep"
#define RRR_TYPE_NAME_MSG	"msg"
#define RRR_TYPE_NAME_FIXP	"fixp"
#define RRR_TYPE_NAME_STR	"str"
#define RRR_TYPE_NAME_NSEP	"nsep"
#define RRR_TYPE_NAME_STX	"stx"
#define RRR_TYPE_NAME_ERR	"err"

#define RRR_TYPE_MAX_LE		sizeof(rrr_type_le)
#define RRR_TYPE_MAX_BE		sizeof(rrr_type_be)
#define RRR_TYPE_MAX_H		sizeof(rrr_type_h)
#define RRR_TYPE_MAX_BLOB	RRR_TYPE_MAX_BLOB_LENGTH
#define RRR_TYPE_MAX_USTR	0
#define RRR_TYPE_MAX_ISTR	0
#define RRR_TYPE_MAX_SEP	64
#define RRR_TYPE_MAX_MSG	0
#define RRR_TYPE_MAX_FIXP	0
#define RRR_TYPE_MAX_STR	0
#define RRR_TYPE_MAX_NSEP	0
#define RRR_TYPE_MAX_STX	64
#define RRR_TYPE_MAX_ERR	0

#define RRR_TYPE_IS_64(type) 	(														\
			(type) == RRR_TYPE_LE || (type) == RRR_TYPE_BE || (type) == RRR_TYPE_H ||	\
			(type) == RRR_TYPE_USTR || (type) == RRR_TYPE_ISTR							\
		)
#define RRR_TYPE_IS_BLOB(type)		((type) == RRR_TYPE_BLOB || (type) == RRR_TYPE_SEP || (type) == RRR_TYPE_MSG || (type) == RRR_TYPE_STR || (type) == RRR_TYPE_NSEP || (type) == RRR_TYPE_STX)
#define RRR_TYPE_IS_FIXP(type)		((type) == RRR_TYPE_FIXP)
#define RRR_TYPE_IS_MSG(type)		((type) == RRR_TYPE_MSG)
#define RRR_TYPE_IS_STR(type)		((type) == RRR_TYPE_STR || (type) == RRR_TYPE_SEP || (type) == RRR_TYPE_NSEP || (type) == RRR_TYPE_STX)
#define RRR_TYPE_IS_STR_EXCACT(type)((type) == RRR_TYPE_STR)
#define RRR_TYPE_IS_SEP(type)		((type) == RRR_TYPE_SEP)
#define RRR_TYPE_IS_NSEP(type)		((type) == RRR_TYPE_NSEP)
#define RRR_TYPE_IS_STX(type)		((type) == RRR_TYPE_STX)
#define RRR_TYPE_ALLOWS_SIGN(type)	((type) == RRR_TYPE_LE || (type) == RRR_TYPE_BE || (type) == RRR_TYPE_H)
#define RRR_TYPE_OK(type)			((type) >= RRR_TYPE_MIN && (type) <= RRR_TYPE_MAX)

#define RRR_TYPE_FLAG_SIGNED ((uint8_t) (1<<0))

#define RRR_TYPE_FLAG_IS_SIGNED(flags)		(((flags) & RRR_TYPE_FLAG_SIGNED) == 1)
#define RRR_TYPE_FLAG_IS_UNSIGNED(flags)	(((flags) & RRR_TYPE_FLAG_SIGNED) == 0)

#define RRR_TYPE_FLAG_SET_SIGNED(flags)		(flags) |= (RRR_TYPE_FLAG_SIGNED)
#define RRR_TYPE_FLAG_SET_UNSIGNED(flags)	(flags) &= (uint8_t) ~(RRR_TYPE_FLAG_SIGNED)

#define RRR_TYPE_CHAR_IS_STX(c) \
	(c >= 1 && c <= 2)     // SOH, STX

#define RRR_TYPE_CHAR_IS_SEP_A(c) \
	(c == '\n' || c == '\r' || c == '\t')
#define RRR_TYPE_CHAR_IS_SEP_B(c) \
	(c >= 33 && c <= 47)   // ! " # $ % & ' ( ) * + , - . /
#define RRR_TYPE_CHAR_IS_SEP_C(c) \
	(c >= 58 && c <= 64)   // : ; < = > ? @
#define RRR_TYPE_CHAR_IS_SEP_D(c) \
	(c >= 91 && c <= 96)   // [ \ ] ^ _ `
#define RRR_TYPE_CHAR_IS_SEP_E(c) \
	(c >= 123 && c <= 126) // { | } ~
#define RRR_TYPE_CHAR_IS_SEP_F(c) \
	(c == 0 || (c >= 3 &&c <= 4))     // NULL, ETX, EOT

#define RRR_TYPE_CHAR_IS_SEP(c) (		\
		RRR_TYPE_CHAR_IS_SEP_A(c)||		\
		RRR_TYPE_CHAR_IS_SEP_B(c)||		\
		RRR_TYPE_CHAR_IS_SEP_C(c)||		\
		RRR_TYPE_CHAR_IS_SEP_D(c)||		\
		RRR_TYPE_CHAR_IS_SEP_E(c)||		\
		RRR_TYPE_CHAR_IS_SEP_F(c)		\
	)

#define RRR_TYPE_GET_IMPORT_LENGTH_ARGS		\
		rrr_length *import_length,		\
		const struct rrr_type_value *node,	\
		const char *buf,					\
		rrr_length buf_size

#define RRR_TYPE_IMPORT_ARGS				\
		struct rrr_type_value *node,		\
		rrr_length *parsed_bytes,		\
		const char *start,					\
		const char *end

#define RRR_TYPE_GET_EXPORT_LENGTH_ARGS		\
		rrr_length *bytes,				\
		const struct rrr_type_value *node

#define RRR_TYPE_EXPORT_ARGS				\
		char *target,						\
		rrr_length *written_bytes,		\
		const struct rrr_type_value *node

#define RRR_TYPE_UNPACK_ARGS				\
		struct rrr_type_value *node

#define RRR_TYPE_PACK_ARGS					\
		char *target,						\
		rrr_length *written_bytes,		\
		uint8_t *new_type_id,				\
		const struct rrr_type_value *node

#define RRR_TYPE_TO_STR_ARGS				\
		char **target,						\
		const struct rrr_type_value *node

#define RRR_TYPE_TO_64_ARGS					\
		const struct rrr_type_value *node

struct rrr_type_value;

struct rrr_type_definition {
	rrr_type type;
	rrr_length max_length;

	// These are for importing or exporting to and from raw data
	// and rrr_array struct
	int (*import)(RRR_TYPE_IMPORT_ARGS);
	void (*get_export_length)(RRR_TYPE_GET_EXPORT_LENGTH_ARGS);
	int (*export)(RRR_TYPE_EXPORT_ARGS);

	// These are for converting between work-copy rrr_array struct
	// and RRR array message, with endian conversions
	int (*unpack)(RRR_TYPE_UNPACK_ARGS);
	int (*pack)(RRR_TYPE_PACK_ARGS);

	int (*to_str)(RRR_TYPE_TO_STR_ARGS);
	uint64_t (*to_64)(RRR_TYPE_TO_64_ARGS);
	const char *identifier;
};

struct rrr_type_value {
	RRR_LL_NODE(struct rrr_type_value);
	const struct rrr_type_definition *definition;
	rrr_type_flags flags;
	rrr_length tag_length;
	rrr_length import_length;
	char *import_length_ref;
	rrr_length total_stored_length;
	rrr_length element_count; // 1 = no array, 0 = auto
	char *element_count_ref;
	char *tag;
	char *data;
};

#define RRR_TYPE_DEFINE_EXTERN(name) \
	extern const struct rrr_type_definition RRR_PASTE(rrr_type_definition_,name)

RRR_TYPE_DEFINE_EXTERN(be);
RRR_TYPE_DEFINE_EXTERN(h);
RRR_TYPE_DEFINE_EXTERN(le);
RRR_TYPE_DEFINE_EXTERN(blob);
RRR_TYPE_DEFINE_EXTERN(ustr);
RRR_TYPE_DEFINE_EXTERN(istr);
RRR_TYPE_DEFINE_EXTERN(sep);
RRR_TYPE_DEFINE_EXTERN(msg);
RRR_TYPE_DEFINE_EXTERN(fixp);
RRR_TYPE_DEFINE_EXTERN(str);
RRR_TYPE_DEFINE_EXTERN(nsep);
RRR_TYPE_DEFINE_EXTERN(stx);
RRR_TYPE_DEFINE_EXTERN(null);

int rrr_type_import_ustr_raw (uint64_t *target, rrr_length *parsed_bytes, const char *start, const char *end);
int rrr_type_import_istr_raw (int64_t *target, rrr_length *parsed_bytes, const char *start, const char *end);

const struct rrr_type_definition *rrr_type_parse_from_string (
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
);
const struct rrr_type_definition *rrr_type_get_from_id (
		uint8_t type_in
);
void rrr_type_value_destroy (
		struct rrr_type_value *template
);
int rrr_type_value_set_tag (
		struct rrr_type_value *value,
		const char *tag,
		rrr_length tag_length
);
int rrr_type_value_new (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_flags flags,
		rrr_length tag_length,
		const char *tag,
		rrr_length import_length,
		char *import_length_ref,
		rrr_length element_count,
		const char *element_count_ref,
		rrr_length stored_length
);
int rrr_type_value_clone (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		int do_clone_data
);
rrr_length rrr_type_value_get_export_length (
		const struct rrr_type_value *value
);
int rrr_type_value_allocate_and_export (
		char **target,
		rrr_length *written_bytes,
		const struct rrr_type_value *node
);
int rrr_type_value_allocate_and_import_raw (
		struct rrr_type_value **result_value,
		const struct rrr_type_definition *definition,
		const char *data_start,
		const char *data_end,
		rrr_length tag_length,
		const char *tag,
		rrr_length import_length,
		rrr_length element_count
);

#endif /* RRR_TYPE_HEADER */
