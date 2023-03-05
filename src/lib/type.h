/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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
#include <string.h>

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

#define RRR_TYPE_PARSE_OK          RRR_READ_OK
#define RRR_TYPE_PARSE_HARD_ERR    RRR_READ_HARD_ERROR
#define RRR_TYPE_PARSE_SOFT_ERR    RRR_READ_SOFT_ERROR
#define RRR_TYPE_PARSE_INCOMPLETE  RRR_READ_INCOMPLETE

// Remember to update convert function pointers in type.c
// Highest possible ID is 255 (uint8_t)
enum rrr_type_enum {
	RRR_TYPE_MIN  = 2,
	RRR_TYPE_LE   = 2,  // Little endian number
	RRR_TYPE_BE   = 3,  // Big endian number
	RRR_TYPE_H    = 4,  // Host endian number (can be both)
	RRR_TYPE_BLOB = 5,  // Type which holds arbitary data
	RRR_TYPE_USTR = 6,  // Unsigned int given as a string
	RRR_TYPE_ISTR = 7,  // Signed int given as a string
	RRR_TYPE_SEP  = 8,  // Separator character ;,.-_*+\/=$@%#!|§ etc. No brackets.
	RRR_TYPE_MSG  = 9,  // Type which holds an RRR message
	RRR_TYPE_FIXP = 10, // Signed 64 type of which 24 bits are fraction given as string in base10 or base16
	RRR_TYPE_STR  = 11, // Dynamic length string quoted with "
	RRR_TYPE_HEX  = 11, // Alias for RRR_TYPE_STR, used when converting blobs to ascii hex
	RRR_TYPE_NSEP = 12, // Group of any byte not being a separator byte
	RRR_TYPE_STX  = 13, // STX or SOH, start of transmission or start of header
	RRR_TYPE_ERR  = 14, // Always produces soft error when being parsed, used to abort branched parsing
	RRR_TYPE_VAIN = 15, // The useless type, indicates NULL or void. Will parse 0 bytes.
	RRR_TYPE_HDLC = 16, // HDLC frame delimited with 0x7e at the beginning and end
	RRR_TYPE_MAX  = 16
};

#define RRR_TYPE_NAME_LE    "le"
#define RRR_TYPE_NAME_BE    "be"
#define RRR_TYPE_NAME_H     "h"
#define RRR_TYPE_NAME_BLOB  "blob"
#define RRR_TYPE_NAME_USTR  "ustr"
#define RRR_TYPE_NAME_ISTR  "istr"
#define RRR_TYPE_NAME_SEP   "sep"
#define RRR_TYPE_NAME_MSG   "msg"
#define RRR_TYPE_NAME_FIXP  "fixp"
#define RRR_TYPE_NAME_STR   "str"
#define RRR_TYPE_NAME_NSEP  "nsep"
#define RRR_TYPE_NAME_STX   "stx"
#define RRR_TYPE_NAME_ERR   "err"
#define RRR_TYPE_NAME_VAIN  "vain"
#define RRR_TYPE_NAME_HDLC  "hdlc"

// Alias for string
#define RRR_TYPE_NAME_HEX   "hex"

#define RRR_TYPE_MAX_LE     sizeof(rrr_type_le)
#define RRR_TYPE_MAX_BE     sizeof(rrr_type_be)
#define RRR_TYPE_MAX_H      sizeof(rrr_type_h)
#define RRR_TYPE_MAX_BLOB   RRR_TYPE_MAX_BLOB_LENGTH
#define RRR_TYPE_MAX_USTR   0
#define RRR_TYPE_MAX_ISTR   0
#define RRR_TYPE_MAX_SEP   64
#define RRR_TYPE_MAX_MSG    0
#define RRR_TYPE_MAX_FIXP   0
#define RRR_TYPE_MAX_STR    0
#define RRR_TYPE_MAX_NSEP   0
#define RRR_TYPE_MAX_STX   64
#define RRR_TYPE_MAX_ERR    0
#define RRR_TYPE_MAX_VAIN   0
#define RRR_TYPE_MAX_HDLC   0

#define RRR_TYPE_IS_64(type)  (                                                             \
  (type) == RRR_TYPE_LE || (type) == RRR_TYPE_BE || (type) == RRR_TYPE_H ||                 \
  (type) == RRR_TYPE_USTR || (type) == RRR_TYPE_ISTR)
#define RRR_TYPE_IS_BLOB(type)        ((type) == RRR_TYPE_BLOB || (type) == RRR_TYPE_SEP || \
                                       (type) == RRR_TYPE_MSG  || (type) == RRR_TYPE_STR || \
				       (type) == RRR_TYPE_NSEP || (type) == RRR_TYPE_STX || \
				       (type) == RRR_TYPE_HDLC)

#define RRR_TYPE_IS_BLOB_EXCACT(type) ((type) == RRR_TYPE_BLOB)
#define RRR_TYPE_IS_FIXP(type)        ((type) == RRR_TYPE_FIXP)
#define RRR_TYPE_IS_MSG(type)         ((type) == RRR_TYPE_MSG)
#define RRR_TYPE_IS_STR(type)         ((type) == RRR_TYPE_STR || (type) == RRR_TYPE_SEP ||  \
                                       (type) == RRR_TYPE_NSEP || (type) == RRR_TYPE_STX)
#define RRR_TYPE_CASE_STR             case RRR_TYPE_STR: case RRR_TYPE_SEP: case RRR_TYPE_NSEP: case RRR_TYPE_STX
#define RRR_TYPE_IS_STR_EXCACT(type)  ((type) == RRR_TYPE_STR)
#define RRR_TYPE_IS_SEP(type)         ((type) == RRR_TYPE_SEP)
#define RRR_TYPE_IS_NSEP(type)        ((type) == RRR_TYPE_NSEP)
#define RRR_TYPE_IS_STX(type)         ((type) == RRR_TYPE_STX)
#define RRR_TYPE_IS_VAIN(type)        ((type) == RRR_TYPE_VAIN)
#define RRR_TYPE_IS_HDLC(type)        ((type) == RRR_TYPE_HDLC)
#define RRR_TYPE_ALLOWS_SIGN(type)    ((type) == RRR_TYPE_LE || (type) == RRR_TYPE_BE || (type) == RRR_TYPE_H)
#define RRR_TYPE_OK(type)             ((type) >= RRR_TYPE_MIN && (type) <= RRR_TYPE_MAX)

#define RRR_TYPE_FLAG_SIGNED ((uint8_t) (1<<0))

#define RRR_TYPE_FLAG_IS_SIGNED(flags)     (((flags) & RRR_TYPE_FLAG_SIGNED) == 1)
#define RRR_TYPE_FLAG_IS_UNSIGNED(flags)   (((flags) & RRR_TYPE_FLAG_SIGNED) == 0)

#define RRR_TYPE_FLAG_SET_SIGNED(flags)    (flags) |= (RRR_TYPE_FLAG_SIGNED)
#define RRR_TYPE_FLAG_SET_UNSIGNED(flags)  (flags) &= (uint8_t) ~(RRR_TYPE_FLAG_SIGNED)

#define RRR_TYPE_CHAR_IS_STX(c)                                \
	(c >= 1 && c <= 2)                     // SOH, STX

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
	(c == 0 || (c >= 3 &&c <= 4))   // NULL, ETX, EOT

#define RRR_TYPE_CHAR_IS_SEP(c) (                              \
        RRR_TYPE_CHAR_IS_SEP_A(c) ||                           \
        RRR_TYPE_CHAR_IS_SEP_B(c) ||                           \
        RRR_TYPE_CHAR_IS_SEP_C(c) ||                           \
        RRR_TYPE_CHAR_IS_SEP_D(c) ||                           \
        RRR_TYPE_CHAR_IS_SEP_E(c) ||                           \
        RRR_TYPE_CHAR_IS_SEP_F(c))

#define RRR_TYPE_GET_IMPORT_LENGTH_ARGS                        \
        rrr_length *import_length,                             \
        const struct rrr_type_value *node,                     \
        const char *buf,                                       \
        rrr_length buf_size

#define RRR_TYPE_IMPORT_ARGS                                   \
        struct rrr_type_value *node,                           \
        rrr_length *parsed_bytes,                              \
        const char *start,                                     \
        const char *end

#define RRR_TYPE_GET_EXPORT_LENGTH_ARGS                        \
        rrr_length *bytes,                                     \
        const struct rrr_type_value *node

#define RRR_TYPE_EXPORT_ARGS                                   \
        char *target,                                          \
        rrr_length *written_bytes,                             \
        const struct rrr_type_value *node

#define RRR_TYPE_UNPACK_ARGS                                   \
        struct rrr_type_value *node

#define RRR_TYPE_PACK_ARGS                                     \
        char *target,                                          \
        rrr_length *written_bytes,                             \
        uint8_t *new_type_id,                                  \
        const struct rrr_type_value *node

#define RRR_TYPE_TO_STR_ARGS                                   \
        char **target,                                         \
        const struct rrr_type_value *node

#define RRR_TYPE_TO_64_ARGS                                    \
        const struct rrr_type_value *node

#define RRR_TYPE_TO_ULL_ARGS                                   \
        const struct rrr_type_value *node

struct rrr_type_value;

struct rrr_type_definition {
	rrr_type type;
	rrr_length max_length;

	// These are for importing or exporting to and from raw data
	// and rrr_array struct
	int (*do_import)(RRR_TYPE_IMPORT_ARGS);
	int (*get_export_length)(RRR_TYPE_GET_EXPORT_LENGTH_ARGS);
	int (*do_export)(RRR_TYPE_EXPORT_ARGS);

	// These are for converting between work-copy rrr_array struct
	// and RRR array message, with endian conversions
	int (*unpack)(RRR_TYPE_UNPACK_ARGS);
	int (*pack)(RRR_TYPE_PACK_ARGS);

	int (*to_str)(RRR_TYPE_TO_STR_ARGS);
	uint64_t (*to_64)(RRR_TYPE_TO_64_ARGS);
	unsigned long long (*to_ull)(RRR_TYPE_TO_ULL_ARGS);
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

#define RRR_TYPE_TAG_MAX RRR_LENGTH_MAX

#define RRR_TYPE_DECLARE_EXTERN(name) \
	extern const struct rrr_type_definition RRR_PASTE(rrr_type_definition_,name)

#define RRR_TYPE_RAW_FIELDS                            \
	const char *data_start,                        \
	const struct rrr_type_definition *type,        \
	rrr_type_flags flags,                          \
	rrr_length tag_length,                         \
	rrr_length total_length,                       \
	rrr_length element_count

RRR_TYPE_DECLARE_EXTERN(be);
RRR_TYPE_DECLARE_EXTERN(h);
RRR_TYPE_DECLARE_EXTERN(le);
RRR_TYPE_DECLARE_EXTERN(blob);
RRR_TYPE_DECLARE_EXTERN(ustr);
RRR_TYPE_DECLARE_EXTERN(istr);
RRR_TYPE_DECLARE_EXTERN(sep);
RRR_TYPE_DECLARE_EXTERN(msg);
RRR_TYPE_DECLARE_EXTERN(fixp);
RRR_TYPE_DECLARE_EXTERN(str);
RRR_TYPE_DECLARE_EXTERN(nsep);
RRR_TYPE_DECLARE_EXTERN(stx);
RRR_TYPE_DECLARE_EXTERN(err);
RRR_TYPE_DECLARE_EXTERN(vain);
RRR_TYPE_DECLARE_EXTERN(hdlc);
RRR_TYPE_DECLARE_EXTERN(null);

#define RRR_TYPE_DEFINITION_BE     rrr_type_definition_be
#define RRR_TYPE_DEFINITION_H      rrr_type_definition_h
#define RRR_TYPE_DEFINITION_LE     rrr_type_definition_le
#define RRR_TYPE_DEFINITION_BLOB   rrr_type_definition_blob
#define RRR_TYPE_DEFINITION_USTR   rrr_type_definition_ustr
#define RRR_TYPE_DEFINITION_ISTR   rrr_type_definition_istr
#define RRR_TYPE_DEFINITION_SEP    rrr_type_definition_sep
#define RRR_TYPE_DEFINITION_MSG    rrr_type_definition_msg
#define RRR_TYPE_DEFINITION_FIXP   rrr_type_definition_fixp
#define RRR_TYPE_DEFINITION_STR    rrr_type_definition_str
#define RRR_TYPE_DEFINITION_HEX    RRR_TYPE_DEFINITION_STR
#define RRR_TYPE_DEFINITION_NSEP   rrr_type_definition_nsep
#define RRR_TYPE_DEFINITION_STX    rrr_type_definition_stx
#define RRR_TYPE_DEFINITION_ERR    rrr_type_definition_err
#define RRR_TYPE_DEFINITION_VAIN   rrr_type_definition_vain
#define RRR_TYPE_DEFINITION_HDLC   rrr_type_definition_hdlc
#define RRR_TYPE_DEFINITION_NULL   rrr_type_definition_null

static inline int rrr_type_value_is_tag (
		const struct rrr_type_value *value,
		const char *tag
) {
	// When comparing tags, NULL and empty
	// strings are equivalent.

	const char *a = value->tag;
	const char *b = tag;

	int a_empty = a == NULL || *a == '\0';
	int b_empty = b == NULL || *b == '\0';

	if (a_empty || b_empty) {
		if (a_empty && b_empty) {
			return 1;
		}
	}
	else {
		if (strcmp(a, b) == 0) {
			return 1;
		}
	}

	return 0;
}

static inline rrr_biglength rrr_type_value_get_allocated_size (
		const struct rrr_type_value *value
) {
	rrr_biglength acc = 0;
	acc += sizeof(*value);
	acc += value->total_stored_length;
	acc += value->tag_length;
	return acc;
}

int rrr_type_import_ustr_raw (
		uint64_t *target,
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
);
int rrr_type_import_istr_raw (
		int64_t *target,
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
);
const struct rrr_type_definition *rrr_type_parse_from_string (
		rrr_length *parsed_bytes,
		const char *start,
		const char *end
);
const struct rrr_type_definition *rrr_type_get_from_id (
		const uint8_t type_in
);
void rrr_type_value_destroy (
		struct rrr_type_value *template_
);
int rrr_type_value_set_tag (
		struct rrr_type_value *value,
		const char *tag,
		rrr_length tag_length
);
void rrr_type_value_set_data (
		struct rrr_type_value *value,
		char *data,
		rrr_length data_length
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
int rrr_type_value_new_and_unpack (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		const char *data_start,
		rrr_type_flags flags,
		rrr_length tag_length,
		rrr_length total_length,
		rrr_length element_count
);
int rrr_type_value_new_simple (
		struct rrr_type_value **result,
		const struct rrr_type_definition *type,
		rrr_type_flags flags,
		rrr_length tag_length,
		const char *tag
);
int rrr_type_new_vain (
		struct rrr_type_value **target,
		rrr_length tag_length,
		const char *tag
);
int rrr_type_new_h (
		struct rrr_type_value **target,
		rrr_length tag_length,
		const char *tag,
		rrr_length element_count
);
int rrr_type_value_clone (
		struct rrr_type_value **target,
		const struct rrr_type_value *source,
		int do_clone_data
);
int rrr_type_value_get_export_length (
		rrr_length *result,
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
int rrr_type_value_with_tmp_do (
		RRR_TYPE_RAW_FIELDS,
		int (*callback)(const struct rrr_type_value *value, void *arg),
		void *callback_arg
);

#endif /* RRR_TYPE_HEADER */
