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

#ifndef RRR_HTTP_HEADER_FIELDS_H
#define RRR_HTTP_HEADER_FIELDS_H

#include "http_fields.h"

#include "../rrr_types.h"
#include "../util/linked_list.h"
#include "../helpers/nullsafe_str.h"

#define RRR_HTTP_HEADER_FIELD_ALLOW_MULTIPLE     (1<<0)
#define RRR_HTTP_HEADER_FIELD_NO_PAIRS           (1<<1)
#define RRR_HTTP_HEADER_FIELD_ANGLED_QUOTE_NAME  (1<<2)
#define RRR_HTTP_HEADER_FIELD_TRIM               (1<<3)

struct rrr_http_header_field_definition;

struct rrr_http_header_field {
	RRR_LL_NODE(struct rrr_http_header_field);

	// This list is filled while parsing the header field
	struct rrr_http_field_collection fields;

	const struct rrr_http_header_field_definition *definition;

	struct rrr_nullsafe_str *name;

	// This is filled by known header field parsers. Pointer
	// must always be checked for NULL before usage, they are
	// only set for certain header field types.
	long long int value_signed;
	long long unsigned int value_unsigned;
	struct rrr_nullsafe_str *binary_value_nullsafe;
	struct rrr_nullsafe_str *value;
};

struct rrr_http_header_field_collection {
	RRR_LL_HEAD(struct rrr_http_header_field);
};

#define RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION \
		struct rrr_http_header_field *field

struct rrr_http_header_field_definition {
	const char *name_lowercase;
	int flags;
	int (*parse)(RRR_HTTP_HEADER_FIELD_PARSER_DEFINITION);
};

void rrr_http_header_field_destroy (
		struct rrr_http_header_field *field
);
void rrr_http_header_field_collection_clear (
		struct rrr_http_header_field_collection *collection
);
const struct rrr_http_header_field *rrr_http_header_field_collection_get (
		const struct rrr_http_header_field_collection *collection,
		const char *name
);
const struct rrr_http_header_field *rrr_http_header_field_collection_get_raw (
		const struct rrr_http_header_field_collection *collection,
		const char *name
);
const struct rrr_http_header_field *rrr_http_header_field_collection_get_with_value_case (
		const struct rrr_http_header_field_collection *collection,
		const char *name_lowercase,
		const char *value_anycase
);
int rrr_http_header_field_new_raw (
		struct rrr_http_header_field **result,
		const char *field_name,
		rrr_length field_name_len
);
int rrr_http_header_field_new_with_value (
		struct rrr_http_header_field **result,
		const char *name,
		const char *value
);
int rrr_http_header_field_new_with_value_nullsafe (
		struct rrr_http_header_field **result,
		const char *name,
		const struct rrr_nullsafe_str *value
);
int rrr_http_header_field_parse_value (
		struct rrr_http_header_field_collection *target_list,
		rrr_length *parsed_bytes,
		const char *name,
		const char *value
);
int rrr_http_header_field_parse_name_and_value (
		struct rrr_http_header_field_collection *target_list,
		rrr_length *parsed_bytes,
		const char *start_orig,
		const char *end
);

#endif /* RRR_HTTP_HEADER_FIELDS_H */
