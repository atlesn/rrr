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

#ifndef RRR_HTTP_FIELDS_H
#define RRR_HTTP_FIELDS_H

#include <stdio.h>

#include "../rrr_types.h"
#include "../util/linked_list.h"

struct rrr_nullsafe_str;

struct rrr_http_field {
	RRR_LL_NODE(struct rrr_http_field);
	struct rrr_nullsafe_str *name;
	struct rrr_nullsafe_str *content_type;
	struct rrr_nullsafe_str *value;
};

struct rrr_http_field_collection {
	RRR_LL_HEAD(struct rrr_http_field);
};

void rrr_http_field_destroy (
		struct rrr_http_field *field
);
int rrr_http_field_new_no_value_raw (
		struct rrr_http_field **target,
		const char *name,
		rrr_length name_length
);
int rrr_http_field_new_no_value (
		struct rrr_http_field **target,
		const struct rrr_nullsafe_str *nullsafe
);
int rrr_http_field_content_type_set (
		struct rrr_http_field *target,
		const struct rrr_nullsafe_str *content_type
);
int rrr_http_field_value_set (
		struct rrr_http_field *target,
		const char *value,
		rrr_length value_length
);
int rrr_http_field_collection_iterate_const (
		const struct rrr_http_field_collection *fields,
		int (*callback)(const struct rrr_http_field *field, void *callback_arg),
		void *callback_arg
);
void rrr_http_field_collection_dump (
		struct rrr_http_field_collection *fields
);
void rrr_http_field_collection_clear (
		struct rrr_http_field_collection *fields
);
int rrr_http_field_collection_add (
		struct rrr_http_field_collection *fields,
		const char *name,
		rrr_length name_length,
		const char *value,
		rrr_length value_length,
		const char *content_type,
		rrr_length content_type_length
);
rrr_length rrr_http_field_collection_get_total_length (
		struct rrr_http_field_collection *fields
);
int rrr_http_field_collection_to_urlencoded_form_data (
		struct rrr_nullsafe_str **target,
		struct rrr_http_field_collection *fields
);
int rrr_http_field_collection_to_raw_form_data (
		struct rrr_nullsafe_str **target,
		struct rrr_http_field_collection *fields
);

#endif /* RRR_HTTP_FIELDS_H */
