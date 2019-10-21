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

#ifndef RRR_HTTP_FIELDS_H
#define RRR_HTTP_FIELDS_H

#include "linked_list.h"

struct rrr_http_field {
	RRR_LL_NODE(struct rrr_http_field);
	char *name;
	char *value;
	int is_binary;
};

struct rrr_http_field_collection {
	RRR_LL_HEAD(struct rrr_http_field);
};

void rrr_http_fields_collection_clear (struct rrr_http_field_collection *fields);
int rrr_http_fields_collection_add_field (
		struct rrr_http_field_collection *fields,
		const char *name,
		const char *value
);
int rrr_http_fields_collection_add_field_binary (
		struct rrr_http_field_collection *fields,
		const char *name,
		void *value,
		ssize_t size
);
int rrr_http_fields_get_total_length (
		struct rrr_http_field_collection *fields
);
char *rrr_http_fields_to_urlencoded_form_data (
		struct rrr_http_field_collection *fields
);
char *rrr_http_fields_to_raw_form_data (
		struct rrr_http_field_collection *fields
);

#endif /* RRR_HTTP_FIELDS_H */
