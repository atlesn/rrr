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

#ifndef RRR_HTTP_QUERY_BUILDER_H
#define RRR_HTTP_QUERY_BUILDER_H

struct rrr_string_builder;
struct rrr_map;
struct rrr_array;
struct rrr_type_value;

struct rrr_http_query_builder {
	struct rrr_string_builder *string_builder;
};

int rrr_http_query_builder_init (
		struct rrr_http_query_builder *query_builder
);
void rrr_http_query_builder_cleanup (
		struct rrr_http_query_builder *query_builder
);
int rrr_http_query_builder_append_type_value_as_escaped_string (
		struct rrr_http_query_builder *query_builder,
		const struct rrr_type_value *value,
		int do_quote_values
);
int rrr_http_query_builder_append_values_from_array (
		struct rrr_http_query_builder *query_builder,
		const struct rrr_array *array,
		const struct rrr_map *columns,
		const char *separator,
		int no_separator_on_first,
		int do_quote_values
);
int rrr_http_query_builder_append_values_from_map (
		struct rrr_http_query_builder *query_builder,
		struct rrr_map *columns,
		const char *separator,
		int no_separator_on_first
);
int rrr_http_query_builder_append_raw (
		struct rrr_http_query_builder *query_builder,
		const char *str
);
const char *rrr_http_query_builder_buf_get (
		struct rrr_http_query_builder *query_builder
);
ssize_t rrr_http_query_builder_wpos_get (
		struct rrr_http_query_builder *query_builder
);
void rrr_http_query_builder_buf_takeover (
		char **target,
		struct rrr_http_query_builder *query_builder
);

#endif /* RRR_HTTP_QUERY_BUILDER_H */
