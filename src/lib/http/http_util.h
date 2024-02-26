/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_UTIL_H
#define RRR_HTTP_UTIL_H

#include <stdint.h>
#include <stdio.h>

#include "http_common.h"
#include "../rrr_types.h"
#include "../util/linked_list.h"

#define RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,source) \
	char name[256]; rrr_nullsafe_str_output_strip_null_append_null_trim(source, name, sizeof(name))

#define RRR_HTTP_UTIL_SET_TMP_NAME_FROM_STR_AND_LENGTH(name,str,len) \
	char name[256]; rrr_nullsafe_str_util_output_strip_null_append_null_trim_raw_null_ok(name, sizeof(name), str, len)

#ifdef RRR_WITH_ZLIB
#	define RRR_HTTP_UTIL_WITH_ENCODING
#endif

struct rrr_array;
struct rrr_nullsafe_str;
struct rrr_string_builder;

struct rrr_http_uri_flags {
	uint8_t is_http;
	uint8_t is_websocket;
	uint8_t is_tls;
	uint8_t is_quic;
};

struct rrr_http_uri {
	char *protocol;
	char *host;
	uint16_t port;
	char *endpoint;
};

void rrr_http_util_print_where_message (
		const char *start,
		const char *end
);
int rrr_http_util_urlencoded_string_decode (
		struct rrr_nullsafe_str *str
);
int rrr_http_util_uri_encode (
		struct rrr_nullsafe_str **target,
		const struct rrr_nullsafe_str *str
);
int rrr_http_util_unquote_string (
		struct rrr_nullsafe_str *str
);
char *rrr_http_util_header_value_quote (
		const char *input,
		rrr_length length,
		char delimeter_start,
		char delimeter_end
);
char *rrr_http_util_header_value_quote_nullsafe (
		const struct rrr_nullsafe_str *str,
		char delimeter_start,
		char delimeter_end
);
const char *rrr_http_util_find_crlf (
		const char *start,
		const char *end
);
const char *rrr_http_util_find_whsp (
		const char *start,
		const char *end
);
int rrr_http_util_strtoull_raw (
		unsigned long long int *result,
		rrr_length *result_len,
		const char *start,
		const char *end,
		int base
);
int rrr_http_util_strtoull (
		unsigned long long int *result,
		const struct rrr_nullsafe_str *nullsafe,
		int base
);
int rrr_http_util_strcasestr (
		const char **result_start,
		rrr_length *result_len,
		const char *start,
		const char *end,
		const char *needle
);
const char *rrr_http_util_strchr (
		const char *start,
		const char *end,
		char chr
);
rrr_length rrr_http_util_count_whsp (
		const char *start,
		const char *end
);
void rrr_http_util_uri_clear (
		struct rrr_http_uri *uri
);
void rrr_http_util_uri_destroy (
		struct rrr_http_uri *uri
);
void rrr_http_util_uri_flags_get (
		struct rrr_http_uri_flags *target,
		const struct rrr_http_uri *uri
);
int rrr_http_util_uri_endpoint_prepend (
		struct rrr_http_uri *uri,
		const char *prefix
);
int rrr_http_util_uri_parse (
		struct rrr_http_uri **uri_result,
		const struct rrr_nullsafe_str *str
);
int rrr_http_util_uri_host_parse (
		struct rrr_http_uri *uri_result,
		const struct rrr_nullsafe_str *str
);
int rrr_http_util_uri_validate_characters (
		unsigned char *invalid,
		const char *str
);
void rrr_http_util_nprintf (
		rrr_length length,
		const char *format,
		...
);
void rrr_http_util_dbl_ptr_free (
		void *ptr
);
enum rrr_http_method rrr_http_util_method_str_to_enum (
		const char *method_str
);
enum rrr_http_body_format rrr_http_util_format_str_to_enum (
		const char *format_str
);
const char *rrr_http_util_iana_response_phrase_from_status_code (
		unsigned int status_code
);
#ifdef RRR_WITH_JSONC
int rrr_http_util_json_to_arrays (
		const char *data,
		rrr_length data_size,
		int (*callback)(const struct rrr_array *array, void *arg),
		void *callback_arg
);
#endif
#ifdef RRR_HTTP_UTIL_WITH_ENCODING
int rrr_http_util_encode (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input,
		const char *encoding
);
int rrr_http_util_decode (
		struct rrr_nullsafe_str *output,
		const struct rrr_nullsafe_str *input,
		const struct rrr_nullsafe_str *encoding
);
const char *rrr_http_util_encodings_get (void);
#endif
int rrr_http_util_alpn_iterate (
		const char * const alpn,
		unsigned int length,
		int (*callback)(unsigned int i, const char *alpn, unsigned char length, void *arg),
		void *callback_arg
);
int rrr_http_util_make_alt_svc_header (
		struct rrr_string_builder *target,
		uint16_t tls_port,
		uint16_t quic_port
);

#endif /* RRR_HTTP_UTIL_H */
