/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_TRANSACTION_H
#define RRR_HTTP_TRANSACTION_H

#include <stdint.h>
#include <stdio.h>

#include "http_common.h"
#include "../type.h"

struct rrr_http_part;
struct rrr_http_header_field;

struct rrr_http_transaction {
	int usercount;

	enum rrr_http_method method;
	char *endpoint_str;

	enum rrr_http_body_format request_body_format;

	struct rrr_nullsafe_str *read_body;
	struct rrr_nullsafe_str *send_body;
	rrr_biglength send_body_pos;

	struct rrr_http_part *request_part;
	struct rrr_http_part *response_part;

	rrr_biglength remaining_redirects;

	// Managed data for downstream server/client
	void *application_data;
	void (*application_data_destroy)(void *arg);

	// Unmanaged data for HTTP protocol layer
	void *protocol_ptr;
	int protocol_int;

	rrr_http_unique_id unique_id;

	int need_response;

	int stream_flags;

	// Helper values for use in callbacks
	enum rrr_http_transport transport_code;
	enum rrr_http_application_type application_type;

	uint64_t creation_time;
};

uint64_t rrr_http_transaction_lifetime_get (
		const struct rrr_http_transaction *transaction
);
int rrr_http_transaction_new (
		struct rrr_http_transaction **target,
		enum rrr_http_method method,
		enum rrr_http_body_format body_format,
		rrr_biglength remaining_redirects,
		int (*unique_id_generator_callback)(RRR_HTTP_COMMON_UNIQUE_ID_GENERATOR_CALLBACK_ARGS),
		void *unique_id_generator_callback_arg,
		void **application_data,
		void (*application_data_destroy)(void *arg)
);
void rrr_http_transaction_application_data_set (
		struct rrr_http_transaction *transaction,
		void **application_data,
		void (*application_data_destroy)(void *arg)
);
void rrr_http_transaction_protocol_data_set (
		struct rrr_http_transaction *transaction,
		void *protocol_ptr,
		int protocol_int
);
int rrr_http_transaction_response_reset (
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_request_reset (
		struct rrr_http_transaction *transaction
);
void rrr_http_transaction_decref_if_not_null (
		struct rrr_http_transaction *transaction
);
void rrr_http_transaction_decref_if_not_null_void (
		void *transaction
);
void rrr_http_transaction_incref (
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_query_field_add (
		struct rrr_http_transaction *transaction,
		const char *name,
		const char *value,
		rrr_length value_size,
		const char *content_type,
		const struct rrr_type_value *value_orig
);
void rrr_http_transaction_query_fields_dump (
		struct rrr_http_transaction *transaction
);
void rrr_http_transaction_method_set (
		struct rrr_http_transaction *transaction,
		enum rrr_http_method method
);
int rrr_http_transaction_endpoint_set (
		struct rrr_http_transaction *transaction,
		const char *endpoint
);
void rrr_http_transaction_request_body_format_set (
		struct rrr_http_transaction *transaction,
		enum rrr_http_body_format body_format
);
int rrr_http_transaction_request_content_type_set (
		struct rrr_http_transaction *transaction,
		const char *content_type
);
int rrr_http_transaction_request_accept_encoding_set (
		struct rrr_http_transaction *transaction,
		const char *accept_encoding
);
int rrr_http_transaction_request_content_type_directive_set (
		struct rrr_http_transaction *transaction,
		const char *name,
		const char *value
);
int rrr_http_transaction_response_alt_svc_set (
		struct rrr_http_transaction *transaction,
		const char *alt_svc
);
int rrr_http_transaction_response_alt_svc_get (
		enum rrr_http_transport *transport_code,
		char **authority,
		uint16_t *port,
		const struct rrr_http_transaction *transaction
);
int rrr_http_transaction_endpoint_path_get (
		char **result,
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_endpoint_with_query_string_create (
		struct rrr_nullsafe_str **target,
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_form_data_generate_if_needed (
		int *form_data_was_made,
		struct rrr_http_transaction *transaction
);
int rrr_http_transaction_send_body_set (
		struct rrr_http_transaction *transaction,
		const void *data,
		rrr_length data_size
);
int rrr_http_transaction_send_body_set_allocated (
		struct rrr_http_transaction *transaction,
		void **data,
		rrr_length data_size
);
int rrr_http_transaction_response_prepare_wrapper (
		struct rrr_http_transaction *transaction,
		int (*header_field_callback)(struct rrr_http_header_field *field, void *arg),
		int (*response_code_callback)(unsigned response_code, enum rrr_http_version protocol_version, void *arg),
		int (*final_callback)(struct rrr_http_transaction *transaction, void *arg),
		void *callback_arg
);
int rrr_http_transaction_request_prepare_wrapper (
		struct rrr_http_transaction *transaction,
		enum rrr_http_upgrade_mode upgrade_mode,
		enum rrr_http_version protocol_version,
		const char *user_agent,
		int (*preliminary_callback)(
			enum rrr_http_method method,
			enum rrr_http_upgrade_mode upgrade_mode,
			enum rrr_http_version protocol_version,
			struct rrr_http_part *request_part,
			const struct rrr_nullsafe_str *request,
			void *arg
		),
		int (*headers_callback)(struct rrr_http_header_field *field, void *arg),
		int (*final_callback)(struct rrr_http_transaction *transaction, void *arg),
		void *callback_arg
);
static inline void rrr_http_transaction_stream_flags_add (
		struct rrr_http_transaction *transaction,
		int flags
) {
	transaction->stream_flags |= flags;
}

static inline int rrr_http_transaction_stream_flags_has (
		struct rrr_http_transaction *transaction,
		int flags
) {
	return ((transaction->stream_flags & flags) == flags);
}

#endif /* RRR_HTTP_TRANSACTION_H */
