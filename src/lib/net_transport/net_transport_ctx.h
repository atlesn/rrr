/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NET_TRANSPORT_CTX_H
#define RRR_NET_TRANSPORT_CTX_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>

#include "../helpers/nullsafe_str.h"
#include "net_transport_types.h"

#define RRR_NET_TRANSPORT_CTX_FD(handle) rrr_net_transport_ctx_get_fd(handle)
#define RRR_NET_TRANSPORT_CTX_PRIVATE_PTR(handle) rrr_net_transport_ctx_get_private_ptr(handle)
#define RRR_NET_TRANSPORT_CTX_HANDLE(handle) rrr_net_transport_ctx_get_handle(handle)

/*
 * The CTX functions operate on the net transport handle object.
 * This object must not be stored anywhere as it may be freed at any time.
 * It may only be used within a net transport callback /context/ .
 * To store reference to a particular handle, use the handle ID ( get_handle() )
 */

struct rrr_net_transport_handle;
struct rrr_read_session;

void rrr_net_transport_ctx_touch (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_notify_read_fast (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_notify_read_slow (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_get_fd (
		struct rrr_net_transport_handle *handle
);
void *rrr_net_transport_ctx_get_private_ptr (
		struct rrr_net_transport_handle *handle
);
rrr_net_transport_handle rrr_net_transport_ctx_get_handle (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_handle_match_data_set (
		struct rrr_net_transport_handle *handle,
		const char *string,
		uint64_t number
);
int rrr_net_transport_ctx_check_alive (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_read_message (
		struct rrr_net_transport_handle *handle,
		rrr_biglength read_step_initial,
		rrr_biglength read_step_max_size,
		rrr_biglength read_max_size,
		uint64_t ratelimit_interval_us,
		rrr_biglength ratelimit_max_bytes,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		void (*get_target_size_error)(struct rrr_read_session *read_session, int is_hard_err, void *arg),
		void *get_target_size_error_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
);
size_t rrr_net_transport_ctx_send_waiting_chunk_count (
		struct rrr_net_transport_handle *handle
);
long double rrr_net_transport_ctx_send_waiting_chunk_limit_factor (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_close_when_send_complete_set (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_close_when_send_complete_get (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_send_push (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_biglength size
);
int rrr_net_transport_ctx_send_push_urgent (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_biglength size
);
int rrr_net_transport_ctx_send_push_const (
		struct rrr_net_transport_handle *handle,
		const void *data,
		rrr_biglength size
);
int rrr_net_transport_ctx_send_push_const_urgent (
		struct rrr_net_transport_handle *handle,
		const void *data,
		rrr_biglength size
);
int rrr_net_transport_ctx_send_push_nullsafe (
		struct rrr_net_transport_handle *handle,
		const struct rrr_nullsafe_str *nullsafe
);
int rrr_net_transport_ctx_read (
		uint64_t *bytes_read,
		struct rrr_net_transport_handle *handle,
		char *buf,
		size_t buf_size
);
int rrr_net_transport_ctx_handle_has_application_data (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_handle_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
);
void rrr_net_transport_ctx_handle_pre_destroy_function_set (
		struct rrr_net_transport_handle *handle,
		int (*pre_destroy_function)(struct rrr_net_transport_handle *handle, void *ptr)
);
void rrr_net_transport_ctx_get_socket_stats (
		uint64_t *bytes_read_total,
		uint64_t *bytes_written_total,
		uint64_t *bytes_total,
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_is_tls (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_connected_address_to_str (
		char *buf,
		size_t buf_size,
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_connected_address_get (
		const struct sockaddr **addr,
		socklen_t *addr_len,
		const struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_selected_proto_get (
		const char **proto,
		struct rrr_net_transport_handle *handle
);

#endif /* RRR_WITH_NET_TRANSPORT_CTX_H */
