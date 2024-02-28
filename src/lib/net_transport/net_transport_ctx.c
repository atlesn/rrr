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

#include <assert.h>
#include <stdlib.h>

#include "../log.h"
#include "../allocator.h"
#include "../ip/ip_util.h"
#include "../util/macro_utils.h"
#include "../helpers/nullsafe_str.h"
#include "net_transport_struct.h"

int rrr_net_transport_ctx_connection_id_push (
		struct rrr_net_transport_handle *handle,
		const struct rrr_net_transport_connection_id *cid
		
) {
	return rrr_net_transport_connection_id_collection_push(&handle->cids, cid);
}

void rrr_net_transport_ctx_connection_id_remove (
		struct rrr_net_transport_handle *handle,
		const struct rrr_net_transport_connection_id *cid
) {
	rrr_net_transport_connection_id_collection_remove(&handle->cids, cid);
}

void rrr_net_transport_ctx_touch (
		struct rrr_net_transport_handle *handle
) {
	if (handle->transport->hard_read_timeout_ms > 0) {
		EVENT_ADD(handle->event_hard_read_timeout);
	}
}

void rrr_net_transport_ctx_reset_noread_counters (
		struct rrr_net_transport_handle *handle
) {
	handle->noread_strike_count = 0;
}

void rrr_net_transport_ctx_notify_read_fast (
		struct rrr_net_transport_handle *handle
) {
	if (!EVENT_PENDING(handle->event_read_notify_fast)) {
		EVENT_ADD(handle->event_read_notify_fast);
	}
}

void rrr_net_transport_ctx_notify_read_slow (
		struct rrr_net_transport_handle *handle
) {
	if (!EVENT_PENDING(handle->event_read_notify_slow)) {
		EVENT_ADD(handle->event_read_notify_slow);
	}
}

void rrr_net_transport_ctx_notify_tick_fast (
		struct rrr_net_transport_handle *handle
) {
	if (!EVENT_PENDING(handle->event_tick_notify_fast)) {
		EVENT_ADD(handle->event_tick_notify_fast);
	}
}

void rrr_net_transport_ctx_notify_tick_slow (
		struct rrr_net_transport_handle *handle
) {
	if (!EVENT_PENDING(handle->event_tick_notify_slow)) {
		EVENT_ADD(handle->event_tick_notify_slow);
	}
}

int rrr_net_transport_ctx_get_fd (
		struct rrr_net_transport_handle *handle
) {
	return handle->submodule_fd;
}

void *rrr_net_transport_ctx_get_application_private_ptr (
		struct rrr_net_transport_handle *handle
) {
	return handle->application_private_ptr;
}

rrr_net_transport_handle rrr_net_transport_ctx_get_handle (
		struct rrr_net_transport_handle *handle
) {
	return handle->handle;
}

struct rrr_net_transport *rrr_net_transport_ctx_get_transport (
		struct rrr_net_transport_handle *handle
) {
	return handle->transport;
}

int rrr_net_transport_ctx_check_alive (
		struct rrr_net_transport_handle *handle
) {
	return handle->transport->methods->poll(handle);
}

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
) {
	if (handle->mode != RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION) {
		RRR_BUG("BUG: Handle to rrr_net_transport_read_message was not of CONNECTION type\n");
	}

	uint64_t bytes_read = 0;
	int ret = handle->transport->methods->read_message (
			&bytes_read,
			handle,
			read_step_initial,
			read_step_max_size,
			read_max_size,
			ratelimit_interval_us,
			ratelimit_max_bytes,
			get_target_size,
			get_target_size_arg,
			get_target_size_error,
			get_target_size_error_arg,
			complete_callback,
			complete_callback_arg
	);
	handle->bytes_read_total += bytes_read;

	if (ret == RRR_NET_TRANSPORT_READ_RATELIMIT) {
		EVENT_REMOVE(handle->event_read);
	}

	return ret;
}

size_t rrr_net_transport_ctx_send_waiting_chunk_count (
		struct rrr_net_transport_handle *handle
) {
	return rrr_socket_send_chunk_collection_count(&handle->send_chunks);
}

long double rrr_net_transport_ctx_send_waiting_chunk_limit_factor (
		struct rrr_net_transport_handle *handle
) {
	long double count = rrr_socket_send_chunk_collection_count(&handle->send_chunks);
	long double limit = handle->transport->send_chunk_count_limit;

	if (limit <= 0) {
		return 0.0;
	}

	long double result = count / limit;

	return (result > 1.0 ? 1.0 : result);
}

static int __rrr_net_transport_ctx_send_push_postcheck (
		struct rrr_net_transport_handle *handle,
		rrr_length send_chunk_count
) {
	if (handle->transport->send_chunk_count_limit != 0 && send_chunk_count > handle->transport->send_chunk_count_limit) {
		RRR_MSG_0("net transport fd %i [%s] send chunk count exceeded specified limit (%i/%i), soft error.\n",
				handle->submodule_fd,
				handle->transport->application_name,
				send_chunk_count,
				handle->transport->send_chunk_count_limit
		);
		return RRR_NET_TRANSPORT_SEND_SOFT_ERROR;
	}
	return 0;
}

static int __rrr_net_transport_ctx_send_push (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_biglength size,
		int is_urgent
) {
	int ret = 0;

	EVENT_ADD(handle->event_write);

	rrr_length send_chunk_count = 0;
	if ((ret = rrr_socket_send_chunk_collection_push (
			&send_chunk_count,
			&handle->send_chunks,
			data,
			size,
			is_urgent ? RRR_SOCKET_SEND_CHUNK_PRIORITY_HIGH
			          : RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL
	)) != 0) {
		goto out;
	}

	ret = __rrr_net_transport_ctx_send_push_postcheck (handle, send_chunk_count);

	out:
	return ret;
}

void rrr_net_transport_ctx_close_when_send_complete_set (
		struct rrr_net_transport_handle *handle
) {
	if (!handle->close_when_send_complete) {
		handle->close_when_send_complete = 1;
		RRR_DBG_7("net transport fd %i [%s] close when send complete activated\n",
				handle->submodule_fd, handle->transport->application_name);

		EVENT_ADD(handle->event_write);
	}
}

int rrr_net_transport_ctx_close_when_send_complete_get (
		struct rrr_net_transport_handle *handle
) {
	return handle->close_when_send_complete;
}

void rrr_net_transport_ctx_close_now_set (
		struct rrr_net_transport_handle *handle
) {
	handle->close_now = 1;

	RRR_DBG_7("net transport fd %i [%s] close now activated\n",
			handle->submodule_fd, handle->transport->application_name);
}

int rrr_net_transport_ctx_send_push (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_biglength size
) {
	return __rrr_net_transport_ctx_send_push (handle, data, size, 0 /* Not urgent */);
}

int rrr_net_transport_ctx_send_push_urgent (
		struct rrr_net_transport_handle *handle,
		void **data,
		rrr_biglength size
) {
	return __rrr_net_transport_ctx_send_push (handle, data, size, 1 /* Urgent */);
}

static int __rrr_net_transport_ctx_send_push_const (
		struct rrr_net_transport_handle *handle,
		const void *data,
		rrr_biglength size,
		int is_urgent
) {
	int ret = 0;

	EVENT_ADD(handle->event_write);

	rrr_length send_chunk_count = 0;
	if ((ret = rrr_socket_send_chunk_collection_push_const (
			&send_chunk_count,
			&handle->send_chunks,
			data,
			size,
			is_urgent ? RRR_SOCKET_SEND_CHUNK_PRIORITY_HIGH
			          : RRR_SOCKET_SEND_CHUNK_PRIORITY_NORMAL
	)) != 0) {
		goto out;
	}

	ret = __rrr_net_transport_ctx_send_push_postcheck (handle, send_chunk_count);

	out:
	return ret;
}

int rrr_net_transport_ctx_send_push_const (
		struct rrr_net_transport_handle *handle,
		const void *data,
		rrr_biglength size
) {
	return __rrr_net_transport_ctx_send_push_const (handle, data, size, 0 /* Not urgent */);
}

int rrr_net_transport_ctx_send_push_const_urgent (
		struct rrr_net_transport_handle *handle,
		const void *data,
		rrr_biglength size
) {
	return __rrr_net_transport_ctx_send_push_const (handle, data, size, 1 /* Urgent */);
}

static int __rrr_net_transport_ctx_send_push_nullsafe_callback (
		const void *data,
		rrr_nullsafe_len data_len,
		void *arg
) {
	struct rrr_net_transport_handle *handle = arg;

	return rrr_net_transport_ctx_send_push_const (handle, data, data_len);
}

int rrr_net_transport_ctx_send_push_nullsafe (
		struct rrr_net_transport_handle *handle,
		const struct rrr_nullsafe_str *nullsafe
) {
	return rrr_nullsafe_str_with_raw_do_const(nullsafe, __rrr_net_transport_ctx_send_push_nullsafe_callback, handle);
}

int rrr_net_transport_ctx_stream_data_get (
		void **stream_data,
		struct rrr_net_transport_handle *handle,
		int64_t stream_id
) {
	return handle->transport->methods->stream_data_get(stream_data, handle, stream_id);
}

int rrr_net_transport_ctx_stream_data_clear (
		struct rrr_net_transport_handle *handle,
		int64_t stream_id
) {
	return handle->transport->methods->stream_data_clear(handle, stream_id);
}

int rrr_net_transport_ctx_stream_open_local (
		int64_t *result,
		struct rrr_net_transport_handle *handle,
		int flags,
		void *stream_open_callback_arg_local
) {
	assert(flags & RRR_NET_TRANSPORT_STREAM_F_LOCAL);

	return handle->transport->methods->stream_open_local (
			result,
			handle,
			flags,
			stream_open_callback_arg_local
	);
}

int rrr_net_transport_ctx_stream_open_remote (
		int64_t stream_id,
		struct rrr_net_transport_handle *handle
) {
	return handle->transport->methods->stream_open_remote (
			stream_id,
			handle
	);
}

int rrr_net_transport_ctx_stream_consume (
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		size_t consumed
) {
	return handle->transport->methods->stream_consume(handle, stream_id, consumed);
}

int rrr_net_transport_ctx_stream_shutdown_read (
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		uint64_t application_error_reason
) {
	return handle->transport->methods->stream_shutdown_read(handle, stream_id, application_error_reason);
}

int rrr_net_transport_ctx_stream_shutdown_write (
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		uint64_t application_error_reason
) {
	return handle->transport->methods->stream_shutdown_write(handle, stream_id, application_error_reason);
}

int rrr_net_transport_ctx_streams_iterate (
		struct rrr_net_transport_handle *handle,
		int (*callback)(int64_t stream_id, void *stream_data, void *arg),
		void *arg
) {
	return handle->transport->methods->streams_iterate(handle, callback, arg);
}

uint64_t rrr_net_transport_ctx_stream_count (
		struct rrr_net_transport_handle *handle
) {
	return handle->transport->methods->stream_count(handle);
}

int rrr_net_transport_ctx_extend_max_streams (
		struct rrr_net_transport_handle *handle,
		int64_t stream_id,
		size_t n
) {
	return handle->transport->methods->extend_max_streams(handle, stream_id, n);
}

int rrr_net_transport_ctx_read (
		uint64_t *bytes_read,
		struct rrr_net_transport_handle *handle,
		char *buf,
		size_t buf_size
) {
	int ret = handle->transport->methods->read(bytes_read, handle, buf, buf_size);

	assert((ret || *bytes_read) && "A return value must be set or data must be returned");

	handle->bytes_read_total += *bytes_read;

	return ret;
}

int rrr_net_transport_ctx_receive (
		uint64_t *next_expiry_nano,
		struct rrr_net_transport_handle *handle,
		const struct rrr_socket_datagram *datagram
) {
	int ret = handle->transport->methods->receive(next_expiry_nano, handle, datagram);

	handle->bytes_read_total += datagram->msg_len;

	return ret;
}

int rrr_net_transport_ctx_handle_has_application_data (
		struct rrr_net_transport_handle *handle
) {
	return (handle->application_private_ptr != NULL);
}

void rrr_net_transport_ctx_get_socket_stats (
		uint64_t *bytes_read_total,
		uint64_t *bytes_written_total,
		uint64_t *bytes_total,
		struct rrr_net_transport_handle *handle
) {
	if (bytes_read_total != NULL) {
		*bytes_read_total = handle->bytes_read_total;
	}
	if (bytes_written_total != NULL) {
		*bytes_written_total = handle->bytes_written_total;
	}
	if (bytes_total != NULL) {
		*bytes_total = handle->bytes_read_total + handle->bytes_written_total;
	}
}

int rrr_net_transport_ctx_is_tls (
		struct rrr_net_transport_handle *handle
) {
	return rrr_net_transport_is_tls(handle->transport);
}

void rrr_net_transport_ctx_connected_address_to_str (
		char *buf,
		size_t buf_size,
		struct rrr_net_transport_handle *handle
) {
	if (handle->connected_addr_len == 0) {
		snprintf(buf, buf_size, "(unknown)");
	}
	else {
		rrr_ip_to_str(buf, buf_size, (const struct sockaddr *) &handle->connected_addr, handle->connected_addr_len);
	}
}

void rrr_net_transport_ctx_connected_address_get (
		const struct sockaddr **addr,
		socklen_t *addr_len,
		const struct rrr_net_transport_handle *handle
) {
	*addr = (const struct sockaddr *) &handle->connected_addr;
	*addr_len = handle->connected_addr_len;
}

int rrr_net_transport_ctx_selected_proto_get (
		char **proto,
		struct rrr_net_transport_handle *handle
) {
	return handle->transport->methods->selected_proto_get(proto, handle);
}

enum rrr_net_transport_type rrr_net_transport_ctx_transport_type_get (
		const struct rrr_net_transport_handle *handle
) {
	return rrr_net_transport_type_get(handle->transport);
}

int rrr_net_transport_ctx_with_match_data_do (
		const struct rrr_net_transport_handle *handle,
		int (*callback)(const char *string, uint64_t number, void *arg),
		void *arg
) {
	return callback(handle->match_string, handle->match_number, arg);
}
