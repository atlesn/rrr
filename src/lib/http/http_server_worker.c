/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../log.h"

#include "http_server_worker.h"
#include "http_common.h"
#include "http_session.h"
#include "http_transaction.h"
#include "http_part.h"
#include "http_util.h"
#include "http_server_common.h"

#include "../net_transport/net_transport.h"
#include "../threads.h"
#include "../array.h"
#include "../ip/ip_util.h"
#include "../util/posix.h"

#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_PING_INTERVAL_S	5
#define RRR_HTTP_SERVER_WORKER_WEBSOCKET_TIMEOUT_S			(RRR_HTTP_SERVER_WORKER_WEBSOCKET_PING_INTERVAL_S*2)

int rrr_http_server_worker_preliminary_data_new (
		struct rrr_http_server_worker_preliminary_data **result,
		const struct rrr_http_server_callbacks *callbacks,
		int disable_http2
) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_server_worker_preliminary_data *data = malloc(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_server_worker_thread_data_new\n");
		ret = 1;
		goto out;
	}

	memset (data, '\0', sizeof(*data));

	data->config_data.disable_http2 = disable_http2;
	data->config_data.callbacks = *callbacks;

	*result = data;

	goto out;
//	out_free:
//		free(data);
	out:
		return ret;
}

void rrr_http_server_worker_preliminary_data_destroy_if_not_null (
		struct rrr_http_server_worker_preliminary_data *worker_data
) {
	if (worker_data == NULL) {
		return;
	}
	free(worker_data);
}

static int __rrr_http_server_worker_preliminary_data_destroy_callback (
		struct rrr_thread *thread,
		void *arg
) {
	(void)(arg);

	if (thread->private_data == NULL) {
		return 0;
	}

	rrr_http_server_worker_preliminary_data_destroy_if_not_null(thread->private_data);
	thread->private_data = NULL;

	return 0;
}

static void __rrr_http_server_worker_preliminary_data_destroy_void_intermediate (
		void *arg
) {
	struct rrr_thread *thread = arg;

	rrr_thread_with_lock_do(thread, __rrr_http_server_worker_preliminary_data_destroy_callback, NULL);
}

static void __rrr_http_server_worker_data_cleanup (
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;
	//printf("push handle %i to close tag list\n", worker_data->config_data.transport_handle);
	rrr_net_transport_handle_close_tag_list_push(worker_data->config_data.transport, worker_data->config_data.transport_handle);
	RRR_FREE_IF_NOT_NULL(worker_data->websocket_application_data);
}

static int __rrr_http_server_worker_response_headers_push (
		struct rrr_http_part *response_part
) {
	int ret = RRR_HTTP_OK;

	ret |= rrr_http_part_header_field_push(response_part, "access-control-request-methods", "OPTIONS, GET, POST, PUT");

	return ret;
}

static int __rrr_http_server_worker_response_initialize (
		struct rrr_http_server_worker_data *worker_data,
		struct rrr_http_part *response_part
) {
	if (__rrr_http_server_worker_response_headers_push(response_part) != 0) {
		RRR_MSG_0("HTTP worker %i: Could not push default response headers in __rrr_http_server_worker_net_transport_ctx_send_response\n",
				worker_data->config_data.transport_handle);
		return RRR_HTTP_HARD_ERROR;
	}

	return RRR_HTTP_OK;
}

static int __rrr_http_server_worker_receive_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	(void)(data_ptr);

	int ret = 0;

	if (RRR_DEBUGLEVEL_2) {
		char ip_buf[256];
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(method_buf, transaction->request_part->request_method_str_nullsafe);
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(uri_buf, transaction->request_part->request_uri_nullsafe);

		rrr_ip_to_str(ip_buf, 256, (const struct sockaddr *) &worker_data->config_data.addr, worker_data->config_data.addr_len);

		RRR_MSG_2("HTTP worker %i %s %s %s %s\n",
				worker_data->config_data.transport_handle,
				ip_buf,
				method_buf,
				uri_buf,
				(transaction->request_part->parsed_protocol_version == RRR_HTTP_APPLICATION_HTTP2 ? "HTTP/2" : "HTTP/1.1")
		);

		if (overshoot_bytes > 0) {
			RRR_MSG_2("HTTP worker %i %s has %li bytes overshoot, expecting another request\n",
					worker_data->config_data.transport_handle, ip_buf, overshoot_bytes);
		}
	}

	if ((ret = __rrr_http_server_worker_response_initialize(worker_data, transaction->response_part)) != RRR_HTTP_OK) {
		goto out;
	}

	if (worker_data->config_data.callbacks.final_callback != NULL) {
		ret = worker_data->config_data.callbacks.final_callback (
				worker_data->thread,
				(const struct sockaddr *) &worker_data->config_data.addr,
				worker_data->config_data.addr_len,
				handle,
				transaction,
				data_ptr,
				overshoot_bytes,
				next_protocol_version,
				worker_data->config_data.callbacks.final_callback_arg
		);
	}

	if (transaction->response_part->response_code == 0) {
		switch (ret) {
			case RRR_HTTP_OK:
				transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT;
				break;
			case RRR_HTTP_SOFT_ERROR:
				transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
				break;
			default:
				transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR;
				break;
		};
	}

	out:
	return ret;
}

static int __rrr_http_server_worker_websocket_handshake_callback (
		RRR_HTTP_SESSION_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	int ret = 0;

	if (worker_data->config_data.callbacks.websocket_handshake_callback == NULL) {
		RRR_DBG_1("Note: HTTP server received an HTTP1 request with upgrade to websocket, but no websocket callback is set\n");
		*do_websocket = 0;
	}
	else if ((ret = worker_data->config_data.callbacks.websocket_handshake_callback (
			&worker_data->websocket_application_data,
			do_websocket,
			handle,
			transaction,
			data_ptr,
			overshoot_bytes,
			next_protocol_version,
			worker_data->config_data.callbacks.final_callback_arg
	)) != 0) {
		goto out;
	}

	out:
	if (ret != 0 || transaction->response_part->response_code != 0) {
		worker_data->request_complete = 1;
	}
	return ret;
}

static int __rrr_http_server_worker_websocket_get_response_callback (
		RRR_HTTP_SESSION_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	*data = NULL;
	*data_len = 0;
	*is_binary = 0;

	if (worker_data->config_data.callbacks.websocket_get_response_callback) {
		return worker_data->config_data.callbacks.websocket_get_response_callback (
				&worker_data->websocket_application_data,
				data,
				data_len,
				is_binary,
				unique_id,
				worker_data->config_data.callbacks.websocket_get_response_callback_arg
		);
	}

	return 0;
}

static int __rrr_http_server_worker_websocket_frame_callback (
		RRR_HTTP_SESSION_WEBSOCKET_FRAME_CALLBACK_ARGS
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	if (worker_data->config_data.callbacks.websocket_frame_callback) {
		return worker_data->config_data.callbacks.websocket_frame_callback (
				&worker_data->websocket_application_data,
				(const struct sockaddr *) &worker_data->config_data.addr,
				worker_data->config_data.addr_len,
				payload,
				is_binary,
				unique_id,
				worker_data->config_data.callbacks.websocket_handshake_callback_arg
		);
	}

	return 0;
}

static int __rrr_http_server_worker_upgrade_verify_callback (
	RRR_HTTP_SESSION_UPGRADE_VERIFY_CALLBACK_ARGS
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	*do_upgrade = 1;

	(void)(from);

	if (to == RRR_HTTP_UPGRADE_MODE_HTTP2 && worker_data->config_data.disable_http2 != 0) {
		RRR_DBG_3("HTTP worker %i received upgrade request to HTTP2, but HTTP2 is disabled. Using HTTP1.\n",
				worker_data->config_data.transport_handle);
		*do_upgrade = 0;
	}

	return 0;
}

static int __rrr_http_server_worker_net_transport_ctx_do_work (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	int ret = 0;

	ssize_t received_bytes = 0;
	uint64_t active_transaction_count = 0;

	if ((ret = rrr_http_session_transport_ctx_tick_server (
			&received_bytes,
			&active_transaction_count,
			&worker_data->complete_transactions_total,
			handle,
			worker_data->config_data.read_max_size,
			worker_data->config_data.callbacks.unique_id_generator_callback,
			worker_data->config_data.callbacks.unique_id_generator_callback_arg,
			__rrr_http_server_worker_upgrade_verify_callback,
			worker_data,
			__rrr_http_server_worker_websocket_handshake_callback,
			worker_data,
			__rrr_http_server_worker_receive_callback,
			worker_data,
			NULL,
			NULL,
			__rrr_http_server_worker_websocket_get_response_callback,
			worker_data,
			__rrr_http_server_worker_websocket_frame_callback,
			worker_data
	)) != 0) {
		if (ret != RRR_HTTP_SOFT_ERROR && ret != RRR_READ_INCOMPLETE && ret != RRR_READ_EOF) {
			RRR_MSG_0("HTTP worker %i: Error while working with client\n",
					worker_data->config_data.transport_handle);
		}
		goto out;
	}

	// Get this after the first tick to make sure we don't print
	// the no data within XXX ms message in the main loop if the
	// request took for some time
	rrr_net_transport_ctx_get_socket_stats(NULL, NULL, &worker_data->bytes_total, handle);

	out:
	return ret;
}

static int __rrr_http_server_worker_preliminary_data_get_callback (
		struct rrr_thread *thread,
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	if (thread->private_data == NULL) {
		return 1;
	}

	struct rrr_http_server_worker_preliminary_data *worker_data_preliminary = thread->private_data;

	worker_data->config_data = worker_data_preliminary->config_data;

	return 0;
}

static void __rrr_http_server_worker_thread_entry (
		struct rrr_thread *thread
) {
	// DO NOT use private_data except from inside lock wrapper callback

	rrr_thread_start_condition_helper_nofork(thread);

	struct rrr_http_server_worker_data worker_data = {0};

	// There is no more communication with main thread over this struct after this point.
	// Copy the data to a local struct. Pointer to main transport will always
	// be valid, main thread will not destroy it before threads have shut down.
	// The lock only protects the data members of the worker data struct, not
	// what they point to. DO NOT have members like char * in the struct.

	if (rrr_thread_with_lock_do (
			thread,
			__rrr_http_server_worker_preliminary_data_get_callback,
			&worker_data
	) != 0) {
		RRR_MSG_0("Failed to get preliminary data in HTTP server worker\n");
		goto out;
	}

	// This might happen upon server shutdown
	if (worker_data.config_data.transport_handle == 0) {
		goto out;
	}

	worker_data.thread = thread;

	// All usage of private data pointer (http_session) of the transport handle
	// must be done with net transport handle lock held.

	// The transport handle integer is always
	// usable, even if the handle it points to has been freed. The lock wrapper
	// function in net transport will fail if the handle has been freed, this means
	// that the HTTP session has also been freed.

	pthread_cleanup_push(__rrr_http_server_worker_data_cleanup, &worker_data);

	RRR_DBG_8("HTTP worker %i thread %p starting\n",
			worker_data.config_data.transport_handle,
			thread
	);

	uint64_t connection_start_time = rrr_time_get_64();
	unsigned int consecutive_nothing_happened = 0; // Let it overflow
	uint64_t prev_bytes_total = 0;
	uint64_t prev_something_happened = rrr_time_get_64();

	uint64_t prev_transaction_complete_count = 0;
	uint64_t prev_transaction_complete = rrr_time_get_64();

	while (rrr_thread_signal_encourage_stop_check(thread) == 0) {
		rrr_thread_watchdog_time_update(thread);

		int ret_tmp = 0;
		if ((ret_tmp = rrr_net_transport_handle_with_transport_ctx_do (
				worker_data.config_data.transport,
				worker_data.config_data.transport_handle,
				__rrr_http_server_worker_net_transport_ctx_do_work,
				&worker_data
		)) != 0) {
			if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
				RRR_DBG_2("HTTP worker %i: Failed while working with client, soft error\n",
						worker_data.config_data.transport_handle);
				break;
			}
			else if (ret_tmp == RRR_READ_EOF) {
				break;
			}
			else if (ret_tmp == RRR_READ_INCOMPLETE) {
				// OK, more work to be done
			}
			else {
				RRR_MSG_0("HTTP worker %i: Failed while working with client, hard error\n",
						worker_data.config_data.transport_handle);
				break;
			}
		}

		if (worker_data.request_complete) {
			break;
		}

		const uint64_t time_now = rrr_time_get_64();

		if (worker_data.bytes_total == 0 && time_now - connection_start_time > RRR_HTTP_SERVER_WORKER_FIRST_DATA_TIMEOUT_MS * 1000) {
			RRR_DBG_2("HTTP worker %i: No data received within %i ms, closing connection.\n",
					worker_data.config_data.transport_handle, RRR_HTTP_SERVER_WORKER_FIRST_DATA_TIMEOUT_MS);
			break;
		}

		if (time_now - prev_something_happened > RRR_HTTP_SERVER_WORKER_IDLE_TIMEOUT_MS * 1000) {
			RRR_DBG_2("HTTP worker %i: Nothing received for %i ms, closing connection.\n",
					worker_data.config_data.transport_handle, RRR_HTTP_SERVER_WORKER_IDLE_TIMEOUT_MS);
			break;
		}

		if (prev_transaction_complete_count != worker_data.complete_transactions_total) {
			prev_transaction_complete = time_now;
			prev_transaction_complete_count = worker_data.complete_transactions_total;
		}
		else if (	worker_data.complete_transactions_total == 0 &&
				time_now - prev_transaction_complete > RRR_HTTP_SERVER_WORKER_TRANSACTION_TIMEOUT_MS * 1000
		) {
			RRR_DBG_2("HTTP worker %i: No transactions completed within %i ms, closing connection.\n",
					worker_data.config_data.transport_handle, RRR_HTTP_SERVER_WORKER_TRANSACTION_TIMEOUT_MS);
			break;
		}

		if (prev_bytes_total != worker_data.bytes_total) {
			prev_something_happened = time_now;
			consecutive_nothing_happened = 0;
		}
		else {
			consecutive_nothing_happened++;
		}

		if (consecutive_nothing_happened > 50) {
			rrr_posix_usleep(30000); // 30 ms
			//printf("long sleep complete transactions: %" PRIu64 "\n", worker_data.complete_transactions_total);
		}
		else if (consecutive_nothing_happened > 10) {
			rrr_posix_usleep(5000); // 5 ms
			//printf("short sleep %u\n", consecutive_nothing_happened);
		}

		prev_bytes_total = worker_data.bytes_total;
	}

	RRR_DBG_3("HTTP worker %i done, %" PRIu64 " requests was processed\n",
			worker_data.config_data.transport_handle,
			worker_data.complete_transactions_total
	);

	RRR_DBG_8("HTTP worker %i thread %p exiting\n",
			worker_data.config_data.transport_handle,
			thread
	);

	// This cleans up HTTP data
	pthread_cleanup_pop(1);
	out:
		return;
}

void *rrr_http_server_worker_thread_entry_intermediate (
		struct rrr_thread *thread
) {
	pthread_cleanup_push(__rrr_http_server_worker_preliminary_data_destroy_void_intermediate, thread);
	__rrr_http_server_worker_thread_entry(thread);
	pthread_cleanup_pop(1);
	return NULL;
}
