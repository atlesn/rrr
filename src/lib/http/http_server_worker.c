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
#include "http_part.h"

#include "../net_transport/net_transport.h"
#include "../threads.h"
#include "../array.h"
#include "../ip/ip_util.h"
#include "../util/posix.h"

int rrr_http_server_worker_preliminary_data_new (
		struct rrr_http_server_worker_preliminary_data **result,
		int (*unique_id_generator_callback)(RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS),
		void *unique_id_generator_callback_arg,
		int (*final_callback_raw)(RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS),
		void *final_callback_raw_arg,
		int (*final_callback)(RRR_HTTP_SERVER_WORKER_RECEIVE_CALLBACK_ARGS),
		void *final_callback_arg
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

	data->final_callback = final_callback;
	data->final_callback_arg = final_callback_arg;

	data->unique_id_generator_callback = unique_id_generator_callback;
	data->unique_id_generator_callback_arg = unique_id_generator_callback_arg;

	data->final_callback_raw = final_callback_raw;
	data->final_callback_raw_arg = final_callback_raw_arg;

	*result = data;

	goto out;
//	out_free:
//		free(data);
	out:
		return ret;
}

void rrr_http_server_worker_preliminary_data_destroy (
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

	rrr_http_server_worker_preliminary_data_destroy(thread->private_data);
	thread->private_data = NULL;

	return 0;
}

static void __rrr_http_server_worker_preliminary_data_destroy_void_intermediate (
		void *arg
) {
	struct rrr_thread *thread = arg;

	rrr_thread_with_lock_do(thread, __rrr_http_server_worker_preliminary_data_destroy_callback, NULL);
}

static void __rrr_http_server_worker_close_transport (
		void *arg
) {
	printf("Worker exiting\n");
	struct rrr_http_server_worker_data *worker_data = arg;
	rrr_net_transport_handle_close_tag_list_push(worker_data->transport, worker_data->transport_handle);
}

static int __rrr_http_server_worker_push_response_headers (
		struct rrr_http_part *response_part
) {
	int ret = RRR_HTTP_OK;

	ret |= rrr_http_part_header_field_push(response_part, "connection", "close");
	ret |= rrr_http_part_header_field_push(response_part, "access-control-request-methods", "OPTIONS, GET, POST, PUT");

	return ret;
}

static int __rrr_http_server_worker_initialize_response (
		struct rrr_http_server_worker_data *worker_data,
		struct rrr_http_part *response_part
) {
	// We allow send_response to be called as long as transpoort handle is OK,
	// but the response part must have been initialized for us to be able to
	// send a response. If it is NULL, we cannot send a response.
//	if (!rrr_http_session_transport_ctx_check_response_part_initialized(handle)) {
//		RRR_DBG_3("HTTP worker %i: No HTTP parts initialized, not sending response\n", worker_data->transport_handle);
//		return 0;
//	}
/*
	if (rrr_http_session_transport_ctx_reset_response_part(handle) != RRR_HTTP_OK) {
		RRR_MSG_0("Could not initialize response part in __rrr_http_server_worker_net_transport_ctx_initialize_response\n");
		return RRR_HTTP_HARD_ERROR;
	}

	// If client has not sent any data, don't send a response
	if (!rrr_http_session_transport_ctx_check_data_received(handle)) {
		RRR_DBG_3("HTTP worker %i: No HTTP request from client, not sending response\n", worker_data->transport_handle);
		return RRR_HTTP_OK;
	}
*/

	if (__rrr_http_server_worker_push_response_headers(response_part) != 0) {
		RRR_MSG_0("HTTP worker %i: Could not push default response headers in __rrr_http_server_worker_net_transport_ctx_send_response\n",
				worker_data->transport_handle);
		return RRR_HTTP_HARD_ERROR;
	}

	/*
	 * For now, no content is sent back to client
		if (rrr_http_session_transport_ctx_push_response_header(handle, "Content-Type", "application/json; charset=utf-8") != 0) {
			RRR_MSG_0("Could not push header field to response part in __rrr_net_http_server_worker_net_transport_ctx_send_response\n");
			return 1;
		}
	*/

	return RRR_HTTP_OK;
}

static int __rrr_http_server_worker_http_session_receive_callback (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	(void)(data_ptr);

	// These are always 0, we read using the recv() function. recvfrom() would
	// not return anything as well. The remote address is instead cached right
	// after we accept the connection.
	(void)(sockaddr);
	(void)(socklen);

	int ret = 0;

	if (RRR_DEBUGLEVEL_2) {
		char ip_buf[256];

		rrr_ip_to_str(ip_buf, 256, (const struct sockaddr *) &worker_data->sockaddr, worker_data->socklen);

		RRR_MSG_2("HTTP worker %i %s %s %s HTTP/1.1\n",
				worker_data->transport_handle, ip_buf, request_part->request_method_str, request_part->request_uri);

		if (overshoot_bytes > 0) {
			RRR_MSG_2("HTTP worker %i %s has %li bytes overshoot, expecting another request\n",
					worker_data->transport_handle, ip_buf, overshoot_bytes);
		}
	}

	if (overshoot_bytes == 0) {
		worker_data->request_complete = 1;
	}

	if ((ret = __rrr_http_server_worker_initialize_response(worker_data, response_part)) != RRR_HTTP_OK) {
		goto out;
	}

	if (worker_data->final_callback != NULL) {
		ret = worker_data->final_callback (
				worker_data->thread,
				handle,
				request_part,
				response_part,
				data_ptr,
				// Address was cached when accepting
				(const struct sockaddr *) &worker_data->sockaddr,
				worker_data->socklen,
				overshoot_bytes,
				unique_id,
				worker_data->final_callback_arg
		);
	}

	if (response_part->response_code == 0) {
		switch (ret) {
			case RRR_HTTP_OK:
				response_part->response_code = RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT;
				break;
			case RRR_HTTP_SOFT_ERROR:
				response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
				break;
			default:
				response_part->response_code = RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR;
				break;
		};
	}

	out:
	return ret;
}

static int __rrr_http_server_worker_net_transport_ctx_do_reading (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	int ret = 0;

	rrr_http_unique_id unique_id = 0;

	if (worker_data->unique_id_generator_callback != NULL) {
		if ((ret = worker_data->unique_id_generator_callback(
				&unique_id,
				worker_data->unique_id_generator_callback_arg
		)) != 0) {
			RRR_MSG_0("Failed to generate unique id in __rrr_http_server_worker_net_transport_ctx_do_reading\n");
			goto out;
		}
	}

	if ((ret = rrr_http_session_transport_ctx_receive (
			handle,
			RRR_HTTP_CLIENT_TIMEOUT_STALL_MS * 1000,
			RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS * 1000,
			worker_data->read_max_size,
			unique_id,
			__rrr_http_server_worker_http_session_receive_callback,
			worker_data,
			worker_data->final_callback_raw,
			worker_data->final_callback_raw_arg
	)) != 0) {
		if (ret != RRR_HTTP_SOFT_ERROR) {
			RRR_MSG_0("HTTP worker %i: Error while reading from client\n",
					worker_data->transport_handle);
		}
		goto out;
	}

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

	worker_data->read_max_size = worker_data_preliminary->read_max_size;
	worker_data->transport = worker_data_preliminary->transport;
	worker_data->transport_handle = worker_data_preliminary->transport_handle;
	worker_data->sockaddr = worker_data_preliminary->sockaddr;
	worker_data->socklen = worker_data_preliminary->socklen;

	worker_data->final_callback = worker_data_preliminary->final_callback;
	worker_data->final_callback_arg = worker_data_preliminary->final_callback_arg;

	worker_data->unique_id_generator_callback = worker_data_preliminary->unique_id_generator_callback;
	worker_data->unique_id_generator_callback_arg = worker_data_preliminary->unique_id_generator_callback_arg;

	worker_data->final_callback_raw = worker_data_preliminary->final_callback_raw;
	worker_data->final_callback_raw_arg = worker_data_preliminary->final_callback_raw_arg;

	return 0;
}

static void __rrr_http_server_worker_thread_entry (
		struct rrr_thread *thread
) {
	// DO NOT use private_data except from inside lock wrapper callback

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

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

//	char buf[256];
//	rrr_ip_to_str(buf, sizeof(buf), (struct sockaddr *) &worker_data.sockaddr, worker_data.socklen);
//	printf("http worker start: %s family %i socklen %i\n", buf, worker_data.sockaddr.ss_family, worker_data.socklen);

	// This might happen upon server shutdown
	if (worker_data.transport_handle == 0) {
		goto out;
	}

	worker_data.thread = thread;

	// All usage of private data pointer (http_session) of the transport handle
	// must be done with net transport handle lock held.

	// The transport handle integer is always
	// usable, even if the handle it points to has been freed. The lock wrapper
	// function in net transport will fail if the handle has been freed, this means
	// that the HTTP session has also been freed.

	pthread_cleanup_push(__rrr_http_server_worker_close_transport, &worker_data);

	RRR_DBG_8("HTTP worker thread %p started worker %i\n", thread, worker_data.transport_handle);

	while (rrr_thread_check_encourage_stop(thread) == 0) {
		rrr_thread_update_watchdog_time(thread);

		int ret_tmp = 0;
		if ((ret_tmp = rrr_net_transport_handle_with_transport_ctx_do (
				worker_data.transport,
				worker_data.transport_handle,
				__rrr_http_server_worker_net_transport_ctx_do_reading,
				&worker_data
		)) != 0) {
			if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
				RRR_DBG_2("HTTP worker %i: Failed while working with client, soft error\n",
						worker_data.transport_handle);
			}
			else {
				RRR_MSG_0("HTTP worker %i: Failed while working with client, hard error\n",
						worker_data.transport_handle);
			}
			break;
		}

		if (worker_data.request_complete) {
			break;
		}

		rrr_posix_usleep(1000);
	}

	RRR_DBG_8("HTTP worker thread %p exiting worker %i\n", thread, worker_data.transport_handle);

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
