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

#include "http_server_worker.h"
#include "http_common.h"
#include "http_session.h"
#include "http_part.h"

#include "../net_transport/net_transport.h"
#include "../threads.h"
#include "../log.h"
#include "../posix.h"

int rrr_http_server_worker_preliminary_data_new (
		struct rrr_http_server_worker_preliminary_data **result
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

	if (pthread_mutex_init(&data->lock, NULL) != 0) {
		RRR_MSG_0("Could not initialize mutex in __rrr_http_server_worker_thread_data_new\n");
		ret = 1;
		goto out_free;
	}

	*result = data;

	goto out;
	out_free:
		free(data);
	out:
		return ret;
}

void rrr_http_server_worker_preliminary_data_destroy (
		struct rrr_http_server_worker_preliminary_data *worker_data
) {
	if (worker_data == NULL) {
		return;
	}
	pthread_mutex_destroy(&worker_data->lock);
	free(worker_data);
}

void rrr_http_server_worker_preliminary_data_destroy_void (
		void *arg
) {
	rrr_http_server_worker_preliminary_data_destroy(arg);
}

static void __rrr_net_http_server_worker_close_transport (
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;
	rrr_net_transport_handle_close_tag_list_push(worker_data->transport, worker_data->transport_handle);
}

static int __rrr_net_http_server_worker_http_session_receive_callback (
		struct rrr_http_part *part,
		const char *data_ptr,
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;

//	printf("In HTTP worker receive callback\n");

	RRR_DBG_2("HTTP worker %i: %s %s HTTP/1.1\n",
			worker_data->transport_handle, part->request_method_str, part->request_uri);

	worker_data->receive_complete = 1;
	worker_data->response_code = RRR_HTTP_RESPONSE_CODE_OK_NO_CONTENT;

	return 0;
}

static int __rrr_net_http_server_worker_net_transport_ctx_do_reading (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;
//	struct http_session_data *session = handle->application_private_ptr;

	int ret = 0;

	if ((ret = rrr_http_session_transport_ctx_receive (
			handle,
			RRR_HTTP_CLIENT_TIMEOUT_STALL_MS * 1000,
			RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS * 1000,
			worker_data->read_max_size,
			__rrr_net_http_server_worker_http_session_receive_callback,
			worker_data
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

static int __rrr_net_http_server_worker_net_transport_ctx_send_response (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_server_worker_data *worker_data = arg;

	// We allow send_response to be called as long as transpoort handle is OK,
	// but the response part must have been initialized for us to be able to
	// send a response. If it is NULL, we cannot send a response.
	if (!rrr_http_session_transport_ctx_check_response_part_initilized(handle)) {
		RRR_DBG_3("HTTP worker %i: No HTTP parts initialized, not sending response\n", worker_data->transport_handle);
		return 0;
	}

	// If client has not sent any data, don't send a response
	if (!rrr_http_session_transport_ctx_check_data_received(handle)) {
		RRR_DBG_3("HTTP worker %i: No HTTP request from client, not sending response\n", worker_data->transport_handle);
		return 0;
	}

	if (worker_data->response_code == 0) {
		RRR_MSG_0("HTTP worker %i: No response code was set in __rrr_net_http_server_worker_net_transport_ctx_send_response, sending 500 to client.\n",
				worker_data->transport_handle);
		worker_data->response_code = 500;
	}

	if (rrr_http_session_transport_ctx_set_response_code(handle, worker_data->response_code) != 0) {
		RRR_MSG_0("HTTP worker %i: Could not set response code in __rrr_net_http_server_worker_net_transport_ctx_send_response\n",
				worker_data->transport_handle);
		return 1;
	}

	RRR_DBG_2("HTTP worker %i: Sending response %lu\n",
			worker_data->transport_handle, worker_data->response_code);

	return rrr_http_session_transport_ctx_send_response(handle);
}

void *rrr_http_server_worker_thread_entry (
		struct rrr_thread *thread
) {
	struct rrr_http_server_worker_preliminary_data *worker_data_preliminary = thread->private_data;

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	struct rrr_http_server_worker_data worker_data = {0};

	// There is no more communication with main thread over this struct after this point.
	// Copy the data to a local struct. Pointer to main transport will always
	// be valid, main thread will not destroy it before threads have shut down.
	// The lock only protects the data members of the worker data struct, not
	// what they point to. DO NOT have members like char * in the struct.
	pthread_mutex_lock(&worker_data_preliminary->lock);
	worker_data.read_max_size = worker_data_preliminary->read_max_size;
	worker_data.transport = worker_data_preliminary->transport;
	worker_data.transport_handle = worker_data_preliminary->transport_handle;
	pthread_mutex_unlock(&worker_data_preliminary->lock);

	// This might happen upon server shutdown
	if (worker_data.transport_handle == 0) {
		goto out;
	}

	// All usage of private data pointer (http_session) of the transport handle
	// must be done with net transport handle lock held.

	// The transport handle integer is always
	// usable, even if the handle it points to has been freed. The lock wrapper
	// function in net transport will fail if the handle has been freed, this means
	// that the HTTP session has also been freed.

	pthread_cleanup_push(__rrr_net_http_server_worker_close_transport, &worker_data);

	RRR_DBG_8("HTTP worker thread %p started worker %i\n", thread, worker_data.transport_handle);

	while (rrr_thread_check_encourage_stop(thread) == 0) {
		rrr_thread_update_watchdog_time(thread);

		int ret_tmp = 0;
		if ((ret_tmp = rrr_net_transport_handle_with_transport_ctx_do (
				worker_data.transport,
				worker_data.transport_handle,
				__rrr_net_http_server_worker_net_transport_ctx_do_reading,
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

		if (worker_data.receive_complete) {
			break;
		}

		rrr_posix_usleep(1000);
	}

	// Always try to send response (if response part is initialized)
	if (rrr_net_transport_handle_with_transport_ctx_do (
			worker_data.transport,
			worker_data.transport_handle,
			__rrr_net_http_server_worker_net_transport_ctx_send_response,
			&worker_data
	) != 0) {
		RRR_MSG_0("Failed while sending response to HTTP client in thread %p\n", thread);
		break;
	}

	RRR_DBG_8("HTTP worker thread %p exiting worker %i\n", thread, worker_data.transport_handle);

	// This cleans up HTTP data
	pthread_cleanup_pop(1);

	out:
	pthread_exit(0);
}
