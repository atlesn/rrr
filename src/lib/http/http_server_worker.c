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

int rrr_http_server_worker_thread_data_new (
		struct rrr_http_server_worker_thread_data **result
) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_server_worker_thread_data *data = malloc(sizeof(*data));
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

void rrr_http_server_worker_thread_data_destroy (
		struct rrr_http_server_worker_thread_data *worker_data
) {
	if (worker_data == NULL) {
		return;
	}
	pthread_mutex_destroy(&worker_data->lock);
	free(worker_data);
}

void rrr_http_server_worker_thread_data_destroy_void (
		void *private_data
) {
	struct rrr_http_server_worker_thread_data *worker_data = private_data;

	rrr_http_server_worker_thread_data_destroy(worker_data);
}

static void __rrr_net_http_server_worker_close_transport (
		void *arg
) {
	struct rrr_http_server_worker_thread_data *worker_data = arg;

	rrr_net_transport_handle_close(worker_data->transport, worker_data->transport_handle);
}

static int __rrr_net_http_server_worker_http_session_receive_callback (
		struct rrr_http_part *part,
		const char *data_ptr,
		void *arg
) {
	return 0;
}

static int __rrr_net_http_server_worker_net_transport_ctx_do_work (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	struct rrr_http_server_worker_thread_data *worker_data = arg;
//	struct http_session_data *session = handle->application_private_ptr;

	int ret = 0;

	if ((ret = rrr_http_session_transport_ctx_receive (
			handle,
			RRR_HTTP_CLIENT_TIMEOUT_STALL_MS * 1000,
			RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS * 1000,
			__rrr_net_http_server_worker_http_session_receive_callback,
			worker_data
	)) != 0) {
		RRR_MSG_0("Error while reading from HTTP client\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

void *rrr_http_server_worker_thread_entry (
		struct rrr_thread *thread
) {
	struct rrr_http_server_worker_thread_data *worker_data_preliminary = thread->private_data;

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	struct rrr_http_server_worker_thread_data worker_data;

	// There is no more communication with main thread over this struct after this point.
	// Make a copy and invalidate the lock. Pointer to main transport will always
	// be valid, main thread will not destroy it before threads have shut down.
	// This lock only protects the data members of the worker data struct, not
	// what they point to.
	pthread_mutex_lock(&worker_data_preliminary->lock);
	worker_data = *worker_data_preliminary;
	pthread_mutex_unlock(&worker_data_preliminary->lock);
	memset (&worker_data.lock, '\0', sizeof(worker_data.lock));

	// This might happen upon server shutdown
	if (worker_data.transport_handle == 0) {
		goto out;
	}

	// All usage of private data pointer (http_session) of work_data must be done
	// with net transport handle lock held. The transport handle integer is always
	// usable, even if the handle it points to has been freed. The lock wrapper
	// function in net transport will fail if the handle has been freed, this means
	// that the HTTP session has also been freed.

	pthread_cleanup_push(__rrr_net_http_server_worker_close_transport, &worker_data);

	while (rrr_thread_check_encourage_stop(thread) == 0) {
		rrr_thread_update_watchdog_time(thread);

		if (rrr_net_transport_handle_with_transport_ctx_do (
				worker_data.transport,
				worker_data.transport_handle,
				__rrr_net_http_server_worker_net_transport_ctx_do_work,
				&worker_data
		) != 0) {
			RRR_MSG_0("Failed while working with HTTP client in thread %p\n", thread);
			break;
		}

		rrr_posix_usleep(1000);
	}

	RRR_DBG_1("HTTP Worker thread %p exiting\n", thread);

	// This cleans up HTTP data
	pthread_cleanup_pop(1);

	out:
	pthread_exit(0);
}
