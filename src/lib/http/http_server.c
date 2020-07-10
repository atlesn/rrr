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

#include "http_common.h"
#include "http_server.h"
#include "http_session.h"
#include "http_util.h"
#include "http_server_worker.h"

#include "../log.h"
#include "../threads.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"

static void __rrr_http_server_ghost_handler (struct rrr_thread *thread) {
	thread->free_private_data_by_ghost = 1;
}

void rrr_http_server_destroy (struct rrr_http_server *server) {
	rrr_thread_stop_and_join_all (
			server->threads,
			__rrr_http_server_ghost_handler
	);
	rrr_thread_destroy_collection(server->threads, 1);

	if (server->transport_http != NULL) {
		rrr_net_transport_destroy(server->transport_http);
	}
	if (server->transport_https != NULL) {
		rrr_net_transport_destroy(server->transport_https);
	}

	free(server);
}

int rrr_http_server_new (struct rrr_http_server **target) {
	int ret = 0;

	*target = NULL;

	struct rrr_http_server *server = malloc(sizeof(*server));
	if (server == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http_server_new\n");
		ret = 1;
		goto out;
	}

	memset(server, '\0', sizeof(*server));

	if (rrr_thread_new_collection(&server->threads) != 0) {
		RRR_MSG_0("Could not create thread collection in rrr_http_server_new\n");
		ret = 1;
		goto out_free;
	}

	*target = server;
	server = NULL;

	goto out;
	out_free:
		free(server);
	out:
		return ret;
}

static void __rrr_http_server_bind_and_listen_callback (
		struct rrr_net_transport_handle *handle,
		void *arg
) {
	int *transport_handle = arg;
	*transport_handle = handle->handle;
}

static int __rrr_http_server_start (
		int *result_handle,
		struct rrr_net_transport **result_transport,
		uint16_t port,
		const struct rrr_net_transport_config *net_transport_config
) {
	int ret = 0;

	if (*result_transport != NULL) {
		RRR_BUG("BUG: Double call to __rrr_http_server_start, pointer already set\n");
	}

	if ((ret = rrr_net_transport_new (result_transport, net_transport_config, 0)) != 0) {
		RRR_MSG_0("Could not create HTTP transport in __rrr_http_server_start \n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_bind_and_listen (
			*result_transport,
			port,
			__rrr_http_server_bind_and_listen_callback,
			result_handle
	)) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_http_server_start_plain (
		struct rrr_http_server *server,
		uint16_t port
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_plain = {
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			RRR_NET_TRANSPORT_PLAIN
	};

	ret = __rrr_http_server_start (&server->handle_http, &server->transport_http, port, &net_transport_config_plain);

	return ret;
}

int rrr_http_server_start_tls (
		struct rrr_http_server *server,
		uint16_t port,
		const struct rrr_net_transport_config *net_transport_config_template
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_tls = *net_transport_config_template;

	net_transport_config_tls.transport_type = RRR_NET_TRANSPORT_TLS;

	ret = __rrr_http_server_start (&server->handle_https, &server->transport_https, port, &net_transport_config_tls);

	return ret;
}

static void __rrr_http_server_accept_create_http_session_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	struct rrr_http_server_worker_thread_data *worker_data = arg;

	(void)(sockaddr);
	(void)(socklen);

	worker_data->error = 0;

	if (rrr_http_session_transport_ctx_server_new (
			handle
	) != 0) {
		RRR_MSG_0("Could not create HTTP session in __rrr_http_server_accept_read_write\n");
		worker_data->error = 1;
	}
	else {
		pthread_mutex_lock(&worker_data->lock);
		// DO NOT STORE HANDLE POINTER
		worker_data->transport = handle->transport;
		worker_data->transport_handle = handle->handle;
		pthread_mutex_unlock(&worker_data->lock);
	}
}

static int __rrr_http_server_accept (
		int *did_accept,
		struct rrr_net_transport *transport,
		int handle,
		struct rrr_http_server_worker_thread_data *worker_data
) {
	int ret = 0;

	*did_accept = 0;

	if ((ret = rrr_net_transport_accept (
			transport,
			handle,
			__rrr_http_server_accept_create_http_session_callback,
			worker_data
	)) != 0) {
		RRR_MSG_0("Error from accept() in __rrr_http_server_accept_read_write\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&worker_data->lock);
	if (worker_data->transport_handle != 0) {
		*did_accept = 1;
	}
	pthread_mutex_unlock(&worker_data->lock);

	out:
	return ret | worker_data->error;
}

struct rrr_http_server_accept_if_free_thread_callback_data {
	struct rrr_net_transport *transport;
	int transport_handle;
	struct rrr_thread *result_thread_to_start;
};

#define RRR_HTTP_SERVER_ACCEPT_OK			0
#define RRR_HTTP_SERVER_ACCEPT_ERR			1
#define RRR_HTTP_SERVER_ACCEPT_ACCEPTED		2

static int __rrr_http_server_accept_if_free_thread_callback (
		struct rrr_thread *locked_thread,
		void *arg
) {
	int ret = RRR_HTTP_SERVER_ACCEPT_OK;

	struct rrr_http_server_accept_if_free_thread_callback_data *callback_data = arg;

	int did_accept = 0;

	if (callback_data->result_thread_to_start != NULL) {
		RRR_BUG("BUG: thread to start pointer was not NULL in __rrr_http_server_accept_if_free_thread_callback\n");
	}

	if ((ret = __rrr_http_server_accept (
			&did_accept,
			callback_data->transport,
			callback_data->transport_handle,
			locked_thread->private_data
	)) != 0) {
		RRR_MSG_0("Error from accept() in __rrr_http_server_accept_if_free_thread_callback\n");
		ret = RRR_HTTP_SERVER_ACCEPT_ERR;
		goto out;
	}

	if (did_accept) {
		callback_data->result_thread_to_start = locked_thread;
		ret = RRR_HTTP_SERVER_ACCEPT_ACCEPTED; // IMPORTANT, MUST SKIP OUT OF ITERATION TO START THREAD IN CALLER
	}

	out:
	return ret;
}

static int __rrr_http_server_accept_if_free_thread (
		int *accept_count,
		struct rrr_net_transport *transport,
		int transport_handle,
		struct rrr_thread_collection *threads
) {
	int ret = 0;

	struct rrr_http_server_accept_if_free_thread_callback_data callback_data = {
			transport,
			transport_handle,
			NULL
	};

	*accept_count = 0;

	if ((ret = rrr_thread_iterate_non_wd_and_not_signalled_by_state (
			threads,
			RRR_THREAD_STATE_INITIALIZED,
			__rrr_http_server_accept_if_free_thread_callback,
			&callback_data
	)) != RRR_HTTP_SERVER_ACCEPT_OK) {
		if (ret == RRR_HTTP_SERVER_ACCEPT_ACCEPTED) {
			if (callback_data.result_thread_to_start == NULL) {
				RRR_BUG("BUG: Broke out of iteration but result thread was still NULL in __rrr_http_server_accept_if_free_thread\n");
			}

			// Thread is locked in callback so we must start it here outside the iteration
			// The thread which received the start signal will not be iterated again
			rrr_thread_set_signal(callback_data.result_thread_to_start, RRR_THREAD_SIGNAL_START);
			ret = 0;

			(*accept_count)++;
		}
		else {
			RRR_MSG_0("Error while accepting connections\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_http_server_allocate_threads (
		struct rrr_thread_collection *threads
) {
	int ret = 0;

	struct rrr_http_server_worker_thread_data *worker_data = NULL;

	int to_allocate = RRR_HTTP_SERVER_WORKER_THREADS - rrr_thread_collection_count(threads);
	for (int i = 0; i < to_allocate; i++) {
		if ((ret = rrr_http_server_worker_thread_data_new(&worker_data)) != 0) {
			RRR_MSG_0("Could not allocate worker thread data in __rrr_http_server_allocate_threads\n");
			goto out;
		}

		struct rrr_thread *thread = rrr_thread_preload_and_register (
				threads,
				rrr_http_server_worker_thread_entry,
				NULL,
				NULL,
				NULL,
				rrr_http_server_worker_thread_data_destroy_void,
				RRR_THREAD_START_PRIORITY_NORMAL,
				worker_data,
				"httpserver_worker"
		);

		if (thread == NULL) {
			RRR_MSG_0("Could create thread in __rrr_http_server_allocate_threads\n");
			goto out;
		}

		worker_data = NULL; // Now managed by thread framework

		if ((ret = rrr_thread_start(thread)) != 0) {
			RRR_MSG_0("Could not start thread in __rrr_http_server_allocate_threads\n");
			goto out;
		}
	}

	out:
	if (worker_data != NULL) {
		rrr_http_server_worker_thread_data_destroy(worker_data);
	}
	return ret;
}

int rrr_http_server_tick (
		int *accept_count_final,
		struct rrr_http_server *server
) {
	int ret = 0;

	*accept_count_final = 0;

	if ((ret = __rrr_http_server_allocate_threads(server->threads)) != 0) {
		RRR_MSG_0("Could not allocate threads in rrr_http_server_tick\n");
		goto out;
	}

	int accept_count = 0;

	if (server->transport_http != NULL) {
		int accept_count_tmp = 0;
		if ((ret = __rrr_http_server_accept_if_free_thread (
				&accept_count_tmp,
				server->transport_http,
				server->handle_http,
				server->threads
		)) != 0) {
			goto out;
		}
		accept_count += accept_count_tmp;
	}

	if (server->transport_https != NULL) {
		int accept_count_tmp = 0;
		if ((ret = __rrr_http_server_accept_if_free_thread (
				&accept_count_tmp,
				server->transport_https,
				server->handle_https,
				server->threads
		)) != 0) {
			goto out;
		}
		accept_count += accept_count_tmp;
	}

	int count;
	rrr_thread_join_and_destroy_stopped_threads(&count, server->threads, 1);

	*accept_count_final = accept_count;

	out:
	return ret;
}
