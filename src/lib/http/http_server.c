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

#include "../log.h"

#include "http_common.h"
#include "http_server.h"
#include "http_session.h"
#include "http_util.h"
#include "http_server_worker.h"

#include "../threads.h"
#include "../net_transport/net_transport.h"
#include "../net_transport/net_transport_config.h"
//#include "../ip_util.h"

void rrr_http_server_destroy (struct rrr_http_server *server) {
	rrr_thread_stop_and_join_all_no_unlock (
			server->threads
	);
	rrr_thread_destroy_collection(server->threads);

	if (server->transport_http != NULL) {
		rrr_net_transport_destroy(server->transport_http);
	}
	if (server->transport_https != NULL) {
		rrr_net_transport_destroy(server->transport_https);
	}

	free(server);
}

void rrr_http_server_destroy_void (void *server) {
	rrr_http_server_destroy(server);
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

static int __rrr_http_server_start (
		struct rrr_net_transport **result_transport,
		uint16_t port,
		const struct rrr_net_transport_config *net_transport_config,
		int net_transport_flags
) {
	int ret = 0;

	if (*result_transport != NULL) {
		RRR_BUG("BUG: Double call to __rrr_http_server_start, pointer already set\n");
	}

	if ((ret = rrr_net_transport_new (result_transport, net_transport_config, net_transport_flags, NULL, 0)) != 0) {
		RRR_MSG_0("Could not create HTTP transport in __rrr_http_server_start return was %i\n", ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_net_transport_bind_and_listen_dualstack (
			*result_transport,
			port,
			NULL,
			NULL
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

	ret = __rrr_http_server_start (&server->transport_http, port, &net_transport_config_plain, 0);

	return ret;
}

int rrr_http_server_start_tls (
		struct rrr_http_server *server,
		uint16_t port,
		const struct rrr_net_transport_config *net_transport_config_template,
		int net_transport_flags
) {
	int ret = 0;

	struct rrr_net_transport_config net_transport_config_tls = *net_transport_config_template;

	net_transport_config_tls.transport_type = RRR_NET_TRANSPORT_TLS;

	ret = __rrr_http_server_start (&server->transport_https, port, &net_transport_config_tls, net_transport_flags);

	return ret;
}

static void __rrr_http_server_accept_create_http_session_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	struct rrr_http_server_worker_preliminary_data *worker_data_preliminary = arg;

	worker_data_preliminary->error = 0;

	struct rrr_http_application *application = NULL;

	if (rrr_http_application_new(
			&application,
			RRR_HTTP_APPLICATION_HTTP1,
			1 // Is server
	) != 0) {
		RRR_MSG_0("Could not create HTTP application in __rrr_http_server_accept_create_http_session_callback\n");
		worker_data_preliminary->error = 1;
		goto out;
	}

	if (rrr_http_session_transport_ctx_server_new (&application, handle) != 0) {
		RRR_MSG_0("Could not create HTTP session in __rrr_http_server_accept_create_http_session_callback\n");
		worker_data_preliminary->error = 1;
		goto out;
	}

/*	char buf[256];
	rrr_ip_to_str(buf, sizeof(buf), sockaddr, socklen);
	printf("accepted from %s family %i\n", buf, sockaddr->sa_family);*/

	// DO NOT STORE HANDLE POINTER

	worker_data_preliminary->config_data.transport = handle->transport;
	worker_data_preliminary->config_data.transport_handle = handle->handle;

	if (socklen > sizeof(worker_data_preliminary->config_data.addr)) {
		RRR_BUG("BUG: Socklen too long in __rrr_http_server_accept_create_http_session_callback\n");
	}

	memcpy(&worker_data_preliminary->config_data.addr, sockaddr, socklen);
	worker_data_preliminary->config_data.addr_len = socklen;

	out:
	rrr_http_application_destroy_if_not_null(&application);
	return;
}

static int __rrr_http_server_accept (
		int *did_accept,
		struct rrr_net_transport *transport,
		struct rrr_http_server_worker_preliminary_data *worker_data_preliminary
) {
	int ret = 0;

	*did_accept = 0;

	if ((ret = rrr_net_transport_accept_all_handles(
			transport,
			__rrr_http_server_accept_create_http_session_callback,
			worker_data_preliminary
	)) != 0) {
		RRR_MSG_0("Error from accept() in __rrr_http_server_accept_read_write\n");
		ret = 1;
		goto out;
	}

	if (worker_data_preliminary->config_data.transport_handle != 0) {
		*did_accept = 1;
	}

	out:
	return ret | worker_data_preliminary->error;
}

struct rrr_http_server_accept_if_free_thread_callback_data {
	struct rrr_net_transport *transport;
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

	// Thread is locked by iterator

	struct rrr_http_server_accept_if_free_thread_callback_data *callback_data = arg;

	int did_accept = 0;

	if (callback_data->result_thread_to_start != NULL) {
		RRR_BUG("BUG: thread to start pointer was not NULL in __rrr_http_server_accept_if_free_thread_callback\n");
	}

	if ((ret = __rrr_http_server_accept (
			&did_accept,
			callback_data->transport,
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
		struct rrr_thread_collection *threads
) {
	int ret = 0;

	struct rrr_http_server_accept_if_free_thread_callback_data callback_data = {
			transport,
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
			rrr_thread_set_signal(callback_data.result_thread_to_start, RRR_THREAD_SIGNAL_START_BEFOREFORK);
			rrr_thread_set_signal(callback_data.result_thread_to_start, RRR_THREAD_SIGNAL_START_AFTERFORK);
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
		struct rrr_thread_collection *threads,
		int count,
		const struct rrr_http_server_callbacks *callbacks
) {
	int ret = 0;

	struct rrr_http_server_worker_preliminary_data *worker_data = NULL;

	// Times two because we need to count the watchdogs
	int to_allocate = (count * 2) - rrr_thread_collection_count(threads);
	for (int i = 0; i < to_allocate; i++) {
		if ((ret = rrr_http_server_worker_preliminary_data_new (
				&worker_data,
				callbacks
		)) != 0) {
			RRR_MSG_0("Could not allocate worker thread data in __rrr_http_server_allocate_threads\n");
			goto out;
		}

		struct rrr_thread *thread = rrr_thread_allocate_preload_and_register (
				threads,
				rrr_http_server_worker_thread_entry_intermediate,
				NULL,
				NULL,
				NULL,
				"httpserver_worker",
				RRR_HTTP_SERVER_WORKER_THREAD_WATCHDOG_TIMER_MS * 1000,
				worker_data
		);

		if (thread == NULL) {
			RRR_MSG_0("Could create thread in __rrr_http_server_allocate_threads\n");
			goto out;
		}

		worker_data = NULL; // Now managed by worker thread

		if ((ret = rrr_thread_start(thread)) != 0) {
			// Unsafe state of worker_data struct
			RRR_BUG("Could not start thread in __rrr_http_server_allocate_threads, cannot recover from this.\n");
		}
	}

	out:
	if (worker_data != NULL) {
		rrr_http_server_worker_preliminary_data_destroy_if_not_null(worker_data);
	}
	return ret;
}

int rrr_http_server_tick (
		int *accept_count_final,
		struct rrr_http_server *server,
		int max_threads,
		const struct rrr_http_server_callbacks *callbacks
) {
	int ret = 0;

	*accept_count_final = 0;

	if ((ret = __rrr_http_server_allocate_threads (
			server->threads,
			max_threads,
			callbacks
	)) != 0) {
		RRR_MSG_0("Could not allocate threads in rrr_http_server_tick\n");
		goto out;
	}

	int accept_count = 0;

	if (server->transport_http != NULL) {
		int accept_count_tmp = 0;
		if ((ret = __rrr_http_server_accept_if_free_thread (
				&accept_count_tmp,
				server->transport_http,
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
				server->threads
		)) != 0) {
			goto out;
		}
		accept_count += accept_count_tmp;
	}

	int count;
	rrr_thread_join_and_destroy_stopped_threads(&count, server->threads);

	*accept_count_final = accept_count;

	out:
	return ret;
}
