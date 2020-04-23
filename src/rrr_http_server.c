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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "global.h"
#include "main.h"
#include "lib/common.h"
#include "../build_timestamp.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/rrr_socket.h"
#include "lib/rrr_socket_read.h"
#include "lib/http_session.h"
#include "lib/http_part.h"
#include "lib/http_util.h"
#include "lib/threads.h"
#include "lib/vl_time.h"
#include "lib/ip.h"
#include "lib/rrr_strerror.h"
#include "lib/gnu.h"
#include "lib/random.h"

#define RRR_HTTP_SERVER_USER_AGENT "RRR/" PACKAGE_VERSION
#define RRR_HTTP_SERVER_WORKER_THREADS 10

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'p',	"port",					"[-p|--port[=]HTTP PORT]"},
		{0,							'P',	"plain-disable",		"[-P|--plain-disable]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	's',	"ssl-port",				"[-s|--ssl-port[=]HTTPS PORT]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'c',	"cerficicate",			"[-c|--certificate[=]PEM SSL CERTIFICATE]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'k',	"key",					"[-k|--key[=]PEM SSL PRIVATE KEY]"},
		{0,							'N',	"no-cert-verify",		"[-N|--no-cert-verify]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_http_server_data {
	char *certificate_file;
	char *private_key_file;
	uint16_t http_port;
	uint16_t https_port;
	int ssl_no_cert_verify;
	int plain_disable;
	struct rrr_http_session *session;
};

/*
struct rrr_http_server_response {
	int code;
	char *argument;
};

static void __rrr_http_server_response_cleanup (struct rrr_http_server_response *response) {
	RRR_FREE_IF_NOT_NULL(response->argument);
	response->code = 0;
}
*/

static void __rrr_http_server_data_init (struct rrr_http_server_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_http_server_data_cleanup (struct rrr_http_server_data *data) {
	RRR_FREE_IF_NOT_NULL(data->certificate_file);
	RRR_FREE_IF_NOT_NULL(data->private_key_file);
	if (data->session != NULL) {
		rrr_http_session_destroy(data->session);
	}
}

static int __rrr_http_server_parse_config (struct rrr_http_server_data *data, struct cmd_data *cmd) {
	int ret = 0;

	// Certificate file
	const char *certificate = cmd_get_value(cmd, "certificate", 0);
	if (cmd_get_value (cmd, "certificate", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one certificate argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (certificate != NULL) {
		data->certificate_file = strdup(certificate);
		if (data->certificate_file == NULL) {
			RRR_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// Private key file
	const char *key = cmd_get_value(cmd, "key", 0);
	if (cmd_get_value (cmd, "key", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one key argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (key != NULL) {
		data->private_key_file = strdup(key);
		if (data->private_key_file == NULL) {
			RRR_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// No plain method
	if (cmd_exists(cmd, "plain-disable", 0)) {
		data->plain_disable = 1;
	}

	// No certificate verification
	if (cmd_exists(cmd, "no-cert-verify", 0)) {
		data->ssl_no_cert_verify = 1;
	}

	// Consistency check
	if ((data->certificate_file == NULL || *(data->certificate_file) == '\0') && (data->private_key_file != NULL && *(data->private_key_file) != '\0')) {
		RRR_MSG_ERR("Private key was specified but certificate was not, please check arguments.\n");
		ret = 1;
		goto out;
	}

	if ((data->private_key_file == NULL || *(data->private_key_file) == '\0') && (data->certificate_file != NULL && *(data->certificate_file) != '\0')) {
		RRR_MSG_ERR("Certificate was specified but private key was not, please check arguments.\n");
		ret = 1;
		goto out;
	}

	// HTTP port
	const char *port = cmd_get_value(cmd, "port", 0);
	uint64_t port_tmp = 0;
	if (cmd_get_value (cmd, "port", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one 'port' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			RRR_MSG_ERR("Could not understand argument 'port', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp == 0) {
		port_tmp = 80;
	}
	if (port_tmp < 1 || port_tmp > 65535) {
		RRR_MSG_ERR("HTTP port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->http_port = port_tmp;

	// HTTPS port
	port = cmd_get_value(cmd, "ssl-port", 0);
	port_tmp = 0;
	if (cmd_get_value (cmd, "ssl-port", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one 'ssl-port' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			RRR_MSG_ERR("Could not understand argument 'ssl-port', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp == 0) {
		port_tmp = 443;
	}
	if (port_tmp < 1 || port_tmp > 65535) {
		RRR_MSG_ERR("HTTPS out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->https_port = port_tmp;

	out:
	return ret;
}

static int __rrr_http_server_bind_and_listen (int *handle, struct rrr_net_transport *transport, uint16_t port) {
	int ret = 0;
	if ((ret = rrr_net_transport_bind_and_listen(handle, transport, port)) != 0) {
		RRR_MSG_ERR("Could not listen on port %u\n", port);
		goto out;
	}
	out:
	return ret;
}

struct rrr_http_server_worker_thread_data {
	pthread_mutex_t lock;
	struct rrr_net_transport *transport;
	int transport_handle;
};

static int __rrr_http_server_accept (
		int *did_accept,
		struct rrr_net_transport *transport,
		int handle,
		struct rrr_http_server_worker_thread_data *worker_data
) {
	int ret = 0;
	int new_handle = 0;
	struct rrr_sockaddr sockaddr;
	socklen_t socklen = sizeof(sockaddr);

	*did_accept = 0;

	if ((ret = rrr_net_transport_accept(&new_handle, (struct sockaddr *) &sockaddr, &socklen, transport, handle)) != 0) {
		RRR_MSG_ERR("Error from accept() in __rrr_http_server_accept_read_write\n");
		ret = 1;
		goto out;
	}
	else if (new_handle != 0) {
		// HTTP session data must be protected by lock to provide memory fence
		pthread_mutex_lock(&worker_data->lock);

		RRR_DBG_1("Accepted a connection\n");
		if (rrr_http_session_server_new_and_register_with_transport (
				transport,
				new_handle
		) != 0) {
			RRR_MSG_ERR("Could not create HTTP session in __rrr_http_server_accept_read_write\n");
			ret = 1;
		}
		else {
			worker_data->transport = transport;
			worker_data->transport_handle = new_handle;
		}

		*did_accept = 1;

		pthread_mutex_unlock(&worker_data->lock);

		if (ret != 0) {
			goto out;
		}
	}
	else {
		goto out;
	}


	out:
	return ret;
}

struct rrr_http_server_accept_if_free_thread_callback_data {
	struct rrr_net_transport *transport;
	int transport_handle;
	struct rrr_thread *result_thread_to_start;
};

static int __rrr_http_server_accept_if_free_thread_callback (
		struct rrr_thread *locked_thread,
		void *arg
) {
	int ret = 0;

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
		RRR_MSG_ERR("Error from accept() in __rrr_http_server_accept_if_free_thread_callback\n");
		ret = 1;
		goto out;
	}

	if (did_accept) {
		callback_data->result_thread_to_start = locked_thread;
		ret = 2; // IMPORTANT, MUST SKIP OUT OF ITERATION TO START THREAD IN CALLER
	}

	out:
	return ret;
}

static int __rrr_http_server_accept_if_free_thread (
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

	if ((ret = rrr_thread_iterate_by_state (
			threads,
			RRR_THREAD_STATE_INITIALIZED,
			__rrr_http_server_accept_if_free_thread_callback,
			&callback_data
	)) != 0) {
		if (ret == 2) {
			if (callback_data.result_thread_to_start == NULL) {
				RRR_BUG("BUG: Broke out of iteration but result thread was still NULL in __rrr_http_server_accept_if_free_thread\n");
			}
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Error while accepting connections\n");
			ret = 1;
			goto out;
		}
	}

	// Thread is locked in callback so we must start it here outside the iteration
	if (callback_data.result_thread_to_start != NULL) {
		rrr_thread_set_signal(callback_data.result_thread_to_start, RRR_THREAD_SIGNAL_START);
	}

	out:
	return ret;
}

int __rrr_http_server_worker_thread_data_new (struct rrr_http_server_worker_thread_data **result) {
	int ret = 0;

	*result = NULL;

	struct rrr_http_server_worker_thread_data *data = malloc(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_http_server_worker_thread_data_new\n");
		ret = 1;
		goto out;
	}

	memset (data, '\0', sizeof(*data));

	if (pthread_mutex_init(&data->lock, NULL) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in __rrr_http_server_worker_thread_data_new\n");
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

void __rrr_http_server_worker_thread_data_destroy (struct rrr_http_server_worker_thread_data *worker_data) {
	if (worker_data == NULL) {
		return;
	}
	pthread_mutex_destroy(&worker_data->lock);
	free(worker_data);
}

void __rrr_http_server_worker_thread_data_destroy_void (void *private_data) {
	struct rrr_http_server_worker_thread_data *worker_data = private_data;

	__rrr_http_server_worker_thread_data_destroy(worker_data);
}

static void *__rrr_http_server_worker_thread_entry (struct rrr_thread *thread) {
	struct rrr_http_server_worker_thread_data *worker_data = thread->private_data;

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait_with_watchdog_update(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	int loops = rrr_rand() % 5;

	while (--loops > 0) {
		rrr_thread_update_watchdog_time(thread);

		usleep (2000000);
		printf ("Worker thread %p in loop\n", thread);
	}

	printf ("Worker thread %p exiting\n", thread);

	pthread_exit(0);
}

void __rrr_http_server_ghost_handler (struct rrr_thread *thread) {
	thread->free_private_data_by_ghost = 1;
}

static int __rrr_http_server_allocate_threads (struct rrr_thread_collection *threads) {
	int ret = 0;

	struct rrr_http_server_worker_thread_data *worker_data = NULL;

	int to_allocate = RRR_HTTP_SERVER_WORKER_THREADS - rrr_thread_collection_count(threads);
	for (int i = 0; i < to_allocate; i++) {
		if ((ret = __rrr_http_server_worker_thread_data_new(&worker_data)) != 0) {
			RRR_MSG_ERR("Could not allocate worker thread data in __rrr_http_server_allocate_threads\n");
			goto out;
		}

		struct rrr_thread *thread = rrr_thread_preload_and_register (
				threads,
				__rrr_http_server_worker_thread_entry,
				NULL,
				NULL,
				NULL,
				__rrr_http_server_worker_thread_data_destroy_void,
				RRR_THREAD_START_PRIORITY_NORMAL,
				worker_data,
				"worker"
		);

		if (thread == NULL) {
			RRR_MSG_ERR("Could create thread in __rrr_http_server_allocate_threads\n");
			goto out;
		}

		worker_data = NULL; // Now managed by thread framework

		if ((ret = rrr_thread_start(thread)) != 0) {
			RRR_MSG_ERR("Could not start thread in __rrr_http_server_allocate_threads\n");
			goto out;
		}
	}

	out:
	if (worker_data != NULL) {
		__rrr_http_server_worker_thread_data_destroy(worker_data);
	}
	return ret;
}

static int main_running = 1;
int rrr_http_server_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		RRR_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	rrr_strerror_init();

	int ret = EXIT_SUCCESS;

	int count = 0;
	struct cmd_data cmd;
	struct rrr_http_server_data data;
	struct rrr_signal_handler *signal_handler = NULL;

	struct rrr_thread_collection *threads = NULL;
	if (rrr_thread_new_collection(&threads) != 0) {
		RRR_MSG_ERR("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	struct rrr_net_transport *transport_http = NULL;
	struct rrr_net_transport *transport_https = NULL;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_http_server_data_init(&data);

	struct rrr_signal_functions signal_functions = {
			rrr_signal_handler_set_active,
			rrr_signal_handler_push,
			rrr_signal_handler_remove
	};

	signal_handler = signal_functions.push_handler(rrr_http_server_signal_handler, NULL);

	if ((ret = main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out;
	}

	if (rrr_print_help_and_version(&cmd, 0) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_server_parse_config(&data, &cmd)) != 0) {
		goto out;
	}

	int http_handle = 0;
	int https_handle = 0;

	if (data.plain_disable != 1) {
		if ((ret = rrr_net_transport_new(&transport_http, RRR_NET_TRANSPORT_PLAIN, 0, NULL, NULL)) != 0) {
			RRR_MSG_ERR("Could not create HTTP transport\n");
			goto out;
		}

		if ((ret = __rrr_http_server_bind_and_listen (&http_handle, transport_http, data.http_port)) != 0) {
			goto out;
		}
	}

	if (data.certificate_file != NULL && data.private_key_file != NULL) {
		if ((ret = rrr_net_transport_new (
				&transport_https,
				RRR_NET_TRANSPORT_TLS,
				(data.ssl_no_cert_verify ? RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY : 0),
				data.certificate_file,
				data.private_key_file
		)) != 0) {
			RRR_MSG_ERR("Could not create HTTPS transport\n");
			goto out;
		}

		if ((ret = __rrr_http_server_bind_and_listen (&https_handle, transport_https, data.https_port)) != 0) {
			goto out;
		}
	}

	if (transport_http == NULL && transport_https == NULL) {
		RRR_MSG_ERR("Neither HTTP or HTTPS are active, check arguments.\n");
		ret = 1;
		goto out;
	}

	signal_functions.set_active(RRR_SIGNALS_ACTIVE);
	rrr_signal_default_signal_actions_register();

	while (main_running) {
		rrr_thread_join_and_destroy_stopped_threads(&count, threads, 1);
		if (count > 0) {
			RRR_DBG_1("Destroyed %i threads which was complete\n", count);
		}

		rrr_thread_run_ghost_cleanup(&count);
		if (count > 0) {
			RRR_DBG_1("Cleaned up after %i ghost threads\n", count);
		}

		if ((ret = __rrr_http_server_allocate_threads(threads)) != 0) {
			RRR_MSG_ERR("Could not allocate threads\n");
			break;
		}

		if (transport_http != NULL) {
			if (__rrr_http_server_accept_if_free_thread(transport_http, http_handle, threads) != 0) {
				break;
			}
		}
		if (transport_https != NULL) {
			if (__rrr_http_server_accept_if_free_thread(transport_https, https_handle, threads) != 0) {
				break;
			}
		}

		usleep(500);
	}

	out:
	rrr_set_debuglevel_on_exit();

	if (threads != NULL) {
		rrr_thread_stop_and_join_all (
				threads,
				__rrr_http_server_ghost_handler
		);
		rrr_thread_destroy_collection(threads, 1);
	}

	rrr_thread_run_ghost_cleanup(&count);
	RRR_DBG_1("Cleaned up after %i ghost threads\n", count);

	rrr_signal_handler_remove(signal_handler);

	if (transport_http != NULL) {
		rrr_net_transport_destroy(transport_http);
	}
	if (transport_https != NULL) {
		rrr_net_transport_destroy(transport_https);
	}

	__rrr_http_server_data_cleanup(&data);

	cmd_destroy(&cmd);

	rrr_socket_close_all();

	rrr_strerror_cleanup();

	return ret;
}
