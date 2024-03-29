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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "../build_timestamp.h"
#include "main.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/common.h"
#include "lib/http/http_server.h"
#include "lib/net_transport/net_transport_config.h"
#include "lib/socket/rrr_socket.h"
#include "lib/version.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/event/event.h"
#include "lib/util/macro_utils.h"
#include "lib/util/rrr_time.h"

#define RRR_HTTP_SERVER_FIRST_DATA_TIMEOUT_MS  3000
#define RRR_HTTP_SERVER_IDLE_TIMEOUT_MS        RRR_HTTP_SERVER_FIRST_DATA_TIMEOUT_MS * 2
#define RRR_HTTP_SERVER_SEND_CHUNK_COUNT_LIMIT 100000

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_http_server");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'p',    "port",                  "[-p|--port[=]HTTP PORT]"},
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
        {0,                            'P',    "plain-disable",         "[-P|--plain-disable]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    's',    "ssl-port",              "[-s|--ssl-port[=]HTTPS PORT]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'c',    "certificate",           "[-c|--certificate[=]PEM SSL CERTIFICATE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'k',    "key",                   "[-k|--key[=]PEM SSL PRIVATE KEY]"},
        {0,                            'N',    "no-cert-verify",        "[-N|--no-cert-verify]"},
#endif
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_http_server_data {
	uint16_t http_port;
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	char *certificate_file;
	char *private_key_file;
	uint16_t https_port;
	int ssl_no_cert_verify;
	int plain_disable;
#endif
};

static void __rrr_http_server_data_init (struct rrr_http_server_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_http_server_data_cleanup (struct rrr_http_server_data *data) {
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	RRR_FREE_IF_NOT_NULL(data->certificate_file);
	RRR_FREE_IF_NOT_NULL(data->private_key_file);
#else
	(void)(data);
#endif
}

static int __rrr_http_server_parse_config (struct rrr_http_server_data *data, struct cmd_data *cmd) {
	int ret = 0;

	uint64_t port_tmp;
	const char *port;

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	// Certificate file
	const char *certificate = cmd_get_value(cmd, "certificate", 0);
	if (cmd_get_value (cmd, "certificate", 1) != NULL) {
		RRR_MSG_0("Error: Only one certificate argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (certificate != NULL) {
		data->certificate_file = rrr_strdup(certificate);
		if (data->certificate_file == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// Private key file
	const char *key = cmd_get_value(cmd, "key", 0);
	if (cmd_get_value (cmd, "key", 1) != NULL) {
		RRR_MSG_0("Error: Only one key argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (key != NULL) {
		data->private_key_file = rrr_strdup(key);
		if (data->private_key_file == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
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
		RRR_MSG_0("Private key was specified but certificate was not, please check arguments.\n");
		ret = 1;
		goto out;
	}

	if ((data->private_key_file == NULL || *(data->private_key_file) == '\0') && (data->certificate_file != NULL && *(data->certificate_file) != '\0')) {
		RRR_MSG_0("Certificate was specified but private key was not, please check arguments.\n");
		ret = 1;
		goto out;
	}

	// HTTPS port
	port = cmd_get_value(cmd, "ssl-port", 0);
	port_tmp = 0;
	if (cmd_get_value (cmd, "ssl-port", 1) != NULL) {
		RRR_MSG_0("Error: Only one 'ssl-port' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			RRR_MSG_0("Could not understand argument 'ssl-port', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp == 0) {
		port_tmp = 443;
	}
	if (port_tmp > 65535) {
		RRR_MSG_0("HTTPS out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->https_port = (uint16_t) port_tmp;
#endif

	// HTTP port
	port = cmd_get_value(cmd, "port", 0);
	port_tmp = 0;
	if (cmd_get_value (cmd, "port", 1) != NULL) {
		RRR_MSG_0("Error: Only one 'port' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			RRR_MSG_0("Could not understand argument 'port', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp == 0) {
		port_tmp = 80;
	}
	else if (port_tmp > 65535) {
		RRR_MSG_0("HTTP port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->http_port = (uint16_t) port_tmp;

	out:
	return ret;
}

static volatile int main_running = 1;
static volatile int sigusr2 = 0;

int rrr_http_server_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static int rrr_http_server_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	(void)(arg);

	rrr_allocator_maintenance_nostats();

	if (sigusr2) {
		RRR_MSG_0("Received SIGUSR2, but this is not implemented in http server\n");
		sigusr2 = 0;
	}

	return (main_running ? 0 : RRR_EVENT_EXIT);
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}
	rrr_strerror_init();

	struct cmd_data cmd;
	struct rrr_http_server_data data;
	struct rrr_signal_handler *signal_handler = NULL;
	struct rrr_http_server *http_server = NULL;
	struct rrr_event_queue *events = NULL;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_http_server_data_init(&data);

	signal_handler = rrr_signal_handler_push(rrr_http_server_signal_handler, NULL);

	if (rrr_event_queue_new(&events) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 0) != 0) {
		goto out;
	}

	if (__rrr_http_server_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	struct rrr_http_server_callbacks callbacks = {
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
	};

	if (rrr_http_server_new (
			&http_server,
			&callbacks
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	int transport_count = 0;

	if (data.plain_disable != 1) {
#endif
		if (rrr_http_server_start_plain (
				http_server,
				events,
				data.http_port,
				RRR_HTTP_SERVER_FIRST_DATA_TIMEOUT_MS,
				RRR_HTTP_SERVER_IDLE_TIMEOUT_MS,
				RRR_HTTP_SERVER_SEND_CHUNK_COUNT_LIMIT
		) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
		transport_count++;
	}
#endif

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (data.certificate_file != NULL && data.private_key_file != NULL) {
		// DO NOT run config cleanup for this, memory managed elsewhere
		struct rrr_net_transport_config net_transport_config_tls = {
				data.certificate_file,
				data.private_key_file,
				NULL,
				NULL,
				NULL,
				RRR_NET_TRANSPORT_TLS
		};

		int flags = 0;

		if (data.ssl_no_cert_verify) {
			flags |= RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY;
		}

		if (rrr_http_server_start_tls (
				http_server,
				events,
				data.https_port,
				RRR_HTTP_SERVER_FIRST_DATA_TIMEOUT_MS,
				RRR_HTTP_SERVER_IDLE_TIMEOUT_MS,
				RRR_HTTP_SERVER_SEND_CHUNK_COUNT_LIMIT,
				&net_transport_config_tls,
				flags
		) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
		transport_count++;
	}

	if (transport_count == 0) {
		RRR_MSG_0("Neither HTTP or HTTPS are active, check arguments.\n");
		ret = EXIT_FAILURE;
		goto out;
	}
#endif

	rrr_signal_default_signal_actions_register();

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if (rrr_event_dispatch(events, 100000, rrr_http_server_event_periodic, NULL) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	out:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_config_set_debuglevel_on_exit();

		if (http_server != NULL) {
			rrr_http_server_destroy(http_server);
			http_server = NULL;
		}

		if (events != NULL) {
			rrr_event_queue_destroy(events);
		}

		rrr_signal_handler_remove(signal_handler);

		__rrr_http_server_data_cleanup(&data);

		cmd_destroy(&cmd);

		rrr_socket_close_all();

		rrr_strerror_cleanup();
		rrr_log_cleanup();

	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
