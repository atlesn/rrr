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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "../build_timestamp.h"
#include "lib/socket/rrr_socket_constants.h"
#include "main.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/common.h"
#include "lib/http/http_server.h"
#include "lib/http/http_transaction.h"
#include "lib/http/http_util.h"
#include "lib/net_transport/net_transport_config.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_client.h"
#include "lib/ip/ip.h"
#include "lib/ip/ip_accept_data.h"
#include "lib/version.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/event/event.h"
#include "lib/event/event_collection.h"
#include "lib/event/event_collection_struct.h"
#include "lib/util/macro_utils.h"
#include "lib/util/readfile.h"
#include "lib/helpers/string_builder.h"

#define RRR_HTTP_SERVER_FIRST_DATA_TIMEOUT_MS  3000
#define RRR_HTTP_SERVER_IDLE_TIMEOUT_MS        RRR_HTTP_SERVER_FIRST_DATA_TIMEOUT_MS * 2
#define RRR_HTTP_SERVER_SEND_CHUNK_COUNT_LIMIT 100000

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_http_server");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'p',    "port",                  "[-p|--port[=]HTTP PORT]"},
        {0,                            'P',    "plain-disable",         "[-P|--plain-disable]"},
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
        {CMD_ARG_FLAG_HAS_ARGUMENT,    's',    "ssl-port",              "[-s|--ssl-port[=]HTTPS PORT]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'c',    "certificate",           "[-c|--certificate[=]PEM SSL CERTIFICATE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'k',    "key",                   "[-k|--key[=]PEM SSL PRIVATE KEY]"},
        {0,                            'N',    "no-cert-verify",        "[-N|--no-cert-verify]"},
#endif
#if defined(RRR_WITH_HTTP3)
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'q',    "quic-port",             "[-q|--quic-port[=]QUIC PORT]"},
#endif
	{CMD_ARG_FLAG_HAS_ARGUMENT,    'R',    "request-file",          "[-R|--request-file[=]HTTP REQUEST FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_http_server_data {
	uint16_t http_port;
	uint16_t https_port;
	uint16_t quic_port;
	char *request_file;
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_HTTP3)
	char *certificate_file;
	char *private_key_file;
	int ssl_no_cert_verify;
#endif
	int plain_disable;
};

static void __rrr_http_server_data_init (struct rrr_http_server_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_http_server_data_cleanup (struct rrr_http_server_data *data) {
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	RRR_FREE_IF_NOT_NULL(data->request_file);
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

	// Request file
	const char *request_file = cmd_get_value(cmd, "request-file", 0);
	if (cmd_get_value (cmd, "request-file", 1) != NULL) {
		RRR_MSG_0("Error: Only one request-file argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (request_file != NULL) {
		data->request_file = rrr_strdup(request_file);
		if (data->request_file == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}


#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_HTTP3)
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

#endif
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
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
	if (port_tmp > 65535) {
		RRR_MSG_0("SSL port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->https_port = (uint16_t) port_tmp;
#endif
#if defined(RRR_WITH_HTTP3)
	// QUIC port
	port = cmd_get_value(cmd, "quic-port", 0);
	port_tmp = 0;
	if (cmd_get_value (cmd, "quic-port", 1) != NULL) {
		RRR_MSG_0("Error: Only one 'quic-port' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			RRR_MSG_0("Could not understand argument 'quic-port', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp > 65535) {
		RRR_MSG_0("QUIC port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->quic_port = (uint16_t) port_tmp;
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

	// No plain method
	if (cmd_exists(cmd, "plain-disable", 0)) {
		if (cmd_exists(cmd, "port", 0) && data->http_port > 0) {
			RRR_MSG_0("A port was specified with --port while --plain-disable was active\n");
			ret = 1;
			goto out;
		}
		data->plain_disable = 1;
	}

	out:
	return ret;
}

static volatile int main_running = 1;
static volatile int sigusr2 = 0;

static int __rrr_http_server_response_postprocess_callback (
		RRR_HTTP_SERVER_WORKER_RESPONSE_POSTPROCESS_CALLBACK_ARGS
) {
	struct rrr_http_server_data *data = arg;

	int ret = 0;

	struct rrr_string_builder alt_svc_header = {0};

	if (data->quic_port == 0 && data->https_port == 0) {
		goto out;
	}

	if ((ret = rrr_http_util_make_alt_svc_header (
			&alt_svc_header,
			data->https_port,
			data->quic_port
	)) != 0) {
		goto out;
	}

	if (rrr_string_builder_length(&alt_svc_header) == 0) {
		goto out;
	}

	if ((ret = rrr_http_transaction_response_alt_svc_set (
			transaction,
			rrr_string_builder_buf(&alt_svc_header)
	)) != 0) {
		goto out;
	}

	out:
	rrr_string_builder_clear(&alt_svc_header);
	return ret;
}

int rrr_http_server_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static int rrr_http_server_response_get_target_size(RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS) {
	(void)(addr);
	(void)(addr_len);
	(void)(private_data);
	(void)(arg);

	assert(read_session->rx_buf_wpos <= INT_MAX);

	printf("%.*s", (int) read_session->rx_buf_wpos, read_session->rx_buf_ptr);

	if (strncmp(read_session->rx_buf_ptr + read_session->rx_buf_wpos - 4, "\r\n\r\n", 4) == 0) {
		return RRR_READ_EOF;
	}

	read_session->rx_buf_skip = read_session->rx_buf_wpos;

	return RRR_READ_OK;
}

static int rrr_http_server_response_complete_callback(RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS) {
	(void)(read_session);
	(void)(addr);
	(void)(addr_len);
	(void)(private_data);
	(void)(arg);

	assert(0 && "Not implemented");

	return 0;
}

struct rrr_http_server_request_file_data {
	int state;
	struct rrr_ip_accept_data *accept_data;
	int fd;
	char *request_data;
};

struct rrr_http_server_periodic_callback_data {
	struct rrr_http_server_data *data;
	struct rrr_http_server_request_file_data *request_file_data;
	struct rrr_socket_client_collection *client_collection;
	struct rrr_event_queue *events;
};

static int rrr_http_server_request_file_process (
		struct rrr_http_server_data *data,
		struct rrr_http_server_request_file_data *request_file_data,
		struct rrr_socket_client_collection *client_collection
) {
	int ret = 0;

	static rrr_biglength data_size = 0;

	switch (request_file_data->state) {
		case 0: {
			assert(request_file_data->accept_data == NULL);

			if ((ret = rrr_ip_network_connect_tcp_ipv4_or_ipv6 (
					&request_file_data->accept_data,
					data->http_port,
					"localhost"
			)) != 0) {
				RRR_MSG_0("Failed to connect in %s: %i\n", __func__, ret);
				return ret;
			}

			if ((ret = rrr_socket_client_collection_connected_fd_push (
					client_collection,
					request_file_data->accept_data->ip_data.fd,
					RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND
			)) != 0) {
				RRR_MSG_0("Failed to push to client collection in %s\n", __func__);
				return ret;
			}

			request_file_data->state = 1;
			// Remove FD from accept data to prevent double close
			request_file_data->fd = request_file_data->accept_data->ip_data.fd;
			request_file_data->accept_data->ip_data.fd = 0;
		} /* Fallthrough */
		case 1: {
			assert(request_file_data->request_data == NULL);

			if ((ret = rrr_readfile_read (
					&request_file_data->request_data,
					&data_size,
					data->request_file,
					0, // No max size
					0  // ENOENT not ok
			)) != 0) {
				RRR_MSG_0("Failed to read file '%s' in %s\n", data->request_file, __func__);
				goto out;
			}

			request_file_data->state = 2;
		} /* Fallthrough */
		case 2: {
			rrr_length send_chunk_count;
			if ((ret = rrr_socket_client_collection_send_push(
					&send_chunk_count,
					client_collection,
					request_file_data->fd,
					(void **) &request_file_data->request_data,
					data_size
			)) != 0) {
				RRR_MSG_0("Failed to push request data in %s\n", __func__);
				goto out;
			}

			request_file_data->state = 3;
		} break;
		case 4: {
			return RRR_EVENT_EXIT;
		} break;
		default: {
			if (!rrr_socket_client_collection_has_fd (
					client_collection,
					request_file_data->fd
			)) {
				return RRR_EVENT_EXIT;
			}

			request_file_data->state++;
		};
	};

	out:
	return ret;
}

static void rrr_http_server_request_file_event (int fd, short flags, void *arg) {
	struct rrr_http_server_periodic_callback_data *callback_data = arg;
	struct rrr_http_server_data *data = callback_data->data;

	(void)(fd);
	(void)(flags);

	int ret_tmp;

	if ((ret_tmp = rrr_http_server_request_file_process (
			data,
			callback_data->request_file_data,
			callback_data->client_collection
	)) != 0) {
		if (ret_tmp == RRR_EVENT_EXIT)
			rrr_event_dispatch_exit(callback_data->events);
		else
			rrr_event_dispatch_break(callback_data->events);
	}
}

static int rrr_http_server_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_http_server_periodic_callback_data *callback_data = arg;
	struct rrr_http_server_data *data = callback_data->data;

	(void)(data);

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
	struct rrr_http_server_request_file_data request_file_data = {0};
	struct rrr_socket_client_collection *client_collection = NULL;
	struct rrr_signal_handler *signal_handler = NULL;
	struct rrr_http_server *http_server = NULL;
	struct rrr_event_queue *events = NULL;
	struct rrr_event_collection event_collection = {0};
	struct rrr_event_handle request_file_event = {0};

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_http_server_data_init(&data);

	signal_handler = rrr_signal_handler_push(rrr_http_server_signal_handler, NULL);

	if (rrr_event_queue_new(&events) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	rrr_event_collection_init(&event_collection, events);

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
			NULL, NULL, NULL, NULL, NULL, NULL, 
			__rrr_http_server_response_postprocess_callback,
			&data
	};

	if (rrr_http_server_new (
			&http_server,
			&callbacks
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_socket_client_collection_new (
			&client_collection,
			events,
			"rrr_http_server"
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	rrr_socket_client_collection_event_setup_raw (
			client_collection,
			NULL,
			NULL,
			NULL,
			65536,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_EOF | RRR_SOCKET_READ_CHECK_POLLHUP,
			NULL,
			NULL,
			rrr_http_server_response_get_target_size,
			NULL,
			NULL,
			NULL,
			rrr_http_server_response_complete_callback,
			NULL
	);

	int transport_count = 0;

	if (data.plain_disable != 1) {
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
		transport_count++;
	}

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (data.https_port > 0) {
		// DO NOT run config cleanup for this, memory managed elsewhere
		struct rrr_net_transport_config net_transport_config_tls = {
				data.certificate_file,
				data.private_key_file,
				NULL,
				NULL,
				RRR_NET_TRANSPORT_TLS,
				RRR_NET_TRANSPORT_F_TLS,
				RRR_NET_TRANSPORT_TLS_NONE
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
#endif

#if defined(RRR_WITH_HTTP3)
	if (data.quic_port > 0) {
		// DO NOT run config cleanup for this, memory managed elsewhere
		struct rrr_net_transport_config net_transport_config_tls = {
				data.certificate_file,
				data.private_key_file,
				NULL,
				NULL,
				RRR_NET_TRANSPORT_QUIC,
				RRR_NET_TRANSPORT_F_QUIC,
				RRR_NET_TRANSPORT_TLS_NONE
		};

		int flags = 0;

		if (data.ssl_no_cert_verify) {
			flags |= RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY;
		}

		if (rrr_http_server_start_quic (
				http_server,
				events,
				data.quic_port,
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
#endif

	if (transport_count == 0) {
		RRR_MSG_0("No listening mode is active, check arguments.\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	rrr_signal_default_signal_actions_register();

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	struct rrr_http_server_periodic_callback_data periodic_callback_data = {
		&data,
		&request_file_data,
		client_collection,
		events
	};

	if (data.request_file != NULL) {
		if (rrr_event_collection_push_periodic (
				&request_file_event,
				&event_collection,
				rrr_http_server_request_file_event,
				&periodic_callback_data,
				5 * 1000 // 5 ms
		) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
		EVENT_ADD(request_file_event);
		EVENT_ACTIVATE(request_file_event);
	}

	if (rrr_event_dispatch(events, 100000, rrr_http_server_event_periodic, &periodic_callback_data) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	out:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_config_set_debuglevel_on_exit();

		if (request_file_data.accept_data != NULL) {
			rrr_ip_accept_data_close_and_destroy(request_file_data.accept_data);
		}
		RRR_FREE_IF_NOT_NULL(request_file_data.request_data);

		if (client_collection != NULL) {
			rrr_socket_client_collection_destroy(client_collection);
		}

		if (http_server != NULL) {
			rrr_http_server_destroy(http_server);
			http_server = NULL;
		}

		rrr_event_collection_clear(&event_collection);

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
