/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include "main.h"
#include "../build_timestamp.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/common.h"
#include "lib/rrr_config.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/array_tree.h"
#include "lib/map.h"
#include "lib/rrr_types.h"
#include "lib/event/event.h"
#include "lib/event/event_collection.h"
#include "lib/messages/msg_msg.h"
#include "lib/messages/msg_checksum.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_common.h"
#include "lib/http/http_util.h"
#include "lib/http/http_client.h"
#include "lib/http/http_transaction.h"
#include "lib/net_transport/net_transport.h"
#include "lib/net_transport/net_transport_config.h"
#include "lib/rrr_strerror.h"
#include "lib/util/rrr_time.h"
#include "lib/util/posix.h"
#include "lib/util/arguments.h"

#define RRR_HTTP_CLIENT_WEBSOCKET_TIMEOUT_S 10

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_http_client");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,    's',    "server",               "{-s|--server[=]HTTP SERVER}"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'p',    "port",                 "[-p|--port[=]HTTP PORT]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "endpoint",             "[-e|--endpoint[=]HTTP ENDPOINT]"},
        {0,                            'w',    "websocket-upgrade",    "[-w|--websocket-upgrade]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'a',    "array-definition",     "[-a|--array-definition[=]ARRAY DEFINITION]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT |
         CMD_ARG_FLAG_SPLIT_COMMA,     't',    "tags-to-send",         "[-t|--tags-to-send[=]ARRAY TAG[,ARRAY TAG...]]"},
        {0,                            'O',    "no-output",            "[-O|--no-output]"},
        {0,                            'P',    "plain-force",          "[-P|--plain-force]"},
        {0,                            'S',    "ssl-force",            "[-S|--ssl-force]"},
        {0,                            '0',    "http10-force",         "[-0|--http10-force]"},
        {0,                            '2',    "http2-upgrade",        "[-2|--http2-upgrade]"},
        {0,                            'N',    "no-cert-verify",       "[-N|--no-cert-verify]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'q',    "query",                "[-q|--query[=]HTTP QUERY]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'r',    "run-directory",        "[-r|--run-directory[=]RUN DIRECTORY]"},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_http_client_data {
	struct rrr_http_client_request_data request_data;
	struct rrr_event_queue *queue;
	struct rrr_http_client *http_client;
	enum rrr_http_upgrade_mode upgrade_mode;
	enum rrr_http_version protocol_version;
	struct rrr_array_tree *tree;
	struct rrr_read_session_collection read_sessions;
	struct rrr_map tags;
	int no_output;
	struct rrr_net_transport_config net_transport_config;
	int final_callback_count;
	rrr_http_unique_id unique_id_counter;

	int redirect_pending;

	struct rrr_event_collection events;
	rrr_event_handle event_stdin;
	rrr_event_handle event_redirect;
};

static void __rrr_http_client_data_cleanup (
		struct rrr_http_client_data *data
) {
	if (data->http_client != NULL) {
		rrr_http_client_destroy(data->http_client);
	}
	rrr_event_collection_clear(&data->events);
	if (data->queue != NULL) {
		rrr_event_queue_destroy(data->queue);
	}
	rrr_http_client_request_data_cleanup(&data->request_data);
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}

	rrr_read_session_collection_clear(&data->read_sessions);
	rrr_map_clear(&data->tags);
}

static int __rrr_http_client_save_tag_callback (
		const char *tag,
		void *arg
) {
	struct rrr_http_client_data *data = arg;
	return rrr_map_item_add_new(&data->tags, tag, tag);
}

static int __rrr_http_client_parse_config (
		struct rrr_http_client_data *data,
		struct cmd_data *cmd
) {
	int ret = 0;

	char *array_tree_tmp = NULL;

	struct rrr_http_client_request_data *request_data = &data->request_data;

	// HTTP CLIENT EXECUTABLE SPECIFIC PARAMETERS

	// Multiple arguments write to upgrade_mode, the order of these matters
	data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;

	// Websocket or HTTP2 upgrade
	if (cmd_exists(cmd, "websocket-upgrade", 0)) {
		data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_WEBSOCKET;
	}
#ifdef RRR_WITH_NGHTTP2
	// Send upgrade: h2c etc. with http/1.1 
	else if (cmd_exists(cmd, "http2-upgrade", 0)) {
		data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_HTTP2;
	}
#endif

	const char *array_definition = cmd_get_value(cmd, "array-definition", 0);

	if (cmd_get_value (cmd, "array-definition", 1) != NULL) {
		RRR_MSG_0("Error: Only one array-definition argument may be specified\n");
		ret = 1;
		goto out;
	}

	if ((ret = cmd_iterate_subvalues_if_exists(cmd, "tags-to-send", __rrr_http_client_save_tag_callback, data)) != 0) {
		RRR_MSG_0("Failed to store tags in __rrr_http_client_parse_config\n");
		goto out;
	}

	if (array_definition == NULL) {
		if (RRR_MAP_COUNT(&data->tags)) {
			RRR_MSG_0("Tags was specified while no array definition was specified\n");
			ret = 1;
			goto out;
		}
	}
	else {
		if (data->upgrade_mode != RRR_HTTP_UPGRADE_MODE_WEBSOCKET) {
			RRR_MSG_0("Array-definition specified while websocket mode was not active\n");
			ret = 1;
			goto out;
		}
		array_tree_tmp = rrr_allocate(strlen(array_definition) + 1 + 1); // plus extra ; plus \0
		if (array_tree_tmp == NULL) {
			RRR_MSG_0("Could not allocate temporary arry tree string in parse_config\n");
			ret = 1;
			goto out;
		}

		sprintf(array_tree_tmp, "%s;", array_definition);

		if (rrr_array_tree_interpret_raw (
				&data->tree,
				array_tree_tmp,
				rrr_length_from_biglength_bug_const(strlen(array_tree_tmp)),
				"-"
		) != 0 || data->tree == NULL) {
			RRR_MSG_0("Error while parsing array tree definition\n");
			ret = 1;
			goto out;
		}
	}

	// HTTP CLIENT FRAMEWORK PARAMETERS

	// Server name
	const char *server = cmd_get_value(cmd, "server", 0);
	if (cmd_get_value (cmd, "server", 1) != NULL) {
		RRR_MSG_0("Error: Only one server argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (server == NULL) {
		RRR_MSG_0("No server specified\n");
		ret = 1;
		goto out;
	}

	request_data->server = rrr_strdup(server);
	if (request_data->server == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Endpoint
	const char *endpoint = cmd_get_value(cmd, "endpoint", 0);
	if (cmd_get_value (cmd, "endpoint", 1) != NULL) {
		RRR_MSG_0("Error: Only one endpoint argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (endpoint == NULL) {
		endpoint = "/";
	}

	request_data->endpoint = rrr_strdup(endpoint);
	if (request_data->endpoint == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Disable output
	if (cmd_exists(cmd, "no-output", 0)) {
		data->no_output = 1;
	}

	// No certificate verification
	if (cmd_exists(cmd, "no-cert-verify", 0)) {
		request_data->ssl_no_cert_verify = 1;
	}

	if (cmd_exists(cmd, "ssl-force", 0) && cmd_exists(cmd, "plain-force", 0)) {
		RRR_MSG_0("Both SSL-force and Plain-force (-S and -P) was set at the same time, but only one of them may be set simultaneously\n");
		ret = 1;
		goto out;
	}

	// Force SSL
	if (cmd_exists(cmd, "ssl-force", 0)) {
		request_data->transport_force = RRR_HTTP_TRANSPORT_HTTPS;
	}

	// Force Plaintext
	if (cmd_exists(cmd, "plain-force", 0)) {
		request_data->transport_force = RRR_HTTP_TRANSPORT_HTTP;
	}

	// Force HTTP/1.0
	if (cmd_exists(cmd, "http10-force", 0)) {
		if (cmd_exists(cmd, "websocket-upgrade", 0)) {
			RRR_MSG_0("Both force HTTP/1.0 and upgrade to websocket was specified, this is an invalid combination.\n");
			ret = 1;
			goto out;
		}
		data->protocol_version = RRR_HTTP_VERSION_10;
		data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
	}

	// HTTP port
	if ((ret = rrr_arguments_parse_port (
			&request_data->http_port,
			cmd,
			"port",
			request_data->transport_force == RRR_HTTP_TRANSPORT_HTTPS ? 443 : 80
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(array_tree_tmp);
	return ret;
}

static int __rrr_http_client_final_write_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	ssize_t *bytes = arg;
	*bytes = write (STDOUT_FILENO, str, rrr_size_from_biglength_bug_const (len));
	return 0;
}

static int __rrr_http_client_final_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	struct rrr_http_client_data *http_client_data = arg;

	int ret = 0;

	rrr_nullsafe_len data_start = 0;
	rrr_nullsafe_len data_size = rrr_nullsafe_str_len(response_data);

	if (data_size == 0) {
		goto out;
	}

	http_client_data->final_callback_count++;

	if (transaction->response_part->response_code == 101 &&
		EVENT_INITIALIZED(http_client_data->event_stdin) &&
		rrr_http_client_active_transaction_count_get(http_client_data->http_client) > 0
	) {
		EVENT_ADD(http_client_data->event_stdin);
	}
	else if (transaction->response_part->response_code < 200 || transaction->response_part->response_code > 299) {
		RRR_MSG_0("Error response from server: %i %s\n",
				transaction->response_part->response_code,
				rrr_http_util_iana_response_phrase_from_status_code(transaction->response_part->response_code)
		);
	}

	if (http_client_data->no_output) {
		goto out;
	}

	RRR_MSG_2("Received %" PRIrrr_nullsafe_len " bytes of data from HTTP library\n", data_size);

	while (data_size > 0) {
		ssize_t bytes = 0;

		rrr_nullsafe_str_with_raw_truncated_do (
				response_data,
				data_start,
				data_size,
				__rrr_http_client_final_write_callback,
				&bytes
		);

		if (bytes < 0) {
			RRR_MSG_0("Error while printing HTTP response in __rrr_http_client_final_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		else {
			if ((rrr_nullsafe_len) bytes > data_size) {
				RRR_BUG("BUG: Underflow in __rrr_http_client_final_callack\n");
			}
			data_start += (rrr_nullsafe_len) bytes;
			data_size -= (rrr_nullsafe_len) bytes;
		}
	}

	out:
	return ret;
}

static int __rrr_http_client_failure_callback (
		RRR_HTTP_CLIENT_FAILURE_CALLBACK_ARGS
) {
	struct rrr_http_client_data *http_client_data = arg;

	(void)(transaction);
	(void)(http_client_data);

	RRR_MSG_0("Error while sending request: %s\n", error_msg);

	return RRR_HTTP_SOFT_ERROR;
}

static int __rrr_http_client_unique_id_generator_callback (
		RRR_HTTP_CLIENT_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
) {
	struct rrr_http_client_data *http_client_data = arg;
	*unique_id = ++(http_client_data->unique_id_counter);
	return 0;
}

static int __rrr_http_client_request_send_loop (
	struct rrr_http_client_data *http_client_data
) {
	int ret = 0;

	int retries = 5000;
	while (--retries) {
		if ((ret = rrr_http_client_request_send (
				&http_client_data->request_data,
				http_client_data->http_client,
				&http_client_data->net_transport_config,
				5, // Max redirects
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL
		)) == 0 || ret != RRR_HTTP_BUSY) {
			goto out;
		}
		rrr_event_dispatch_once(http_client_data->queue);
		rrr_posix_usleep(1000);
	}

	out:
	return ret;
}

static int __rrr_http_client_redirect_callback (
		RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS
) {
	struct rrr_http_client_data *http_client_data = arg;

	int ret = 0;

	if ((ret = rrr_http_client_request_data_reset_from_uri(&http_client_data->request_data, uri)) != 0) {
		goto out;
	}

	// Continue using protocol provided by server
	http_client_data->request_data.protocol_version = transaction->response_part->parsed_version;

	EVENT_ACTIVATE(http_client_data->event_redirect);

	out:
	return ret;
}

struct rrr_http_client_send_websocket_frame_callback_data {
	void **data;
	rrr_biglength *data_len;
	int *is_binary;
	struct rrr_http_client_data *http_client_data;
};

static int __rrr_http_client_send_websocket_frame_final_callback (
		struct rrr_read_session *read_session,
		struct rrr_array *array_final,
		void *arg
) {
	int ret = RRR_READ_OK;

	(void)(read_session);
	(void)(array_final);
	(void)(arg);

	return ret;
}

static int __rrr_http_client_send_websocket_frame_callback (RRR_HTTP_CLIENT_WEBSOCKET_RESPONSE_GET_CALLBACK_ARGS) {
	struct rrr_http_client_data *http_client_data = arg;

	(void)(unique_id);
	(void)(application_topic);

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;
	char *raw_tmp = NULL;
	struct rrr_array array = {0};

	*data = NULL;
	*data_len = 0;
	*is_binary = 0;

	if (http_client_data->tree == NULL) {
		ret = RRR_HTTP_DONE;
		goto out;
	}

	struct rrr_http_client_send_websocket_frame_callback_data callback_data = {
			data,
			data_len,
			is_binary,
			http_client_data
	};

	uint64_t bytes_read = 0;
	if ((ret = rrr_socket_common_receive_array_tree (
			&bytes_read,
			&http_client_data->read_sessions,
			STDIN_FILENO,
			RRR_SOCKET_READ_METHOD_READ_FILE|RRR_SOCKET_READ_CHECK_EOF|RRR_SOCKET_READ_NO_GETSOCKOPTS|RRR_SOCKET_READ_USE_POLL,
			&array,
			http_client_data->tree,
			1, // Do sync byte by byte
			65535,
			0, // No ratelimit interval
			0, // No ratelimit max bytes
			1 * 1024 * 1024 * 1024, // 1 GB
			__rrr_http_client_send_websocket_frame_final_callback,
			NULL,
			&callback_data
	)) != 0) {
		goto out;
	}

	if (rrr_array_count(&array)) {
		if (RRR_LL_COUNT(&http_client_data->tags)) {
			rrr_biglength target_size = 0;
			int found_tags = 0;
			if ((ret = rrr_array_selected_tags_export(&raw_tmp, &target_size, &found_tags, &array, &http_client_data->tags)) != 0) {
				RRR_MSG_0("Failed to get specified array tags from input data, return was %i\n", ret);
				goto out;
			}

			if (target_size > SSIZE_MAX) {
				RRR_MSG_0("Exported size of array exceeds maximum (%llu > %lli)\n",
					(unsigned long long) target_size,
					(long long int) SSIZE_MAX
				);
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			*data_len = target_size;

			*data = raw_tmp;
			raw_tmp = NULL;
			goto out;
		}
		else {
			if ((ret = rrr_array_new_message_from_array(&msg_tmp, &array, rrr_time_get_64(), NULL, 0)) != 0) {
				RRR_MSG_0("Failed to create RRR array message from input data\n");
				goto out;
			}

			*is_binary = 1;
			*data_len = MSG_TOTAL_SIZE(msg_tmp);

			rrr_msg_msg_prepare_for_network(msg_tmp);
			rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg_tmp);

			*data = msg_tmp;
			msg_tmp = NULL;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	RRR_FREE_IF_NOT_NULL(raw_tmp);
	rrr_array_clear(&array);
	if (ret != 0 && ret != RRR_SOCKET_READ_INCOMPLETE && EVENT_INITIALIZED(http_client_data->event_stdin)) {
		EVENT_REMOVE(http_client_data->event_stdin);
	}
	return ret;
}

static int __rrr_http_client_receive_websocket_frame_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	(void)(arg);
	ssize_t bytes = write (STDOUT_FILENO, str, rrr_size_from_biglength_bug_const(len));
	RRR_DBG_3("%lli bytes printed\n", (long long int) bytes);
	return 0;
}

static int __rrr_http_client_receive_websocket_frame_callback (RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS) {
	struct rrr_http_client_data *http_client_data = arg;

	(void)(unique_id);
	(void)(handle);
	(void)(http_client_data);
	(void)(application_topic);

	if (is_binary) {
		printf ("- (binary data) -\n");
	}
	else {
		rrr_nullsafe_str_with_raw_do_const (
				payload,
				__rrr_http_client_receive_websocket_frame_nullsafe_callback,
				NULL
		);
	}

	return 0;
}

static void rrr_http_client_event_redirect (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct rrr_http_client_data *data = arg;

	data->redirect_pending = 1;

	rrr_event_dispatch_exit(data->queue);
}

static void rrr_http_client_event_stdin (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct rrr_http_client_data *data = arg;

	rrr_http_client_websocket_response_available_notify(data->http_client);
}

static int main_running = 1;
int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

static int rrr_http_client_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_http_client_data *data = arg;

	if (!main_running) {
		return RRR_EVENT_EXIT;
	}

	if (rrr_http_client_active_transaction_count_get(data->http_client) == 0) {
		if (!EVENT_INITIALIZED(data->event_stdin) || !EVENT_PENDING(data->event_stdin)) {
			return RRR_EVENT_EXIT;
		}
	}

	rrr_allocator_maintenance_nostats();

	return 0;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler = NULL;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_strerror_init();
	rrr_signal_default_signal_actions_register();
	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);
	rrr_signal_handler_set_active (RRR_SIGNALS_ACTIVE);

	struct cmd_data cmd;
	struct rrr_http_client_data data = {0};

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out;
	}

	if (__rrr_http_client_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_http_client_request_data_reset (
			&data.request_data,
			RRR_HTTP_TRANSPORT_ANY,
			RRR_HTTP_METHOD_GET,
			RRR_HTTP_BODY_FORMAT_URLENCODED,
			data.upgrade_mode,
			data.request_data.protocol_version,
			0, // No plain HTTP2
			RRR_HTTP_CLIENT_USER_AGENT
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	data.net_transport_config.transport_type = RRR_NET_TRANSPORT_BOTH;

	struct rrr_http_client_callbacks callbacks = {
			__rrr_http_client_final_callback,
			&data,
			__rrr_http_client_failure_callback,
			&data,
			__rrr_http_client_redirect_callback,
			&data,
			__rrr_http_client_send_websocket_frame_callback,
			&data,
			__rrr_http_client_receive_websocket_frame_callback,
			&data,
			__rrr_http_client_unique_id_generator_callback,
			&data
	};

	if (rrr_event_queue_new(&data.queue) != 0) {
		ret = EXIT_FAILURE;
		goto out;

	}

	rrr_event_collection_init(&data.events, data.queue);

	if (data.tree != NULL) {
		if (rrr_event_collection_push_read (
				&data.event_stdin,
				&data.events,
				STDIN_FILENO,
				rrr_http_client_event_stdin,
				&data,
				0
		) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}

		EVENT_ADD(data.event_stdin);
	}

	if (rrr_event_collection_push_oneshot (
			&data.event_redirect,
			&data.events,
			rrr_http_client_event_redirect,
			&data
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_http_client_new (
			&data.http_client,
			data.queue,
			5000,   // 5s idle timeout
			0,      // No send chunk limit
			&callbacks
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	data.request_data.upgrade_mode = data.upgrade_mode;
	data.request_data.protocol_version = data.protocol_version;

	redirect:

	data.redirect_pending = 0;

	if (__rrr_http_client_request_send_loop (
			&data
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if ((rrr_event_dispatch (
			data.queue,
			100000,
			rrr_http_client_event_periodic,
			&data
	) & ~(RRR_EVENT_EXIT)) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (data.redirect_pending) {
		goto redirect;
	}

	out:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_config_set_debuglevel_on_exit();
		__rrr_http_client_data_cleanup(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
