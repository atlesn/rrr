/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include "lib/rrr_config.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/log.h"
#include "lib/array_tree.h"
#include "lib/map.h"
#include "lib/messages/msg_msg.h"
#include "lib/messages/msg_checksum.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_common.h"
#include "lib/http/http_client.h"
#include "lib/net_transport/net_transport.h"
#include "lib/net_transport/net_transport_config.h"
#include "lib/rrr_strerror.h"
#include "lib/util/rrr_time.h"
#include "lib/util/posix.h"

#define RRR_HTTP_CLIENT_WEBSOCKET_TIMEOUT_S 10

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_http_client");

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_HAS_ARGUMENT,	's',	"server",				"{-s|--server[=]HTTP SERVER}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'p',	"port",					"[-p|--port[=]HTTP PORT]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'e',	"endpoint",				"[-e|--endpoint[=]HTTP ENDPOINT]"},
		{0,							'w',	"websocket-upgrade",	"[-w|--websocket-upgrade]"},
#ifdef RRR_WITH_NGHTTP2
		{0,							'u',	"http2-upgrade",		"[-u|--http2-upgrade]"},
#endif
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'a',	"array-definition",		"[-a|--array-definition[=]ARRAY DEFINITION]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA,	't',	"tags-to-send",			"[-t|--tags-to-send[=]ARRAY TAG[,ARRAY TAG...]]"},
		{0,							'P',	"plain-force",			"[-P|--plain-force]"},
		{0,							'S',	"ssl-force",			"[-S|--ssl-force]"},
		{0,							'N',	"no-cert-verify",		"[-N|--no-cert-verify]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'q',	"query",				"[-q|--query[=]HTTP QUERY]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'e',	"environment-file",		"[-e|--environment-file[=]ENVIRONMENT FILE]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel-on-exit",	"[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_http_client_data {
	struct rrr_http_client_request_data request_data;
	enum rrr_http_upgrade_mode upgrade_mode;
	struct rrr_array_tree *tree;
	struct rrr_read_session_collection read_sessions;
	struct rrr_map tags;
	int final_callback_count;
};

static void __rrr_http_client_data_cleanup (
		struct rrr_http_client_data *data
) {
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

	// Websocket or HTTP2 upgrade
	if (cmd_exists(cmd, "websocket-upgrade", 0)) {
#ifdef RRR_WITH_NGHTTP2
		if (cmd_exists(cmd, "http2-upgrade", 0)) {
			RRR_MSG_0("Both upgrade to websocket and http2 was set\n");
			ret = 1;
			goto out;
		}
#endif
		data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_WEBSOCKET;
	}
#ifdef RRR_WITH_NGHTTP2
	else if (cmd_exists(cmd, "http2-upgrade", 0)) {
		data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_HTTP2;
	}
#endif
	else {
		data->upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
	}

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
		array_tree_tmp = malloc(strlen(array_definition) + 1 + 1); // plus extra ; plus \0
		if (array_tree_tmp == NULL) {
			RRR_MSG_0("Could not allocate temporary arry tree string in parse_config\n");
			ret = 1;
			goto out;
		}

		sprintf(array_tree_tmp, "%s;", array_definition);

		if (rrr_array_tree_interpret_raw(&data->tree, array_tree_tmp, strlen(array_tree_tmp), "-") != 0 || data->tree == NULL) {
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

	request_data->server= strdup(server);
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

	request_data->endpoint = strdup(endpoint);
	if (request_data->endpoint == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
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

	// HTTP port
	const char *port = cmd_get_value(cmd, "port", 0);
	uint64_t port_tmp = 0;
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
		if (request_data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
			port_tmp = 443;
		}
		else {
			port_tmp = 80;
		}
	}
	if (port_tmp < 1 || port_tmp > 65535) {
		RRR_MSG_0("HTTP port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	request_data->http_port = port_tmp;

	out:
	RRR_FREE_IF_NOT_NULL(array_tree_tmp);
	return ret;
}

static int __rrr_http_client_final_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	struct rrr_http_client_data *http_client_data = arg;

	http_client_data->final_callback_count++;

	int ret = 0;

	(void)(data);
	(void)(chunk_idx);
	(void)(chunk_total);
	(void)(part_data_size);

	if (chunk_data_start == NULL) {
		goto out;
	}

	while (chunk_data_size > 0) {
		ssize_t bytes;

		bytes = write (STDOUT_FILENO, chunk_data_start, chunk_data_size);
		if (bytes < 0) {
			RRR_MSG_0("Error while printing HTTP response in __rrr_http_client_receive_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
		else {
			chunk_data_start += bytes;
			chunk_data_size -= bytes;
		}
	}

	out:
	return ret;
}

struct rrr_http_client_send_websocket_frame_callback_data {
	void **data;
	ssize_t *data_len;
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

static int __rrr_http_client_send_websocket_frame_callback (RRR_HTTP_CLIENT_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS) {
	struct rrr_http_client_data *http_client_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;
	char *raw_tmp = NULL;
	struct rrr_array array = {0};

	*data = NULL;
	*data_len = 0;
	*is_binary = 0;

	if (http_client_data->tree == NULL) {
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
		1 * 1024 * 1024 * 1024, // 1 GB
		__rrr_http_client_send_websocket_frame_final_callback,
		&callback_data
	)) != 0) {
		goto out;
	}

	if (rrr_array_count(&array)) {
		if (RRR_LL_COUNT(&http_client_data->tags)) {
			ssize_t target_size = 0;
			int found_tags = 0;
			if ((ret = rrr_array_selected_tags_export(&raw_tmp, &target_size, &found_tags, &array, &http_client_data->tags)) != 0) {
				RRR_MSG_0("Failed to get specified array tags from input data, return was %i\n", ret);
				goto out;
			}

			*data_len = target_size;

			*data = raw_tmp;
			raw_tmp = NULL;
			goto out;
		}
		else {
			if ((ret = rrr_array_new_message_from_collection(&msg_tmp, &array, rrr_time_get_64(), NULL, 0)) != 0) {
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
	return ret;
}

static int __rrr_http_client_receive_websocket_frame_callback (RRR_HTTP_CLIENT_WEBSOCKET_FRAME_CALLBACK_ARGS) {
	struct rrr_http_client_data *http_client_data = arg;

	(void)(is_binary);
	(void)(payload);
	(void)(payload_size);
	(void)(unique_id);
	(void)(http_client_data);

	if (payload_size < INT_MAX) {
		printf("Received response: %.*s\n", (int) payload_size, payload);
	}

	return 0;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	if (rrr_log_init() != 0) {
		goto out_final;
	}
	rrr_strerror_init();

	struct cmd_data cmd;
	struct rrr_http_client_data data = {0};
	struct rrr_net_transport *net_transport_keepalive = NULL;
	int net_transport_keepalive_handle = 0;

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_http_client_data_init(&data.request_data, RRR_HTTP_CLIENT_USER_AGENT) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_main_print_help_and_version(&cmd, 2) != 0) {
		goto out;
	}

	if (__rrr_http_client_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	int retry_max = 10;

	retry:
	if (--retry_max == 0) {
		RRR_MSG_0("Maximum number of retries reached\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	// In case of redirect between HTTPS and HTTP, destroy the transport
	if (net_transport_keepalive != NULL) {
		rrr_http_client_terminate_if_open(net_transport_keepalive, net_transport_keepalive_handle);
		rrr_net_transport_destroy(net_transport_keepalive);
		net_transport_keepalive = NULL;
		net_transport_keepalive_handle = 0;
	}

	struct rrr_net_transport_config net_transport_config = {
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			RRR_NET_TRANSPORT_BOTH
	};

	if (rrr_http_client_request_send (
			&data.request_data,
			RRR_HTTP_METHOD_GET,
			RRR_HTTP_APPLICATION_HTTP1,
			data.upgrade_mode,
			&net_transport_keepalive,
			&net_transport_keepalive_handle,
			&net_transport_config,
			NULL,
			NULL,
			NULL,
			NULL
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	int got_redirect = 0;
	uint64_t prev_bytes_total = 0;

	do {
		uint64_t bytes_total = 0;

		ret = rrr_http_client_tick (
				&got_redirect,
				&bytes_total,
				&data.request_data,
				net_transport_keepalive,
				net_transport_keepalive_handle,
				1 * 1024 * 1024 * 1024, // 1 GB
				__rrr_http_client_final_callback,
				&data,
				__rrr_http_client_send_websocket_frame_callback,
				&data,
				__rrr_http_client_receive_websocket_frame_callback,
				&data,
				NULL,
				NULL
		);

		if (ret == RRR_READ_EOF) {
			ret = EXIT_SUCCESS;
			goto out;
		}

		// HTTP2 and WebSocket return EOF when complete, OK when not complete
		if (	(	data.upgrade_mode == RRR_HTTP_UPGRADE_MODE_WEBSOCKET ||
					data.upgrade_mode == RRR_HTTP_UPGRADE_MODE_HTTP2 /* Add or application == HTTP2 */
				)
				&& ret == RRR_HTTP_OK
		) {
			ret = RRR_READ_INCOMPLETE;
		}

		if (ret != 0 && ret != RRR_READ_EOF && ret != RRR_READ_INCOMPLETE) {
			ret = EXIT_FAILURE;
			goto out;
		}

		if (prev_bytes_total == bytes_total) {
			rrr_posix_usleep(5000); // 5 ms
		}

		prev_bytes_total = bytes_total;
	} while (ret != 0 && data.final_callback_count == 0);

	if (got_redirect) {
		goto retry;
	}

	out:
		rrr_config_set_debuglevel_on_exit();
		if (net_transport_keepalive != NULL) {
			rrr_net_transport_destroy(net_transport_keepalive);
		}
		__rrr_http_client_data_cleanup(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
	out_final:
		return ret;
}
