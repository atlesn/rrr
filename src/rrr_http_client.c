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
#include "lib/socket/rrr_socket.h"
#include "lib/http/http_client.h"
#include "lib/net_transport/net_transport_config.h"
#include "lib/rrr_strerror.h"
#include "lib/util/rrr_time.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_http_client");

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_HAS_ARGUMENT,	's',	"server",				"{-s|--server[=]HTTP SERVER}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'p',	"port",					"[-p|--port[=]HTTP PORT]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'e',	"endpoint",				"[-e|--endpoint[=]HTTP ENDPOINT]"},
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

static int __rrr_http_client_parse_config (struct rrr_http_client_data *data, struct cmd_data *cmd) {
	int ret = 0;

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

	data->server= strdup(server);
	if (data->server == NULL) {
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

	data->endpoint = strdup(endpoint);
	if (data->endpoint == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// No certificate verification
	if (cmd_exists(cmd, "no-cert-verify", 0)) {
		data->ssl_no_cert_verify = 1;
	}

	if (cmd_exists(cmd, "ssl-force", 0) && cmd_exists(cmd, "plain-force", 0)) {
		RRR_MSG_0("Both SSL-force and Plain-force (-S and -P) was set at the same time, but only one of them may be set simultaneously\n");
		ret = 1;
		goto out;
	}

	// Force SSL
	if (cmd_exists(cmd, "ssl-force", 0)) {
		data->transport_force = RRR_HTTP_TRANSPORT_HTTPS;
	}

	// Force Plaintext
	if (cmd_exists(cmd, "plain-force", 0)) {
		data->transport_force = RRR_HTTP_TRANSPORT_HTTP;
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
		if (data->transport_force == RRR_HTTP_TRANSPORT_HTTPS) {
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
	data->http_port = port_tmp;

	out:
	return ret;
}

static int __rrr_http_client_final_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	int ret = 0;

	(void)(response_code);
	(void)(response_argument);
	(void)(data);
	(void)(chunk_idx);
	(void)(chunk_total);
	(void)(arg);

	if (data_start != NULL && data_size > 0) {
//		const char *separator_line = "=============================";
//		size_t separator_line_length = strlen(separator_line);

		int bytes;

//		bytes = write (STDOUT_FILENO, separator_line, separator_line_length);

		retry:

//		printf("data start: %p size %li\n", data_start, data_size);

		bytes = write (STDOUT_FILENO, data_start, data_size);
		if (bytes < data_size) {
			if (bytes > 0) {
				data_start += bytes;
				data_size -= bytes;
				goto retry;
			}
			else {
				RRR_MSG_0("Error while printing HTTP response in __rrr_http_client_receive_callback: %s\n", rrr_strerror(errno));
				ret = 1;
				goto out;
			}
		}

		//bytes = write (STDOUT_FILENO, separator_line, separator_line_length);
	}

	out:
	return ret;
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
	struct rrr_http_client_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_http_client_data_init(&data, RRR_HTTP_CLIENT_USER_AGENT) != 0) {
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

	data.do_retry = 0;

	struct rrr_net_transport_config net_transport_config = {
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			RRR_NET_TRANSPORT_BOTH
	};

	if (rrr_http_client_send_request_simple (
			&data,
			RRR_HTTP_METHOD_GET,
			&net_transport_config,
			__rrr_http_client_final_callback,
			NULL
	) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (data.do_retry) {
		goto retry;
	}

	out:
		rrr_config_set_debuglevel_on_exit();
		rrr_http_client_data_cleanup(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
	out_final:
		return ret;
}
