/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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
#include "../build_timestamp.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/rrr_socket.h"
#include "lib/rrr_socket_read.h"
#include "lib/http_session.h"
#include "lib/http_part.h"
#include "lib/vl_time.h"
#include "lib/ip.h"
#define RRR_HTTP_CLIENT_USER_AGENT "RRR/" PACKAGE_VERSION

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_HAS_ARGUMENT,	's',	"server",				"{-s|--server[=]HTTP SERVER}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'p',	"port",					"[-p|--port[=]HTTP PORT]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'e',	"endpoint",				"[-e|--endpoint[=]HTTP ENDPOINT]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'q',	"query",				"[-q|--query[=]HTTP QUERY]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_http_client_data {
	char *server;
	char *endpoint;
	char *query;
	uint16_t http_port;
	struct rrr_http_session *session;
};
static void __rrr_http_client_data_init (struct rrr_http_client_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_http_client_destroy_data (struct rrr_http_client_data *data) {
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->endpoint);
	RRR_FREE_IF_NOT_NULL(data->query);
	if (data->session != NULL) {
		rrr_http_session_destroy(data->session);
	}
}

static int __rrr_http_client_parse_config (struct rrr_http_client_data *data, struct cmd_data *cmd) {
	int ret = 0;

	// Server name
	const char *server = cmd_get_value(cmd, "server", 0);
	if (cmd_get_value (cmd, "server", 1) != NULL) {
		VL_MSG_ERR("Error: Only one server argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (server == NULL) {
		VL_MSG_ERR("No server specified\n");
		ret = 1;
		goto out;
	}

	data->server= strdup(server);
	if (data->server == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Endpoint
	const char *endpoint = cmd_get_value(cmd, "endpoint", 0);
	if (cmd_get_value (cmd, "endpoint", 1) != NULL) {
		VL_MSG_ERR("Error: Only one endpoint argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (endpoint == NULL) {
		endpoint = "/";
	}

	data->endpoint = strdup(endpoint);
	if (data->endpoint == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Query
	const char *query = cmd_get_value(cmd, "query", 0);
	if (cmd_get_value (cmd, "query", 1) != NULL) {
		VL_MSG_ERR("Error: Only one query argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (query != NULL) {
		data->query = strdup(query);
		if (data->query == NULL) {
			VL_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// HTTP port
	const char *port = cmd_get_value(cmd, "port", 0);
	uint64_t port_tmp = 80;
	if (cmd_get_value (cmd, "count", 1) != NULL) {
		VL_MSG_ERR("Error: Only one 'count' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			VL_MSG_ERR("Could not understand argument 'count', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp < 1 || port_tmp > 65535) {
		VL_MSG_ERR("HTTP port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->http_port = port_tmp;

	out:
	return ret;
}

static int __rrr_http_client_receive_callback (struct rrr_http_session *session, void *arg) {
	struct rrr_http_client_data *data = arg;

	(void)(data);

	struct rrr_http_part *part = session->data;

	int ret = 0;

	if (part->response_code < 200 || part->response_code > 299) {
		VL_MSG_ERR("Error while fetching HTTP: %i %s\n",
				part->response_code, part->response_str);
		ret = 1;
		goto out;
	}

	if (part->data_ptr != 0 && part->data_length > 0) {
		int bytes = write (STDOUT_FILENO, part->data_ptr, part->data_length);
		if (bytes != part->data_length) {
			VL_MSG_ERR("Error while printing HTTP response in __rrr_http_client_receive_callback\n");
			ret = 1;
			goto out;
		}
		printf ("\n");
	}

	out:
	return ret;
}


static int __rrr_http_client_send_request (struct rrr_http_client_data *data) {
	int ret = 0;

	if (data->session != NULL) {
		rrr_http_session_destroy(data->session);
		data->session = NULL;
	}

	if ((ret = rrr_http_session_new (
			&data->session,
			RRR_HTTP_METHOD_GET,
			data->server,
			data->http_port,
			"/?e=f",
			RRR_HTTP_CLIENT_USER_AGENT
	)) != 0) {
		VL_MSG_ERR("Could not create session in __rrr_http_client_send_request\n");
		goto out;
	}

	if ((ret = rrr_http_session_connect(data->session)) != 0) {
		VL_MSG_ERR("Could not connect to server in __rrr_http_client_send_request\n");
		goto out;
	}

	rrr_http_session_add_query_field(data->session, "a", "1");
	rrr_http_session_add_query_field(data->session, "b", "2/(&(&%\"¤&!        #Q¤#!¤&/");
	rrr_http_session_add_query_field(data->session, "\\\\\\\\", "\\\\");

	if ((ret = rrr_http_session_send_request(data->session)) != 0) {
		VL_MSG_ERR("Could not send request in __rrr_http_client_send_request\n");
		goto out;
	}

	out:
	return ret;
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;
	struct rrr_http_client_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_http_client_data_init(&data);

	if ((ret = main_parse_cmd_arguments(&cmd)) != 0) {
		goto out;
	}

	if (rrr_print_help_and_version(&cmd) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_client_parse_config(&data, &cmd)) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_client_send_request(&data)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_session_receive(data.session, __rrr_http_client_receive_callback, &data)) != 0) {
		goto out;
	}

	out:
	rrr_set_debuglevel_on_exit();
	__rrr_http_client_destroy_data(&data);
	cmd_destroy(&cmd);
	rrr_socket_close_all();
	return ret;
}
