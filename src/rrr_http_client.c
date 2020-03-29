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
#include "lib/http_util.h"
#include "lib/vl_time.h"
#include "lib/ip.h"
#include "lib/rrr_strerror.h"
#include "lib/gnu.h"
#define RRR_HTTP_CLIENT_USER_AGENT "RRR/" PACKAGE_VERSION

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_HAS_ARGUMENT,	's',	"server",				"{-s|--server[=]HTTP SERVER}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'p',	"port",					"[-p|--port[=]HTTP PORT]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'e',	"endpoint",				"[-e|--endpoint[=]HTTP ENDPOINT]"},
		{0,							'P',	"plain-force",			"[-P|--plain-force]"},
		{0,							'S',	"ssl-force",			"[-S|--ssl-force]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'q',	"query",				"[-q|--query[=]HTTP QUERY]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_http_client_data {
	char *protocol;
	char *hostname;
	char *endpoint;
	char *query;
	uint16_t http_port;
	int plain_force;
	int ssl_force;
	struct rrr_http_session *session;
};

struct rrr_http_client_response {
	int code;
	char *argument;
};

static void __rrr_http_client_response_cleanup (struct rrr_http_client_response *response) {
	RRR_FREE_IF_NOT_NULL(response->argument);
	response->code = 0;
}

static void __rrr_http_client_data_init (struct rrr_http_client_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_http_client_data_cleanup (struct rrr_http_client_data *data) {
	RRR_FREE_IF_NOT_NULL(data->protocol);
	RRR_FREE_IF_NOT_NULL(data->hostname);
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
		RRR_MSG_ERR("Error: Only one server argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (server == NULL) {
		RRR_MSG_ERR("No server specified\n");
		ret = 1;
		goto out;
	}

	data->hostname= strdup(server);
	if (data->hostname == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Endpoint
	const char *endpoint = cmd_get_value(cmd, "endpoint", 0);
	if (cmd_get_value (cmd, "endpoint", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one endpoint argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (endpoint == NULL) {
		endpoint = "/";
	}

	data->endpoint = strdup(endpoint);
	if (data->endpoint == NULL) {
		RRR_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Query
	const char *query = cmd_get_value(cmd, "query", 0);
	if (cmd_get_value (cmd, "query", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one query argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (query != NULL) {
		data->query = strdup(query);
		if (data->query == NULL) {
			RRR_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// Force SSL
	if (cmd_exists(cmd, "ssl-force", 0)) {
		data->ssl_force = 1;
	}

	// Force Plaintext
	if (cmd_exists(cmd, "plain-force", 0)) {
		data->plain_force = 1;
	}

	if (data->ssl_force != 0 && data->plain_force != 0) {
		RRR_MSG_ERR("Both SSL-force and Plain-force (-S and -P) was set at the same time, but only one of them may be set simultaneously\n");
		ret = 1;
		goto out;
	}

	// HTTP port
	const char *port = cmd_get_value(cmd, "port", 0);
	uint64_t port_tmp = 0;
	if (cmd_get_value (cmd, "count", 1) != NULL) {
		RRR_MSG_ERR("Error: Only one 'count' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (port != NULL) {
		if (cmd_convert_uint64_10(port, &port_tmp)) {
			RRR_MSG_ERR("Could not understand argument 'count', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}
	if (port_tmp == 0) {
		if (data->ssl_force != 0) {
			port_tmp = 443;
		}
		else {
			port_tmp = 80;
		}
	}
	if (port_tmp < 1 || port_tmp > 65535) {
		RRR_MSG_ERR("HTTP port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->http_port = port_tmp;

	out:
	return ret;
}

static int __rrr_http_client_update_target_if_not_null (
		struct rrr_http_client_data *data,
		const char *protocol,
		const char *hostname,
		const char *endpoint,
		unsigned int port
) {
	if (protocol != NULL) {
		RRR_FREE_IF_NOT_NULL(data->protocol);
		if ((data->protocol = strdup(protocol)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for protocol in __rrr_http_client_update_target_if_not_null\n");
			return 1;
		}
	}

	if (hostname != NULL) {
		RRR_FREE_IF_NOT_NULL(data->hostname);
		if ((data->hostname = strdup(hostname)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for hostname in __rrr_http_client_update_target_if_not_null\n");
			return 1;
		}
	}

	if (endpoint != NULL) {
		RRR_FREE_IF_NOT_NULL(data->endpoint);
		if ((data->endpoint = strdup(endpoint)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for endpoint in __rrr_http_client_update_target_if_not_null\n");
			return 1;
		}
	}

	if (port > 0) {
		data->http_port = port;
	}

	return 0;
}

static int __rrr_http_client_receive_callback (
		struct rrr_http_session *session,
		const char *start,
		const char *end,
		void *arg
) {
	struct rrr_http_client_response *response = arg;
	struct rrr_http_part *part = session->response_part;

	int ret = 0;

	// If transfer encoding is chunked, we get called multiple times
	if (response->code != 0 || response->argument != NULL) {
		if (part->response_code < 200 || part->response_code > 299) {
			RRR_BUG("Multiple calls to __rrr_http_client_receive_callback with non-200 response code\n");
		}
		goto print_data;
	}

	response->code = part->response_code;

	// Moved-codes. Maybe this parsing is too persmissive.
	if (part->response_code >= 300 && part->response_code <= 399) {
		const struct rrr_http_header_field *location = rrr_http_part_get_header_field(part, "location");
		if (location == NULL) {
			RRR_MSG_ERR("Could not find Location-field in HTTP response %i %s\n",
					part->response_code, part->response_str);
			ret = 1;
		}
		RRR_DBG_1("HTTP Redirect to %s\n", location->value);

		if (response->argument != NULL) {
			RRR_BUG("Response argument was not NULL in __rrr_http_client_receive_callback, possible double call with non-200 response\n");
		}
		if ((response->argument = strdup(location->value)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for location string in __rrr_http_client_receive_callback\n");
			ret = 1;
			goto out;
		}

		goto out;
	}
	else if (part->response_code < 200 || part->response_code > 299) {
		RRR_MSG_ERR("Error while fetching HTTP: %i %s\n",
				part->response_code, part->response_str);
		ret = 1;
		goto out;
	}

	print_data:
	if (start != NULL && end != NULL) {
//		const char *separator_line = "=============================";
//		size_t separator_line_length = strlen(separator_line);

		int bytes;

//		bytes = write (STDOUT_FILENO, separator_line, separator_line_length);

		bytes = write (STDOUT_FILENO, start, end - start);
		if (bytes != end - start) {
			RRR_MSG_ERR("Error while printing HTTP response in __rrr_http_client_receive_callback\n");
			ret = 1;
			goto out;
		}

		//bytes = write (STDOUT_FILENO, separator_line, separator_line_length);
	}

	out:
	return ret;
}

static int __rrr_http_client_send_request (struct rrr_http_client_data *data) {
	int ret = 0;

	char *endpoint_and_query = NULL;

	if (data->session != NULL) {
		rrr_http_session_destroy(data->session);
		data->session = NULL;
	}

	if (data->endpoint == NULL || *(data->endpoint) == '\0') {
		RRR_FREE_IF_NOT_NULL(data->endpoint);
		if ((data->endpoint = strdup("/")) == NULL) {
			RRR_MSG_ERR("Could not allocate memory for endpoint in __rrr_http_client_send_request\n");
			ret = 1;
			goto out;
		}
	}

	if (data->query != NULL && *(data->query) != '\0') {
		if ((ret = rrr_asprintf(&endpoint_and_query, "%s?%s", data->endpoint, data->query)) <= 0) {
			RRR_MSG_ERR("Could not allocate string for endpoint and query in __rrr_http_client_send_request\n");
			ret = 1;
			goto out;
		}
	}
	else {
		if ((endpoint_and_query = strdup(data->endpoint)) == NULL) {
			RRR_MSG_ERR("Could not allocate string for endpoint in __rrr_http_client_send_request\n");
			ret = 1;
			goto out;
		}
	}

	int transport = RRR_HTTP_TRANSPORT_ANY;

	if (data->protocol != NULL) {
		if (strcasecmp(data->protocol, "http") == 0) {
			transport = RRR_HTTP_TRANSPORT_HTTP;
		}
		else if (strcasecmp(data->protocol, "https") == 0) {
			transport = RRR_HTTP_TRANSPORT_HTTPS;
		}
		else {
			RRR_MSG_ERR("Unknown transport protocol '%s' in __rrr_http_client_send_request, expected 'http' or 'https'\n", data->protocol);
			ret = 1;
			goto out;
		}
	}

	if (data->ssl_force != 0) {
		RRR_DBG_1("Forcing SSL/TLS\n");
		if (transport != RRR_HTTP_TRANSPORT_HTTPS && transport != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_ERR("Requested URI contained non-https transport while force SSL was active, cannot continue\n");
			ret = 1;
			goto out;
		}
		transport = RRR_HTTP_TRANSPORT_HTTPS;
	}
	if (data->plain_force != 0) {
		RRR_DBG_1("Forcing plaintext non-SSL/TLS\n");
		if (transport != RRR_HTTP_TRANSPORT_HTTPS && transport != RRR_HTTP_TRANSPORT_ANY) {
			RRR_MSG_ERR("Requested URI contained non-http transport while force plaintext was active, cannot continue\n");
			ret = 1;
			goto out;
		}
		transport = RRR_HTTP_TRANSPORT_HTTP;
	}

	RRR_DBG_1("Using server %s port %u transport %i\n", data->hostname, data->http_port, transport);
	RRR_DBG_1("Using endpoint and query: '%s'\n", endpoint_and_query);

	if ((ret = rrr_http_session_new (
			&data->session,
			transport,
//			RRR_HTTP_METHOD_POST_URLENCODED,
			RRR_HTTP_METHOD_GET,
			data->hostname,
			data->http_port,
			endpoint_and_query,
			RRR_HTTP_CLIENT_USER_AGENT
	)) != 0) {
		RRR_MSG_ERR("Could not create session in __rrr_http_client_send_request\n");
		goto out;
	}

	if ((ret = rrr_http_session_connect(data->session)) != 0) {
		RRR_MSG_ERR("Could not connect to server in __rrr_http_client_send_request\n");
		goto out;
	}

//	rrr_http_session_add_query_field(data->session, "a", "1");
//	rrr_http_session_add_query_field(data->session, "b", "2/(&(&%\"¤&!        #Q¤#!¤&/");
//	rrr_http_session_add_query_field(data->session, "\\\\\\\\", "\\\\");

	if ((ret = rrr_http_session_send_request(data->session)) != 0) {
		RRR_MSG_ERR("Could not send request in __rrr_http_client_send_request\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(endpoint_and_query);
	return ret;
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		RRR_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	rrr_strerror_init();

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;
	struct rrr_http_client_data data;
	struct rrr_http_client_response response = {0};

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_http_client_data_init(&data);

	if ((ret = main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out;
	}

	if (rrr_print_help_and_version(&cmd, 2) != 0) {
		goto out;
	}

	if ((ret = __rrr_http_client_parse_config(&data, &cmd)) != 0) {
		goto out;
	}

	int retry_max = 10;

	retry:
	if (--retry_max == 0) {
		RRR_MSG_ERR("Maximum number of retries reached\n");
		ret = 1;
		goto out;
	}

	__rrr_http_client_response_cleanup(&response);

	if ((ret = __rrr_http_client_send_request(&data)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_session_receive(data.session, __rrr_http_client_receive_callback, &response)) != 0) {
		goto out;
	}

	if (response.code >= 300 && response.code <= 399) {
		if (response.argument == NULL) {
			RRR_BUG("BUG: Argument was NULL with 300<=code<=399\n");
		}

		struct rrr_http_uri *uri = NULL;

		if (rrr_http_util_uri_parse(&uri, response.argument) != 0) {
			RRR_MSG_ERR("Could not parse Location from redirect response header\n");
			ret = 1;
			goto out;
		}

		RRR_DBG_1("Redirected to %s (%s, %s, %s, %u)\n",
				response.argument,
				(uri->protocol != NULL ? uri->protocol : "-"),
				(uri->host != NULL ? uri->host : "-"),
				(uri->endpoint != NULL ? uri->endpoint : "-"),
				uri->port
		);

		if (__rrr_http_client_update_target_if_not_null (
				&data,
				uri->protocol,
				uri->host,
				uri->endpoint,
				uri->port
		) != 0) {
			RRR_MSG_ERR("Could not update target after redirect\n");
			ret = 1;
			goto out;
		}

		rrr_http_util_uri_destroy(uri);

		goto retry;
	}

	out:
	__rrr_http_client_response_cleanup(&response);
	rrr_set_debuglevel_on_exit();
	__rrr_http_client_data_cleanup(&data);
	cmd_destroy(&cmd);
	rrr_socket_close_all();
	rrr_strerror_cleanup();
	return ret;
}
