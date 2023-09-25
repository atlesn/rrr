/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>

#include "main.h"
#include "lib/version.h"
#include "lib/allocator.h"
#include "lib/log.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/random.h"
#include "lib/common.h"
#include "lib/util/rrr_endian.h"
#include "lib/cmdlineparser/cmdline.h"

#define RRR_MODBUS_PORT 502
#define RRR_MODBUS_PORT_ALTERNATE 5022
#define RRR_MODBUS_BUFFER_SIZE 1024

struct rrr_modbus_server_data {
	uint16_t port;
};

static int __rrr_modbus_server_parse_config (struct rrr_modbus_server_data *data, struct cmd_data *cmd) {
	int ret = 0;

	uint64_t port_tmp;
	const char *port;

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
		port_tmp = RRR_MODBUS_PORT;
	}
	else if (port_tmp > 65535) {
		RRR_MSG_0("Port out of range (must be 1-65535, got %" PRIu64 ")\n", port_tmp);
		ret = 1;
		goto out;
	}
	data->port = (uint16_t) port_tmp;

	out:
	return ret;
}

static int main_running = 1;
static int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'p',    "port",                  "[-p|--port[=]HTTP PORT]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_modbus_server");

static int __make_response (
		size_t *bytes_consumed,
		char *dst_buf,
		size_t *dst_buf_size,
		const char *src_buf,
		const size_t *src_buf_size
) {
	int ret = 0;
/*
	if (rrr_rand() % 100 > 90) {
		rrr_random_string(dst_buf, *dst_buf_size);
		size_t size = ((size_t) rrr_rand()) % 10 + 1;
		assert(*dst_buf_size >= size);
		*dst_buf_size = size;
		RRR_DBG_1("Generated random junk data size %llu\n", (unsigned long long) size);
		goto out;
	}
*/
	assert(*dst_buf_size >= *src_buf_size);

	memcpy(dst_buf, src_buf, *src_buf_size);
	*dst_buf_size = *src_buf_size;

	uint8_t exception = 0x01; /* Illegal function */

	if (*src_buf_size < 7) {
		RRR_DBG_1("Frame too short\n");
		ret = 1;
		goto out;
	}
	RRR_DBG_1("Request %u received, making response.\n", dst_buf[7]);

	uint16_t length = rrr_be16toh(*((uint16_t *) &dst_buf[4]));

	switch(dst_buf[7]) { // Function code
		case 0x01:
		case 0x02:
			if (dst_buf[10] != 0 || dst_buf[11] != 8) {
				RRR_DBG_1("Illegal address/quantity %u/%u for function 0x01\n", dst_buf[10], dst_buf[11]);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			if (length < 6) {
				RRR_DBG_1("Length %u too short function 0x01\n", length);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 4;     // Length low
			dst_buf[8] = 1;     // Byte count
			dst_buf[9] = 0x01;  // Coil status 0
			*dst_buf_size = 10;
			*bytes_consumed = 12;
			break;
		case 0x03:
			if (dst_buf[10] != 0 || dst_buf[11] != 1) {
				RRR_DBG_1("Illegal address/quantity %u/%u for function 0x03\n", dst_buf[10], dst_buf[11]);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			if (length < 6) {
				RRR_DBG_1("Length %u too short function 0x03\n", length);
				exception = 0x02; /* Illegal data address */
				goto exception;
			}
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 5;     // Length low
			dst_buf[8] = 2;     // Byte count
			dst_buf[9] = 0x01;  // Register high
			dst_buf[10] = 0x01;  // Register low
			*dst_buf_size = 11;
			*bytes_consumed = 12;
			break;
		default:
			RRR_DBG_1("Illegal function 0x%u\n", dst_buf[7]);
			goto exception;
	}

	goto out;
	exception:
		dst_buf[4] = 0;     // Length high
		dst_buf[5] = 3;     // Length low
		dst_buf[7] += 0x80;
		dst_buf[8] = (char) exception;
		*dst_buf_size = 9;
	out:
		return ret;
}

int main(int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	int server_fd, client_fd;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_len;
	ssize_t bytes;
	char buf[RRR_MODBUS_BUFFER_SIZE];
	char buf2[RRR_MODBUS_BUFFER_SIZE];
	size_t buf_size, buf2_size, bytes_consumed, bytes_offset;
	struct rrr_signal_handler *signal_handler;
	struct cmd_data cmd;
	struct rrr_modbus_server_data modbus_data = {0};

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}

	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_strerror_init();

	cmd_init(&cmd, cmd_rules, argc, argv);

	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 0) != 0) {
		goto out_cleanup_signal;
	}

	if (__rrr_modbus_server_parse_config (&modbus_data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		RRR_MSG_0("Failed to create listening socket: %s\n", rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	bind_again:

	memset(&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(modbus_data.port);

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		if (modbus_data.port != RRR_MODBUS_PORT_ALTERNATE) {
			RRR_MSG_1("Listening on port %u failed (%s), trying alternate port %u\n",
				modbus_data.port, rrr_strerror(errno), RRR_MODBUS_PORT_ALTERNATE);
			modbus_data.port = RRR_MODBUS_PORT_ALTERNATE;
			goto bind_again;
		}
		RRR_MSG_0("Failed to bind to TCP port %u: %s\n", modbus_data.port, rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out_close;
	}

	if (listen(server_fd, 1) < 0) {
		RRR_MSG_0("Failed to listen: %s\n", rrr_strerror(errno));
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	RRR_DBG_1("Listening on port %u\n", modbus_data.port);

	rrr_signal_default_signal_actions_register();
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	while (main_running) {
		RRR_DBG_1("Accepting connection...\n");

		client_addr_len = sizeof(client_addr);
		if ((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
			if (errno == EINTR) {
				RRR_DBG_1("Accept interrupted\n");
				continue;
			}
			RRR_MSG_0("Error while accepting: %s\n", rrr_strerror(errno));
			continue;
		}

		while (main_running) {
			bytes_offset = 0;
			bytes = recv(client_fd, buf, sizeof(buf), 0);
			if (bytes <= 0) {
				if (errno == EINTR) {
					RRR_DBG_1("Recv interrupted\n");
					continue;
				}
				RRR_DBG_1("Connection closed: %lli %s\n",
					(long long int) bytes, rrr_strerror(errno));
				break;
			}

			RRR_DBG_2("Read data size %llu\n", (long long unsigned) bytes);

			again:

			buf_size = (size_t) bytes - bytes_offset;
			buf2_size = sizeof(buf2);

			RRR_DBG_2("Process request size %llu\n", (long long unsigned) buf_size);

			if (__make_response (
					&bytes_consumed,
					buf2,
					&buf2_size,
					buf + bytes_offset,
					&buf_size
			) != 0) {
				break;
			}

			if (bytes_consumed < buf_size) {
				bytes_offset += bytes_consumed;
				goto again;
			}

			RRR_DBG_2("Write response size %llu\n", (long long unsigned) buf2_size);

			if (write(client_fd, buf2, buf2_size) != (ssize_t) buf2_size) {
				RRR_MSG_0("Write to client failed: %s\n", rrr_strerror(errno));
				break;
			}
		}

		RRR_DBG_1("Closing connection\n");

		close(client_fd);
	}

	if (!main_running) {
		RRR_DBG_1("Exiting after received signal\n");
	}

	out_close:
		close(server_fd);
	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
		cmd_destroy(&cmd);
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
