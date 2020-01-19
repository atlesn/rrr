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
#include "lib/array.h"
#include "lib/linked_list.h"
#include "lib/rrr_socket.h"
#include "lib/rrr_socket_read.h"
#include "lib/rrr_socket_common.h"
#include "lib/vl_time.h"
#include "lib/messages.h"

#define RRR_POST_DEFAULT_ARRAY_DEFINITION "msg"

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"socket",				"{RRR SOCKET}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'f',	"file",					"[-f|--file[=]FILENAME|-]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA,	'r',	"readings",				"[-r|--readings[=]reading1,reading2,...]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA,	'a',	"array_definition",		"[-a|--array_definition[=]ARRAY DEFINITION]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'c',	"count",				"[-c|--count[=]MAX FILE ELEMENTS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	't',	"topic",				"[-t|--topic[=]MQTT TOPIC]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_post_reading {
	RRR_LL_NODE(struct rrr_post_reading);
	uint64_t value;
};

struct rrr_post_reading_collection {
	RRR_LL_HEAD(struct rrr_post_reading);
};

struct rrr_post_data {
	char *filename;
	char *socket_path;
	char *topic;
	struct rrr_post_reading_collection readings;
	uint64_t max_elements;
	uint64_t elements_count;
	struct rrr_array definition;

	int input_fd;
	int output_fd;
};

static void __rrr_post_data_init (struct rrr_post_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_post_destroy_data (struct rrr_post_data *data) {
	RRR_FREE_IF_NOT_NULL(data->filename);
	RRR_FREE_IF_NOT_NULL(data->socket_path);
	RRR_FREE_IF_NOT_NULL(data->topic);
	RRR_LL_DESTROY(&data->readings, struct rrr_post_reading, free(node));
	rrr_array_clear(&data->definition);
}

static int __rrr_post_add_readings (struct rrr_post_data *data, struct cmd_data *cmd) {
	for (int i = 0; 1; i++) {
		const char *reading = cmd_get_value(cmd, "readings", i);
		if (reading != NULL) {
			for (int j = 0; 1; j++) {
				reading = cmd_get_subvalue(cmd, "readings", i, j);
				if (reading != NULL) {
					uint64_t value;
					if (cmd_convert_uint64_10(reading, &value) != 0) {
						VL_MSG_ERR("Error in reading '%s', not an unsigned integer\n", reading);
						return 1;
					}
					struct rrr_post_reading *reading_new = malloc(sizeof(*reading_new));
					if (reading_new == NULL) {
						VL_MSG_ERR("Could not allocate memory in __rrr_post_add_readings\n");
						return 1;
					}
					reading_new->value = value;
					RRR_LL_APPEND(&data->readings, reading_new);
				}
				else {
					break;
				}
			}
		}
		else {
			break;
		}
	}
	return 0;
}

static int __rrr_post_parse_config (struct rrr_post_data *data, struct cmd_data *cmd) {
	int ret = 0;

	// Socket
	const char *socket = cmd_get_value(cmd, "socket", 0);
	if (socket == NULL || *socket == '\0') {
		VL_MSG_ERR("No socket path specified\n");
		ret = 1;
		goto out;
	}

	data->socket_path = strdup(socket);
	if (data->socket_path == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Filename
	const char *filename = cmd_get_value(cmd, "file", 0);
	if (cmd_get_value (cmd, "file", 1) != NULL) {
		VL_MSG_ERR("Error: Only one filename argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (filename != NULL) {
		data->filename = strdup(filename);
		if (data->filename == NULL) {
			VL_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	const char *topic = cmd_get_value(cmd, "topic", 0);
	if (cmd_get_value (cmd, "topic", 1) != NULL) {
		VL_MSG_ERR("Error: Only one topic argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (topic != NULL) {
		data->topic = strdup(topic);
		if (data->topic == NULL) {
			VL_MSG_ERR("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// Readings
	if (__rrr_post_add_readings(data, cmd) != 0) {
		goto out;
	}

	// Count
	const char *max_elements = cmd_get_value(cmd, "count", 0);
	if (cmd_get_value (cmd, "count", 1) != NULL) {
		VL_MSG_ERR("Error: Only one 'count' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (max_elements != NULL) {
		if (cmd_convert_uint64_10(max_elements, &data->max_elements)) {
			VL_MSG_ERR("Could not understand argument 'count', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}

	// Array definition
	const char *array_definition = cmd_get_value(cmd, "array_definition", 0);

	struct rrr_array_parse_single_definition_callback_data callback_data = {
			&data->definition, 0
	};

	if (array_definition == NULL) {
		ret = rrr_array_parse_single_definition_callback(RRR_POST_DEFAULT_ARRAY_DEFINITION, &callback_data);
	}
	else {
		if (cmd_iterate_subvalues (
				cmd,
				"array_definition",
				0,
				rrr_array_parse_single_definition_callback,
				&callback_data
		) != 0 ) {
			ret = 1;
		}
	}

	if (ret != 0 || callback_data.parse_ret != 0 || rrr_array_validate_definition(&data->definition) != 0) {
		VL_MSG_ERR("Error while parsing array definition\n");
		ret = 1;
		goto out;
	}

	if (cmd_get_value (cmd, "array_definition", 1) != NULL) {
		VL_MSG_ERR("Error: Only one array_definition argument may be specified\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_post_connect(struct rrr_post_data *data) {
	int ret = 0;

	if (rrr_socket_unix_create_and_connect(&data->output_fd, "rrr_post", data->socket_path, 0) != 0) {
		VL_MSG_ERR("Could not connect to socket\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_post_open(struct rrr_post_data *data) {
	int ret = 0;

	if (data->filename == NULL) {
		data->input_fd = -1;
	}
	else if (strcmp(data->filename, "-") == 0) {
		data->input_fd = STDIN_FILENO;
	}
	else {
		data->input_fd = rrr_socket_open(data->filename, O_RDONLY, "rrr_post");
		if (data->input_fd < 0) {
			VL_MSG_ERR("Could not open input file %s: %s\n",
					data->filename, strerror(errno));
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static void __rrr_post_close(struct rrr_post_data *data) {
	if (data->output_fd > 0) {
		rrr_socket_close(data->output_fd);
	}
	if (data->input_fd > 0) {
		rrr_socket_close(data->input_fd);
	}
}

static int __rrr_post_send_message(struct rrr_post_data *data, struct vl_message *message) {
	int ret = 0;

	ssize_t msg_size = MSG_TOTAL_SIZE(message);

	message_prepare_for_network((struct vl_message *) message);
	rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message);

	if ((ret = rrr_socket_sendto(data->output_fd, message, msg_size, NULL, 0)) != 0) {
		VL_MSG_ERR("Error while sending message in __rrr_post_send_message\n");
		goto out;
	}

	out:
	return ret;
}

static int __rrr_post_send_reading(struct rrr_post_data *data, struct rrr_post_reading *reading) {
	int ret = 0;

	struct vl_message *message = message_new_reading(reading->value, time_get_64());
	if (message == NULL) {
		VL_MSG_ERR("Could not allocate message in __rrr_post_send_reading\n");
		ret = 1;
		goto out;
	}

	ret = __rrr_post_send_message(data, message);

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

static int __rrr_post_send_readings(struct rrr_post_data *data) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&data->readings, struct rrr_post_reading);
		if ((ret = __rrr_post_send_reading(data, node)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END(&data->readings);

	out:
	return ret;
}

static int __rrr_post_read_message_callback (struct vl_message *message, void *arg) {
	struct rrr_post_data *data = arg;
	int ret = 0;

	ret = __rrr_post_send_message(data, message);

	data->elements_count++;

	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

static int __rrr_post_read_callback(struct rrr_socket_read_session *read_session, void *arg) {
	struct rrr_post_data *data = arg;

	int ret = 0;

	if ((ret = rrr_array_new_message_from_buffer_with_callback (
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			data->topic,
			(data->topic != NULL ? strlen(data->topic) : 0),
			&data->definition,
			__rrr_post_read_message_callback,
			data
	)) != 0) {
		VL_MSG_ERR("Could not create or send message in __rrr_post_read_callback\n");
		goto out;
	}

	out:
	return ret;
}

static int __rrr_post_read(struct rrr_post_data *data) {
	int ret = 0;

	struct rrr_socket_read_session_collection read_sessions;
	rrr_socket_read_session_collection_init(&read_sessions);

	if (data->filename == NULL) {
		goto out;
	}

	int read_flags = RRR_SOCKET_READ_METHOD_READ_FILE | RRR_SOCKET_READ_USE_TIMEOUT;
	if (data->max_elements == 0 && strcmp (data->filename, "-") != 0) {
		read_flags |= RRR_SOCKET_READ_CHECK_EOF;
	}

	while (ret == 0 && (data->max_elements == 0 || data->elements_count < data->max_elements)) {
		ret = rrr_socket_common_receive_array (
				&read_sessions,
				data->input_fd,
				read_flags,
				&data->definition,
				0, // Sync byte by byte
				__rrr_post_read_callback,
				data
		);
	}

	if (ret == RRR_SOCKET_READ_EOF) {
		VL_DEBUG_MSG_1("End of file reached\n");
		ret = 0;
	}

	out:
	rrr_socket_read_session_collection_clear(&read_sessions);
	return ret;
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;
	struct rrr_post_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_post_data_init(&data);

	if ((ret = main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out;
	}

	if (rrr_print_help_and_version(&cmd) != 0) {
		goto out;
	}

	if ((ret = __rrr_post_parse_config(&data, &cmd)) != 0) {
		goto out;
	}

	// Connect to RRR socket
	if ((ret = __rrr_post_connect(&data)) != 0) {
		goto out;
	}

	// Send readings defined in command arguments
	if ((ret = __rrr_post_send_readings(&data)) != 0) {
		goto out;
	}

	// Open input file if defined
	if ((ret = __rrr_post_open(&data)) != 0) {
		goto out;
	}

	// Send readings from input file or stdin
	if ((ret = __rrr_post_read(&data)) != 0) {
		goto out;
	}

	out:
	rrr_set_debuglevel_on_exit();
	__rrr_post_close(&data);
	__rrr_post_destroy_data(&data);
	cmd_destroy(&cmd);
	rrr_socket_close_all();
	return ret;
}
