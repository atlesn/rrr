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
#include <lib/read.h>
#include <signal.h>

#include "main.h"
#include "../build_timestamp.h"
#include "lib/rrr_config.h"
#include "lib/log.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/array.h"
#include "lib/array_tree.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_read.h"
#include "lib/socket/rrr_socket_common.h"
#include "lib/rrr_strerror.h"
#include "lib/read.h"
#include "lib/messages/msg_msg.h"
#include "lib/util/rrr_time.h"
#include "lib/util/gnu.h"
#include "lib/util/linked_list.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_post");

#define RRR_POST_DEFAULT_ARRAY_DEFINITION	"msg"
#define RRR_POST_DEFAULT_MAX_MESSAGE_SIZE	4096

static volatile int rrr_post_abort = 0;
static volatile int rrr_post_print_stats = 0;

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"socket",				"{RRR SOCKET}"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'f',	"file",					"[-f|--file[=]FILENAME|-]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA,	'r',	"readings",				"[-r|--readings[=]reading1,reading2,...]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'a',	"array_definition",		"[-a|--array_definition[=]ARRAY DEFINITION]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'm',	"max-message-size",		"[-m|--max-message-size]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'c',	"count",				"[-c|--count[=]MAX FILE ELEMENTS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	't',	"topic",				"[-t|--topic[=]MQTT TOPIC]"},
		{0,							's',	"sync",					"[-s|--sync]"},
		{0,							'q',	"quiet",				"[-q|--quiet]"},
		{0,							'l',	"loglevel-translation",	"[-l|--loglevel-translation]"},
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
	uint64_t max_message_size;
	uint64_t elements_count;
	struct rrr_array_tree *tree;

	int sync_byte_by_byte;
	int quiet;

	int input_fd;
	int output_fd;

	uint64_t start_time;
};

static void __rrr_post_signal_handler (int s) {
	if (s == SIGUSR1) {
		rrr_post_print_stats = 1;
	}
	else if (s == SIGPIPE) {
		RRR_MSG_0("Received SIGPIPE, ignoring\n");
	}
	else if (s == SIGTERM) {
		RRR_MSG_0("Received SIGTERM, exiting\n");
		exit(EXIT_FAILURE);
	}
	else if (s == SIGINT) {
		// Allow double ctrl+c to close program immediately
		signal(SIGINT, SIG_DFL);
		rrr_post_abort = 1;
	}
}

static void __rrr_post_data_init (struct rrr_post_data *data) {
	memset (data, '\0', sizeof(*data));
	data->start_time = rrr_time_get_64();
}

static void __rrr_post_destroy_data (struct rrr_post_data *data) {
	RRR_FREE_IF_NOT_NULL(data->filename);
	RRR_FREE_IF_NOT_NULL(data->socket_path);
	RRR_FREE_IF_NOT_NULL(data->topic);
	RRR_LL_DESTROY(&data->readings, struct rrr_post_reading, free(node));
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}
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
						RRR_MSG_0("Error in reading '%s', not an unsigned integer\n", reading);
						return 1;
					}
					struct rrr_post_reading *reading_new = malloc(sizeof(*reading_new));
					if (reading_new == NULL) {
						RRR_MSG_0("Could not allocate memory in __rrr_post_add_readings\n");
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

	char *array_tree_tmp = NULL;

	// Socket
	const char *socket = cmd_get_value(cmd, "socket", 0);
	if (socket == NULL || *socket == '\0') {
		RRR_MSG_0("No socket path specified\n");
		ret = 1;
		goto out;
	}

	data->socket_path = strdup(socket);
	if (data->socket_path == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
		ret = 1;
		goto out;
	}

	// Sync byte by byte
	if (cmd_exists(cmd, "sync", 0)) {
		data->sync_byte_by_byte = 1;
	}
	else {
		data->sync_byte_by_byte = 0;
	}

	// Quiet operation
	if (cmd_exists(cmd, "quiet", 0)) {
		data->quiet = 1;
	}
	else {
		data->quiet = 0;
	}

	// Filename
	const char *filename = cmd_get_value(cmd, "file", 0);
	if (cmd_get_value (cmd, "file", 1) != NULL) {
		RRR_MSG_0("Error: Only one filename argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (filename != NULL) {
		data->filename = strdup(filename);
		if (data->filename == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	const char *topic = cmd_get_value(cmd, "topic", 0);
	if (cmd_get_value (cmd, "topic", 1) != NULL) {
		RRR_MSG_0("Error: Only one topic argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (topic != NULL) {
		data->topic = strdup(topic);
		if (data->topic == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_post_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// Readings
	if ((ret = __rrr_post_add_readings(data, cmd)) != 0) {
		goto out;
	}

	// Count
	const char *max_elements = cmd_get_value(cmd, "count", 0);
	if (cmd_get_value (cmd, "count", 1) != NULL) {
		RRR_MSG_0("Error: Only one 'count' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (max_elements != NULL) {
		if (cmd_convert_uint64_10(max_elements, &data->max_elements)) {
			RRR_MSG_0("Could not understand argument 'count', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}

	// Array definition
	const char *array_definition = cmd_get_value(cmd, "array_definition", 0);

	if (array_definition == NULL || *array_definition == '\0') {
		array_definition = RRR_POST_DEFAULT_ARRAY_DEFINITION;
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

	if (cmd_get_value (cmd, "array_definition", 1) != NULL) {
		RRR_MSG_0("Error: Only one array_definition argument may be specified\n");
		ret = 1;
		goto out;
	}

	// Max message size, make sure default value is being set
	data->max_message_size = RRR_POST_DEFAULT_MAX_MESSAGE_SIZE;

	const char *max_message_size = cmd_get_value(cmd, "max-message-size", 0);
	if (cmd_get_value (cmd, "max-message-size", 1) != NULL) {
		RRR_MSG_0("Error: Only one 'max-message-size' argument may be specified\n");
		ret = 1;
		goto out;
	}
	if (max_message_size != NULL) {
		if (cmd_convert_uint64_10(max_message_size, &data->max_message_size)) {
			RRR_MSG_0("Could not understand argument 'max-message-size', must be and unsigned integer\n");
			ret = 1;
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(array_tree_tmp);
	return ret;
}

static int __rrr_post_connect(struct rrr_post_data *data) {
	int ret = 0;

	if (rrr_socket_unix_connect(&data->output_fd, "rrr_post", data->socket_path, 0) != RRR_SOCKET_OK) {
		RRR_MSG_0("Could not connect to socket\n");
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
		data->input_fd = rrr_socket_open(data->filename, O_RDONLY, 0, "rrr_post", 0);
		if (data->input_fd < 0) {
			RRR_MSG_0("Could not open input file %s: %s\n",
					data->filename, rrr_strerror(errno));
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

static int __rrr_post_send_message(struct rrr_post_data *data, struct rrr_msg_msg *message) {
	int ret = 0;

	if ((ret = rrr_socket_common_prepare_and_send_msg_blocking((struct rrr_msg *) message, data->output_fd, NULL)) != 0) {
		RRR_MSG_0("Error while sending message in __rrr_post_send_message\n");
		goto out;
	}

	out:
	return ret;
}

static int __rrr_post_send_reading(struct rrr_post_data *data, struct rrr_post_reading *reading) {
	int ret = 0;

	char *text = NULL;
	if (rrr_asprintf(&text, "%" PRIu64, reading->value) <= 0) {
		RRR_MSG_0("Could not create reading text in __rrr_post_send_reading\n");
		ret = 1;
		goto out;
	}

	struct rrr_msg_msg *message = NULL;
	if (rrr_msg_msg_new_empty(&message, MSG_TYPE_MSG, MSG_CLASS_DATA, rrr_time_get_64(), 0, strlen(text) + 1)) {
		RRR_MSG_0("Could not allocate message in __rrr_post_send_reading\n");
		ret = 1;
		goto out;
	}

	memcpy(MSG_DATA_PTR(message), text, strlen(text) + 1);

	ret = __rrr_post_send_message(data, message);

	out:
	RRR_FREE_IF_NOT_NULL(text);
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

static int __rrr_post_send_readings(struct rrr_post_data *data) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&data->readings, struct rrr_post_reading);
		if ((ret = __rrr_post_send_reading(data, node)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}
struct rrr_post_read_callback_data {
	struct rrr_post_data *data;
};

static int __rrr_post_read_callback (struct rrr_read_session *read_session, struct rrr_array *array_final, void *arg) {
	struct rrr_post_read_callback_data *callback_data = arg;
	struct rrr_post_data *data = callback_data->data;

	(void)(read_session);

	int ret = 0;

	struct rrr_msg_msg *message = NULL;

	if ((ret = rrr_array_new_message_from_collection (
			&message,
			array_final,
			rrr_time_get_64(),
			data->topic,
			(data->topic != NULL ? strlen(data->topic) : 0)
	)) != 0) {
		RRR_MSG_0("Could not create or send message in __rrr_post_read_callback\n");
		goto out;
	}

	if ((ret = __rrr_post_send_message(data, message)) != 0) {
		// Message printed in called function
	}

	data->elements_count++;

	out:
	RRR_FREE_IF_NOT_NULL(message);

	return ret;
}

static void __rrr_post_print_statistics (struct rrr_post_data *data) {
	uint64_t runtime = rrr_time_get_64() - data->start_time;
	runtime = runtime / 1000 / 1000;

	if (runtime == 0) {
		runtime = 1;
	}

	uint64_t speed = data->elements_count / runtime;

	RRR_DBG("Processed messages: %" PRIu64 " (%" PRIu64 " m/s), limit: %" PRIu64 ", run time: %" PRIu64 "\n",
			data->elements_count,
			speed,
			data->max_elements,
			runtime
	);
}

static int __rrr_post_read (struct rrr_post_data *data) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	struct rrr_read_session_collection read_sessions;
	rrr_read_session_collection_init(&read_sessions);

	if (data->filename == NULL) {
		goto out;
	}

	int socket_read_flags = RRR_SOCKET_READ_METHOD_READ_FILE | RRR_SOCKET_READ_USE_TIMEOUT | RRR_SOCKET_READ_NO_GETSOCKOPTS;
	if (data->max_elements == 0 && strcmp (data->filename, "-") != 0) {
		socket_read_flags |= RRR_SOCKET_READ_CHECK_EOF;
	}

	struct rrr_post_read_callback_data callback_data = {
			data
	};
	while (	ret == 0 &&
			(data->max_elements == 0 || data->elements_count < data->max_elements) &&
			rrr_post_abort == 0
	) {
		uint64_t bytes_read = 0;
		ret = rrr_socket_common_receive_array_tree (
				&bytes_read,
				&read_sessions,
				data->input_fd,
				socket_read_flags,
				&array_tmp,
				data->tree,
				data->sync_byte_by_byte,
				data->max_message_size,
				__rrr_post_read_callback,
				&callback_data
		);

		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_MSG_0("Warning: Invalid or unexpected data received\n");
			ret = 0;
		}

		if (rrr_post_print_stats != 0) {
			__rrr_post_print_statistics(data);
			rrr_post_print_stats = 0;
		}
	}

	if (ret == RRR_SOCKET_READ_EOF) {
		RRR_DBG_1("End of file reached\n");
		ret = 0;
	}

	out:
	rrr_array_clear(&array_tmp);
	rrr_read_session_collection_clear(&read_sessions);
	return ret;
}

int main (int argc, const char *argv[]) {
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
	struct rrr_post_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_post_data_init(&data);

	if ((ret = rrr_main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out;
	}

	if (rrr_main_print_help_and_version(&cmd, 2) != 0) {
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

	struct sigaction action;
	action.sa_handler = __rrr_post_signal_handler;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	// We generally ignore sigpipe and use NONBLOCK on all sockets
	sigaction (SIGPIPE, &action, NULL);
	// Used to set rrr_post_abort = 1. The signal is set to default afterwards
	// so that a second SIGINT will terminate the process
	sigaction (SIGINT, &action, NULL);
	// Used to print statistics
	sigaction (SIGUSR1, &action, NULL);
	// Exit immediately with EXIT_FAILURE
	sigaction (SIGTERM, &action, NULL);

	// Send readings from input file or stdin
	if ((ret = __rrr_post_read(&data)) != 0) {
		goto out;
	}

	out:
		if (data.quiet == 0) {
			__rrr_post_print_statistics(&data);
		}

		rrr_config_set_debuglevel_on_exit();
		__rrr_post_close(&data);
		__rrr_post_destroy_data(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_final:
		return ret;
}
