/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "lib/log.h"
#include "lib/allocator.h"

#include "lib/rrr_types.h"
#include "lib/socket/rrr_socket_constants.h"
#include "lib/type.h"
#include "main.h"
#include "../build_timestamp.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/array.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_client.h"
#include "lib/event/event.h"
#include "lib/messages/msg_msg.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_logd");

static volatile int main_running = 1;
static volatile int sigusr2 = 0;

int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,   's',    "socket",                "[-s|--socket[=]SOCKET]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'f',    "file-descriptor",       "[-f|--file-descriptor[=]FILE DESCRIPTOR]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'p',    "persist",               "[-p|--persist]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'l',    "loglevel-translation",  "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'h',    "help",                  "[-h|--help]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'v',    "version",               "[-v|--version]"},
        {0,                           '\0',    NULL,                   NULL}
};

struct rrr_logd_data {
	const char *receive_socket;
	int receive_socket_fd;
	int receive_fd;
	int persist;
};

static int rrr_logd_parse_config (struct rrr_logd_data *data, struct cmd_data *cmd) {
	const char *receive_socket;
	const char *receive_fd_str;

	receive_socket = cmd_get_value(cmd, "socket", 0);
	if (cmd_get_value(cmd, "socket", 1) != NULL) {
		RRR_MSG_0("Argument 'socket' may not be specified multiple times\n");
		return 1;
	}

	receive_fd_str = cmd_get_value(cmd, "file-descriptor", 0);
	if (cmd_get_value(cmd, "file-descriptor", 1) != NULL) {
		RRR_MSG_0("Argument 'file-descriptor' may not be specified multiple times\n");
		return 1;
	}

	if (receive_socket == NULL && receive_fd_str == NULL) {
		RRR_MSG_0("Neither 'file-descriptor' nor 'socket' argument was specified\n");
		return 1;
	}

	if (receive_socket != NULL) {
		data->receive_socket = receive_socket;
	}

	if (receive_fd_str != NULL) {
		long fd_tmp;
		if (cmd_convert_integer_10(receive_fd_str, &fd_tmp) != 0) {
			RRR_MSG_0("Failed to convert 'file-descriptor' argument to integer\n");
			return 1;
		}
#if LONG_MAX > INT_MAX
		if (fd_tmp > INT_MAX) {
			RRR_MSG_0("Value for 'file-descriptor' too high\n");
			return 1;
		}
#endif
		if (fd_tmp < 2) {
			RRR_MSG_0("Value for 'file-descriptor' must be greater than 2\n");
			return 1;
		}

		data->receive_fd = rrr_int_from_slength_bug_const(fd_tmp);
	}

	if (cmd_exists(cmd, "persist", 0)) {
		data->persist = 1;
	}

	return 0;
}

static int rrr_logd_socket_setup(struct rrr_logd_data *data) {
	if (data->receive_socket == NULL)
		return 0;

	if (rrr_socket_unix_create_bind_and_listen (
			&data->receive_socket_fd,
			"rrr_logd",
			data->receive_socket,
			SOMAXCONN,
			1, /* Non-blocking */
			0, /* No mkstemp */
			0  /* No unlink if exists */
	) != 0) {
		return 1;
	}

	return 0;
}

static int rrr_logd_periodic (void *arg) {
	struct rrr_logd_data *data = arg;

	(void)(data);

	if (!main_running)
		return RRR_EVENT_EXIT;

	return RRR_EVENT_OK;
}

static void rrr_logd_print (
	const char *file,
	int line,
	uint8_t loglevel,
	const char *prefix,
	const char *message
) {
	if (line == 0 || file == NULL || *file == '\0') {
		line = __LINE__;
		file = __FILE__;
	}

	if (prefix == NULL || *prefix == '\0') {
		prefix = "rrr_logd";
	}

	assert(message != NULL);

	rrr_log_printf_nolock (
			file,
			line,
			loglevel,
			prefix,
			"%s\n",
			message
	);
}

static int rrr_logd_read_message_extract_uint_field (
		uint64_t *target,
		struct rrr_array *array,
		const char *field,
		int mandatory
) {
	int ret = RRR_READ_OK;

	const struct rrr_type_value *value_tmp;

	if ((value_tmp = rrr_array_value_get_by_tag_const(array, field)) == NULL && mandatory) {
		RRR_MSG_0("Received array message did not have the required field '%s'\n",
			field);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}
	else if (value_tmp == NULL) {
		goto out;
	}
	else if (!RRR_TYPE_IS_64(value_tmp->definition->type)) {
		RRR_MSG_0("The field '%s' of received array message was not an integer\n",
			field);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}
	else if (!RRR_TYPE_FLAG_IS_UNSIGNED(value_tmp->definition->type)) {
		RRR_MSG_0("The field '%s' of received array message was not unsigned\n",
			field);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (rrr_array_get_value_unsigned_64_by_tag(target, array, "log_level", 0)) {
		RRR_MSG_0("Failed to get unsigned field '%s' from array\n",
			field);
		ret = RRR_READ_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int rrr_logd_read_msg_extract_string_field (
		char **target,
		struct rrr_array *array,
		const char *field,
		int mandatory
) {
	int ret = RRR_READ_OK;

	const struct rrr_type_value *value_tmp;

	if ((value_tmp = rrr_array_value_get_by_tag_const(array, field)) == NULL && mandatory) {
		RRR_MSG_0("Received array message did not have the required field '%s'\n",
			field);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}
	else if (value_tmp == NULL) {
		goto out;
	}
	else if (!RRR_TYPE_IS_STR(value_tmp->definition->type)) {
		RRR_MSG_0("The field '%s' of received array message was not a string\n",
			field);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (rrr_array_get_value_str_by_tag(target, array, field) != 0) {
		RRR_MSG_0("Failed to get string field '%s' from array\n",
			field);
		ret = RRR_READ_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int rrr_logd_read_msg_callback (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_msg_msg *msg = *message;
	struct rrr_logd_data *data = arg1;

	struct rrr_array array = {0};
	char *log_message = NULL;
	char *log_prefix = NULL;
	char *log_file = NULL;
	uint64_t log_level = 7;
	uint64_t log_line = 0;

	int ret = RRR_READ_OK;

	(void)(arg2);

	if (!MSG_IS_ARRAY(msg)) {
		RRR_MSG_0("Received non-array RRR standard message from client, this is not supported\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	uint16_t array_version;
	if ((ret = rrr_array_message_append_to_array(&array_version, &array, msg)) != 0) {
		goto out;
	}

	if ((ret = rrr_logd_read_msg_extract_string_field(&log_message, &array, "log_message", 1)) != 0) {
		goto out;
	}

	if ((ret = rrr_logd_read_msg_extract_string_field(&log_prefix, &array, "log_prefix", 0)) != 0) {
		goto out;
	}

	if ((ret = rrr_logd_read_msg_extract_string_field(&log_prefix, &array, "log_file", 0)) != 0) {
		goto out;
	}

	if ((ret = rrr_logd_read_message_extract_uint_field(&log_level, &array, "log_level", 0)) != 0) {
		goto out;
	}

	if (log_level > 7) {
		RRR_MSG_0("Log level in received array message exceeded the maximum of 7\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if ((ret = rrr_logd_read_message_extract_uint_field(&log_line, &array, "log_line", 0)) != 0) {
		goto out;
	}

	if (log_line > INT_MAX) {
		RRR_MSG_0("Line number in received array message exceeded the maximum of %i\n", INT_MAX);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	rrr_logd_print (
			log_file,
			log_line,
			log_level,
			log_prefix,
			log_message
	);

	out:
	RRR_FREE_IF_NOT_NULL(log_message);
	RRR_FREE_IF_NOT_NULL(log_prefix);
	RRR_FREE_IF_NOT_NULL(log_file);
	rrr_array_clear(&array);
	return ret;
}

static int rrr_logd_read_log_callback (
		const struct rrr_msg_log *message,
		void *arg1,
		void *arg2
) {
	assert(0 && "Read log not implemented");
	return 0;
}

static int rrr_logd_read_ctrl_callback (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	assert(0 && "Read ctrl no implemented");
	return 0;
}

static void rrr_logd_fd_close_callback (RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS) {
	struct rrr_logd_data *data = arg;

	(void)(addr);
	(void)(addr_len);
	(void)(addr_string);

	if (!main_running)
		return;

	if (data->persist &&
	    create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_INBOUND)
		return;

	RRR_DBG_1("Received close notification for fd %i, stopping now. Was finalized is %i.\n",
		fd, was_finalized);
	main_running = 0;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler = NULL;
	struct cmd_data cmd = {0};
	struct rrr_logd_data data = {0};
	struct rrr_event_queue *events;
	struct rrr_socket_client_collection *clients;

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
	rrr_signal_default_signal_actions_register();

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 3)) {
		goto out_cleanup_signal;
	}

	if (rrr_logd_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if (rrr_logd_socket_setup(&data) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_socket;
	}

	if (rrr_event_queue_new(&events) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_socket;
	}

	if (rrr_socket_client_collection_new(&clients, events, "rrr_logd") != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_events;
	}

	rrr_socket_client_collection_event_setup (
			clients,
			NULL,
			NULL,
			NULL,
			65536,
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP,
			NULL,
			NULL,
			rrr_logd_read_msg_callback,
			NULL,
			rrr_logd_read_log_callback,
			rrr_logd_read_ctrl_callback,
			NULL,
			&data
	);

	rrr_socket_client_collection_fd_close_notify_setup (
			clients,
			rrr_logd_fd_close_callback,
			&data
	);

	if (data.receive_socket_fd > 0 && rrr_socket_client_collection_listen_fd_push (
			clients,
			data.receive_socket_fd
	) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_clients;
	}

	if (data.receive_fd > 0) {
		if (rrr_socket_check_alive (data.receive_fd) != 0) {
			RRR_MSG_0("Given file descriptor %i was unusable, exiting now.\n",
				data.receive_fd);
			ret = EXIT_FAILURE;
			goto out_cleanup_clients;
		}

		if (rrr_socket_client_collection_connected_fd_push (
				clients,
				data.receive_fd,
				RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT
		) != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_clients;
		}
	}

	RRR_DBG_1("RRR log deamon starting dispatch\n");

	if (rrr_event_dispatch (
			events,
			100 * 1000, /* 100 ms */
			rrr_logd_periodic,
			&data
	) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_clients;
	}

	RRR_DBG_1("RRR log deamon dispatch ended\n");

	out_cleanup_clients:
		rrr_socket_client_collection_destroy(clients);
		data.receive_socket_fd = 0;
	out_cleanup_events:
		rrr_event_queue_destroy(events);
	out_cleanup_socket:
		if (data.receive_socket_fd > 0)
			rrr_socket_close(data.receive_socket_fd);
		rrr_socket_close_all();
	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_log_cleanup();

	out_cleanup_allocator:
		rrr_allocator_cleanup();

	out_final:
		return ret;
}
