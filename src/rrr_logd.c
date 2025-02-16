/*

Read Route Record

Copyright (C) 2024-2025 Atle Solbakken atle@goliathdns.no

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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "lib/log.h"
#include "lib/allocator.h"

#include "lib/messages/msg_head.h"
#include "lib/messages/msg_log.h"
#include "lib/messages/msg_msg_struct.h"
#include "lib/rrr_types.h"
#include "lib/socket/rrr_socket_constants.h"
#include "lib/util/macro_utils.h"
#include "main.h"
#include "../build_timestamp.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/array.h"
#include "lib/fork.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_client.h"
#include "lib/event/event.h"
#include "lib/helpers/log_helper.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_logd");

static volatile int some_fork_has_stopped = 0;
static volatile int main_running = 1;
static volatile int sigusr2 = 0;

int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_HAS_ARGUMENT,   's',    "socket",                "[-s|--socket[=]SOCKET]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'f',    "file-descriptor",       "[-f|--file-descriptor[=]FILE DESCRIPTOR]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'p',    "persist",               "[-p|--persist]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'q',    "quiet",                 "[-q|--quiet]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'n',    "add-newline",           "[-a|--add-newline]"},
	{CMD_ARG_FLAG_NO_ARGUMENT,    'm',    "message-only",          "[-m|--message-only]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'l',    "loglevel-translation",  "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'h',    "help",                  "[-h|--help]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'v',    "version",               "[-v|--version]"},
	{CMD_ARG_FLAG_NO_FLAG_MULTI,  '\0',   "wrapper-and-args",      "[WRAPPER AND ARGS]"},
        {0,                           '\0',    NULL,                   NULL}
};

struct rrr_logd_data {
	const char *receive_socket;
	int receive_socket_fd;
	int receive_fd;
	int persist;
	int quiet;
	int add_newline;
	int message_only;
	char **wrapper;
};

static void rrr_logd_cleanup_config (struct rrr_logd_data *data) {
	char *p;
	int i;
	if (data->wrapper != NULL) {
		for (i = 0, p = data->wrapper[0]; p != NULL; i++, p = data->wrapper[i]) {
			rrr_free(p);
		}
		rrr_free(data->wrapper);
	}
}

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

	if (cmd_exists(cmd, "quiet", 0)) {
		data->quiet = 1;
	}

	if (cmd_exists(cmd, "add-newline", 0)) {
		data->add_newline = 1;
	}

	if (cmd_exists(cmd, "message-only", 0)) {
		data->message_only = 1;
	}

	const char *wrapper_string;
	cmd_arg_count wrapper_count = 0;
	while ((wrapper_string = cmd_get_value(cmd, "wrapper-and-args", wrapper_count)) != NULL) {
		wrapper_count++;
	}

	if (wrapper_count > 0) {
		if ((data->wrapper = rrr_allocate_zero(sizeof(*data->wrapper) * (wrapper_count + 1))) == NULL) {
			RRR_MSG_0("Failed to allocate memory for arguments in %s\n", __func__);
			return 1;
		}

		for (cmd_arg_count i = 0; i < wrapper_count; i++) {
			const char *str = cmd_get_value(cmd, "wrapper-and-args", i);
			if ((data->wrapper[i] = rrr_strdup(str)) == NULL) {
				RRR_MSG_0("Failed to allocate memory for wrapper argument in %s\n");
				return 1;
			}
		}
	}

	/* Caller must call cleanup function upon fail */

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

struct rrr_logd_callback_data {
	struct rrr_logd_data *data;
	struct rrr_fork_handler *fork_handler;
	int fd_stdout_orig;
};

static void rrr_logd_stdout_restore (int fd_stdout_orig) {
	if (fd_stdout_orig) {
		if (dup2(fd_stdout_orig, STDOUT_FILENO) < 0) {
			// Further messages will not be printed, just crash to avoid confusion
			RRR_BUG("Failed to redirect output back to standard output, cannot handle this situation");
		}
		RRR_DBG_1("Redirected output back to standard output\n");
	}
}

static int rrr_logd_periodic (void *arg) {
	struct rrr_logd_callback_data *callback_data = arg;

	if (!main_running)
		return RRR_EVENT_EXIT;

	rrr_fork_handle_sigchld_and_notify_if_needed(callback_data->fork_handler, 0);

	if (some_fork_has_stopped) {
		rrr_logd_stdout_restore(callback_data->fd_stdout_orig);
		RRR_MSG_0("One or more forks has exited\n");
		return RRR_EVENT_EXIT;
	}

	return RRR_EVENT_OK;
}

static void rrr_logd_print (
		struct rrr_logd_data *data,
		const char *file,
		int line,
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
		const char *prefix,
		const char *message
) {
	int add_newline = 0;

	assert(message != NULL);

	if (data->add_newline && message[strlen(message) - 1] != '\n')
		add_newline = 1;

	if (data->message_only) {
		printf(add_newline ? "%s\n" : "%s", message);
		return;
	}

	if (line == 0 || file == NULL || *file == '\0') {
		line = __LINE__;
		file = __FILE__;
	}

	if (prefix == NULL || *prefix == '\0') {
		prefix = "rrr_logd";
	}

	if (loglevel_orig == RRR_MSG_LOG_LEVEL_ORIG_NOT_GIVEN) {
		rrr_log_printf_nolock_loglevel_translated (
				file,
				line,
				loglevel_translated,
				prefix,
				add_newline ? "%s\n" : "%s",
				message
		);
	}
	else {
		rrr_log_printf_nolock (
				file,
				line,
				loglevel_orig,
				prefix,
				add_newline ? "%s\n" : "%s",
				message
		);
	}
}

static int rrr_logd_read_msg_callback (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	struct rrr_msg_msg *msg = *message;
	struct rrr_logd_callback_data *callback_data = arg2;

	(void)(arg1);

	int ret = RRR_READ_OK;

	struct rrr_array array = {0};
	char *log_message = NULL;
	char *log_prefix = NULL;
	char *log_file = NULL;
	uint8_t log_level_translated = 7;
	int log_line = 0;

	if (callback_data->data->quiet)
		goto out;

	if (!MSG_IS_ARRAY(msg)) {
		RRR_MSG_0("Received non-array RRR standard message from client, this is not supported\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	uint16_t array_version;
	if ((ret = rrr_array_message_append_to_array(&array_version, &array, msg)) != 0) {
		goto out;
	}

	if ((ret = rrr_log_helper_extract_log_fields_from_array (
			&log_file,
			&log_line,
			&log_level_translated,
			&log_prefix,
			&log_message,
			&array
	)) != 0) {
		// Returns hard or soft error
		RRR_MSG_0("Error while processing received array message\n");
		goto out;
	}

	rrr_logd_print (
			callback_data->data,
			log_file,
			log_line,
			log_level_translated,
			RRR_MSG_LOG_LEVEL_ORIG_NOT_GIVEN,
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
	struct rrr_logd_callback_data *callback_data = arg2;

	(void)(arg1);

	int ret = RRR_READ_OK;

	char *log_prefix = NULL;
	char *log_message = NULL;

	if (callback_data->data->quiet)
		goto out;

	if ((ret = rrr_msg_msg_log_to_str(&log_prefix, &log_message, message)) != 0) {
		goto out;
	}

	rrr_logd_print (
			callback_data->data,
			message->file,
			message->line > INT_MAX
				? INT_MAX
				: rrr_int_from_biglength_bug_const(message->line),
			message->loglevel_translated,
			message->loglevel_orig,
			log_prefix,
			log_message
	);

	out:
	RRR_FREE_IF_NOT_NULL(log_prefix);
	RRR_FREE_IF_NOT_NULL(log_message);
	return ret;
}

static int rrr_logd_read_ctrl_callback (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	(void)(arg1);
	(void)(arg2);

	if (!RRR_MSG_CTRL_F_HAS(message, RRR_MSG_CTRL_F_PING)) {
		RRR_MSG_0("Received control message did not have ping flag set\n");
		return RRR_READ_SOFT_ERROR;
	}

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

	int is_child = 0;

	struct rrr_signal_handler *signal_handler = NULL;
	struct rrr_signal_handler *signal_handler_fork = NULL;
	struct cmd_data cmd = {0};
	struct rrr_logd_data data = {0};
	struct rrr_event_queue *events;
	struct rrr_socket_client_collection *clients;
	struct rrr_fork_handler *fork_handler;
	struct rrr_fork_default_exit_notification_data exit_notification_data = {
		&some_fork_has_stopped
	};
	int fd_to_wrapper[2] = {0, 0};

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

	if (rrr_fork_handler_new (&fork_handler) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	signal_handler_fork = rrr_signal_handler_push(rrr_fork_signal_handler, NULL);
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
		goto out_cleanup_config;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if (rrr_logd_socket_setup(&data) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_config;
	}

	if (rrr_event_queue_new(&events) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_socket;
	}

	if (rrr_socket_client_collection_new(&clients, events, "rrr_logd") != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_events;
	}

	struct rrr_logd_callback_data callback_data = {
		&data,
		fork_handler,
		0
	};

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
			&callback_data
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
		if (rrr_socket_check_alive (data.receive_fd, 0 /* Not silent */) != 0) {
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

	if (data.wrapper) {
		RRR_DBG_1("Starting wrapper process '%s'\n", *data.wrapper);

		for (char **arg = data.wrapper + 1; *arg; arg++) {
			RRR_DBG_1(" - arg: '%s'\n", *arg);
		}

		if (rrr_socket_pipe_blocking(fd_to_wrapper, "logd wrapper") != 0) {
			RRR_MSG_0("Failed to create pipe to wrapper\n");
			goto out_cleanup_clients;
		}

		pid_t pid = rrr_fork (
				fork_handler,
				rrr_fork_default_exit_notification,
				&exit_notification_data
		);
		if (pid < 0) {
			RRR_MSG_0("Could not fork child process: %s\n", rrr_strerror(errno));
			ret = EXIT_FAILURE;
			goto out_cleanup_pipe;
		}
		else if (pid == 0) {
			// CHILD CODE
			is_child = 1;

			RRR_DBG_1("In child wrapper\n");

			rrr_socket_close_if_set(&fd_to_wrapper[1]);

			if (rrr_socket_dup2(fd_to_wrapper[0], STDIN_FILENO) != 0) {
				RRR_MSG_0("dup2 failed in child wrapper\n");
				ret = EXIT_FAILURE;
				goto out_cleanup_pipe;
			}

			execve(data.wrapper[0], data.wrapper, (char * const *) env);

			RRR_MSG_0("Failed to execute wrapper '%s': %s\n", data.wrapper[0], rrr_strerror(errno));

			goto out_cleanup_pipe;
		}

		rrr_socket_close_if_set(&fd_to_wrapper[0]);

		RRR_DBG_1("Child wrapper started pid %i, redirecting output\n", pid);

		if ((callback_data.fd_stdout_orig = dup(STDOUT_FILENO)) < 0) {
			RRR_MSG_0("dup failed int main process\n");
			ret = EXIT_FAILURE;
			goto out_cleanup_pipe;
		}

		if (rrr_socket_dup2(fd_to_wrapper[1], STDOUT_FILENO) != 0) {
			RRR_MSG_0("dup2 failed int main process\n");
			ret = EXIT_FAILURE;
			goto out_cleanup_pipe;
		}

		RRR_DBG_1("Output now redirected\n", pid);
	}

	RRR_DBG_1("RRR log deamon starting dispatch\n");

	if (rrr_event_dispatch (
			events,
			100 * 1000, /* 100 ms */
			rrr_logd_periodic,
			&callback_data
	) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_pipe;
	}

	rrr_logd_stdout_restore(callback_data.fd_stdout_orig);

	RRR_DBG_1("RRR log deamon dispatch ended\n");

	out_cleanup_pipe:
		rrr_socket_close_if_set(&fd_to_wrapper[0]);
		rrr_socket_close_if_set(&fd_to_wrapper[1]);
	out_cleanup_clients:
		rrr_socket_client_collection_destroy(clients);
		data.receive_socket_fd = 0;
	out_cleanup_events:
		rrr_event_queue_destroy(events);
	out_cleanup_config:
		rrr_logd_cleanup_config(&data);
	out_cleanup_socket:
		if (data.receive_socket_fd > 0)
			rrr_socket_close(data.receive_socket_fd);
		rrr_socket_close_all();

	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

		rrr_signal_handler_remove(signal_handler);
		rrr_signal_handler_remove(signal_handler_fork);

		if (is_child) {
			// Child forks must skip *ALL* the fork-cleanup stuff. It's possible that a
			// child which regularly calls rrr_fork_handle_sigchld_and_notify_if_needed
			// will hande a SIGCHLD before we send signals to all forks, in which case
			// it will clean up properly anyway.
			goto out_cleanup_cmd;
		}

		rrr_fork_send_sigusr1_and_wait(fork_handler);
		rrr_fork_handle_sigchld_and_notify_if_needed(fork_handler, 1);
		rrr_fork_handler_destroy (fork_handler);

	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_log_cleanup();

	out_cleanup_allocator:
		rrr_allocator_cleanup();

	out_final:
		return ret;
}
