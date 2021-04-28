/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../build_timestamp.h"
#include "main.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/version.h"
#include "lib/common.h"
#include "lib/rrr_config.h"
#include "lib/rrr_strerror.h"
#include "lib/array.h"
#include "lib/string_builder.h"
#include "lib/socket/rrr_socket.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/messages/msg.h"
#include "lib/messages/msg_msg.h"
#include "lib/messages/msg_addr.h"
#include "lib/messages/msg_log.h"
#include "lib/messages/msg_checksum.h"
#include "lib/ip/ip_defines.h"
#include "lib/util/rrr_time.h"
#include "lib/util/rrr_endian.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_msg");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG_MULTI,   '\0',   "file",                 "{FILE}..."},
        {0,                            'r',    "read",                 "[-r|--read] (default mode)"},
        {0,                            'i',    "ignore-errors",        "[-i|--ignore-errors]"},
        {0,                            'f',    "force",                "[-f|--force]"},
        {0,                            's',    "selftest",             "[-s|--selftest]"},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {0,                            'b',    "banner",               "[-b|--banner]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                  NULL}
};

enum rrr_msg_mode {
	RRR_MSG_MODE_READ
};

struct rrr_msg_data {
	enum rrr_msg_mode mode;
	int do_ignore_errors;
	int do_force;
	int do_selftest;
};

static void __rrr_msg_data_cleanup (
		struct rrr_msg_data *data
) {
	(void)(data);
}

static int __rrr_msg_parse_config (
		struct rrr_msg_data *data,
		struct cmd_data *cmd
) {
	int ret = 0;

	if (cmd_exists(cmd, "read", 0)) {
		data->mode = RRR_MSG_MODE_READ;
	}
	if (cmd_exists(cmd, "ignore-errors", 0)) {
		data->do_ignore_errors = 1;
	}
	if (cmd_exists(cmd, "force", 0)) {
		data->do_force = 1;
	}
	if (cmd_exists(cmd, "selftest", 0)) {
		data->do_selftest = 1;
	}

	return ret;
}

static int __rrr_msg_msg_callback (
		struct rrr_msg_msg **message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	const struct rrr_msg_msg *msg = *message;

	int ret = 0;

	struct rrr_array array_tmp = {0};
	char *topic_tmp = NULL;

	RRR_MSG_1("== Type: RRR Message (%s)\n", MSG_TYPE_NAME(msg));
	RRR_MSG_1("Version: %u\n", msg->version);

	if ((ret = rrr_msg_msg_topic_get(&topic_tmp, msg)) != 0) {
		goto out;
	}

	RRR_MSG_1("Topic: %s\n", (topic_tmp != NULL && *topic_tmp != '\0' ? topic_tmp : "(no topic)"));
	RRR_MSG_1("Value: %" PRIu32 "\n", msg->msg_value);
	RRR_MSG_1("Timestamp: %" PRIu64 "\n", msg->timestamp);

	if (MSG_CLASS(msg) == MSG_CLASS_ARRAY) {
		RRR_MSG_1("Class: array\n");
		if (msg->version != RRR_ARRAY_VERSION) {
			if (data->do_force) {
				RRR_MSG_1("Force: yes, ignoring unsupported version\n");
			}
			else {
				RRR_MSG_0("Warning: Unsupported version %u, dumps may be unreliable. Use -f to force dump anyway.\n", msg->version);
				goto out;
			}
		}

		uint16_t array_version = 0;
		if ((ret = rrr_array_message_append_to_collection(&array_version, &array_tmp, msg)) != 0) {
			goto out;
		}

		if (RRR_DEBUGLEVEL_2) {
			rrr_array_dump(&array_tmp);
		}
	}
	else if (MSG_CLASS(msg) == MSG_CLASS_DATA) {
		RRR_MSG_1("Class: data\n");
		RRR_MSG_1("Data size: %llu\n", (unsigned long long int) MSG_DATA_LENGTH(msg));
		if (RRR_DEBUGLEVEL_6) {
			struct rrr_string_builder str_tmp = {0};
			const unsigned char *buf = (const unsigned char *) MSG_DATA_PTR(msg);
			for (unsigned int i = 0; i < MSG_DATA_LENGTH(msg); i++) {
				rrr_string_builder_append_format(&str_tmp, "%02x-", *(buf + i));
			}
			RRR_DBG_6("Data: %s\n", rrr_string_builder_buf(&str_tmp));
			rrr_string_builder_clear(&str_tmp);
		}
	}
	else {
		RRR_MSG_0("Unknown class %u\n", MSG_CLASS(msg));
	}

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int __rrr_msg_addr_callback (
		const struct rrr_msg_addr *message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	(void)(data);

	int ret = 0;

	RRR_MSG_1("== Type: RRR Address Message\n");
	RRR_MSG_1("Transport: %s\n", RRR_IP_TRANSPORT_NAME(message->protocol));

	char str[256];
	rrr_msg_addr_to_str(str, sizeof(str), message);

	RRR_MSG_1("Address: %s\n", str);

	return ret;
}

static int __rrr_msg_log_callback (
		const struct rrr_msg_log *message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	(void)(data);

	int ret = 0;

	RRR_MSG_1("== Type: RRR Log Message\n");

	char *prefix_tmp = NULL;
	char *message_tmp = NULL;

	if ((ret = rrr_msg_msg_log_to_str(&prefix_tmp, &message_tmp, message)) != 0) {
		goto out;
	}

	RRR_MSG_1("RRR loglevel: %u\n", message->loglevel_orig);
	RRR_MSG_1("RFC loglevel: %u\n", message->loglevel_translated);
	RRR_MSG_1("Is stdout: %u\n", message->is_stdout);
	RRR_MSG_1("Prefix: %s\n", prefix_tmp);
	RRR_MSG_1("Message: %s\n", message_tmp);

	out:
	RRR_FREE_IF_NOT_NULL(prefix_tmp);
	RRR_FREE_IF_NOT_NULL(message_tmp);
	return ret;
}

#define PRINT_FLAG(flag) \
	RRR_MSG_1("- " RRR_QUOTE(flag) ": %s\n", RRR_MSG_CTRL_F_HAS(message, RRR_PASTE(RRR_MSG_CTRL_F_,flag)) ? "yes" : "no")

static int __rrr_msg_ctrl_callback (
		const struct rrr_msg *message,
		void *arg1,
		void *arg2
) {
	(void)(arg2);
	struct rrr_msg_data *data = arg1;
	(void)(data);

	int ret = 0;

	RRR_MSG_1("== Type: RRR Control Message\n");
	RRR_MSG_1("Flags: %u\n", RRR_MSG_CTRL_FLAGS(message));
	PRINT_FLAG(PING);
	PRINT_FLAG(PONG);
	PRINT_FLAG(ACK);
	PRINT_FLAG(NACK);
	PRINT_FLAG(USR_A);
	PRINT_FLAG(USR_B);
	PRINT_FLAG(USR_C);
	PRINT_FLAG(USR_D);

	return ret;
}

static int __rrr_msg_to_host_and_dump (
		struct rrr_msg_data *data,
		struct rrr_msg *msg,
		rrr_length expected_size
) {
	int ret = 0;

	RRR_DBG_3("Header value: %" PRIu32 "\n", rrr_htobe32(msg->msg_value));
	RRR_DBG_3("Header CRC32: %" PRIu32 "\n", rrr_htobe32(msg->header_crc32));
	RRR_DBG_3("Data   CRC32: %" PRIu32 "\n", rrr_htobe32(msg->data_crc32));

	if ((ret = rrr_msg_to_host_and_verify_with_callback (
			&msg,
			expected_size,
			__rrr_msg_msg_callback,
			__rrr_msg_addr_callback,
			__rrr_msg_log_callback,
			__rrr_msg_ctrl_callback,
			NULL,
			data,
			NULL
	)) != 0) {
		if (RRR_MSG_IS_SETTING(msg)) {
			RRR_MSG_1("Possibly an RRR Setting Message (dump not supported)\n");
		}
		else if (RRR_MSG_IS_TREE_DATA(msg)) {
			RRR_MSG_1("Possibly an RRR Stats Engine Tree Data Message (dump not supported)\n");
		}
		goto out;
	}

	out:
	return ret;
}

static int __rrr_msg_read (
		struct rrr_msg_data *data,
		const char *file
) {
	int ret = 0;

	char *file_data = NULL;
	ssize_t file_size = 0;

	RRR_MSG_1("== Filename: %s\n", file);

	if ((ret = rrr_socket_open_and_read_file(&file_data, &file_size, file, 0, 0)) != 0) {
		RRR_MSG_0("Failed to read file '%s'\n", file);
		goto out;
	}

	RRR_MSG_1("== Size: %lli\n", (long long signed) file_size);

#if SSIZE_MAX > RRR_LENGTH_MAX
	if (file_size < (ssize_t) sizeof(struct rrr_msg) || file_size > (rrr_slength) RRR_LENGTH_MAX) {
#else
	if (file_size < (ssize_t) sizeof(struct rrr_msg)) {
#endif
		RRR_MSG_0("File size of file '%s' was out of range while reading (must have %llu <= size <= %llu, got %lli)\n",
			file,
			(long long unsigned) sizeof(struct rrr_msg),
			(long long unsigned) RRR_LENGTH_MAX,
			(long long signed) file_size
		);
		ret = 1;
		goto out;
	}

	struct rrr_msg *msg = (struct rrr_msg *) file_data;

	if ((ret = __rrr_msg_to_host_and_dump(data, msg, file_size)) != 0) {
		RRR_MSG_0("Failed to read message from file '%s'\n", file);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(file_data);
	return ret;
}

#define CHECKSUM_AND_CHECK(msg,size) \
	rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg); \
	do {if ((ret = __rrr_msg_to_host_and_dump (data, (struct rrr_msg *) msg, size)) != 0) { goto out; }} while(0)

static int __rrr_msg_selftest (
		struct rrr_msg_data *data
) {
	(void)(data);

	int ret = 0;

	struct rrr_array array_tmp = {0};
	struct rrr_msg_msg *msg_msg = NULL;
	struct rrr_msg_log *msg_log = NULL;
	struct rrr_msg_addr *msg_addr = NULL;

	{
		RRR_MSG_1("Test RRR Message (data)\n");

		if ((ret = rrr_msg_msg_new_with_data (
			&msg_msg,
			MSG_TYPE_PUT,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			"topic",
			strlen("topic"),
			"data",
			strlen("data")

		)) != 0) {
			goto out;
		}

		rrr_length size = MSG_TOTAL_SIZE(msg_msg);
		rrr_msg_msg_prepare_for_network(msg_msg);
		CHECKSUM_AND_CHECK(msg_msg,size);

		RRR_FREE_IF_NOT_NULL(msg_msg);
	}

	{
		RRR_MSG_1("Test RRR Message (array)\n");

		if ((ret = rrr_array_push_value_str_with_tag(&array_tmp, "tag", "value")) != 0) {
			goto out;
		}

		if ((ret = rrr_array_new_message_from_collection (
				&msg_msg,
				&array_tmp,
				rrr_time_get_64(),
				"topic",
				strlen("topic")
		)) != 0) {
			goto out;
		}

		rrr_length size = MSG_TOTAL_SIZE(msg_msg);
		rrr_msg_msg_prepare_for_network(msg_msg);
		CHECKSUM_AND_CHECK(msg_msg,size);

		RRR_FREE_IF_NOT_NULL(msg_msg);
	}

	{
		RRR_MSG_1("Test RRR Log Message\n");

		if ((ret = rrr_msg_msg_log_new(&msg_log, 7, 3, "prefix", "This is the log message")) != 0) {
			goto out;
		}

		rrr_length size = MSG_TOTAL_SIZE(msg_log);
		rrr_msg_msg_log_prepare_for_network(msg_log);
		CHECKSUM_AND_CHECK(msg_log, size);
	}

	{
		RRR_MSG_1("Test RRR Address Message\n");

		struct sockaddr_in in = {0};

		if (inet_pton(AF_INET, "1.2.3.4", &(in.sin_addr)) != 1) {
			RRR_MSG_0("inet_pton failed\n");
		}

		in.sin_family = AF_INET;
		in.sin_port = htons(1234);

		if ((ret = rrr_msg_addr_new(&msg_addr)) != 0) {
			goto out;
		}

		memcpy(&msg_addr->addr, &in, sizeof(in));
		rrr_msg_addr_init_head(msg_addr, sizeof(in));
		rrr_length size = msg_addr->msg_size;
		rrr_msg_addr_prepare_for_network(msg_addr);
		CHECKSUM_AND_CHECK(msg_addr, size);
	}

	out:
	rrr_array_clear(&array_tmp);
	RRR_FREE_IF_NOT_NULL(msg_msg);
	RRR_FREE_IF_NOT_NULL(msg_log);
	RRR_FREE_IF_NOT_NULL(msg_addr);
	if (ret != 0) {
		RRR_MSG_0("Selftest failed\n");
	}
	return ret;
}

static int main_running = 1;
int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler = NULL;

	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}

	rrr_strerror_init();
	rrr_signal_default_signal_actions_register();
	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);
	rrr_signal_handler_set_active (RRR_SIGNALS_ACTIVE);

	struct cmd_data cmd;
	struct rrr_msg_data data = {0};

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out;
	}

	if (__rrr_msg_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (data.do_selftest) {
		if (__rrr_msg_selftest(&data) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	else {
		const char *arg = NULL;
		for (cmd_arg_count i = 0; main_running && (arg = cmd_get_value(&cmd, "file", i)) != NULL; i++) {
			if (data.mode == RRR_MSG_MODE_READ) {
				if (__rrr_msg_read(&data, arg) != 0 && !data.do_ignore_errors) {
					ret = EXIT_FAILURE;
					goto out;
				}
			}
		}
	}

	out:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_config_set_debuglevel_on_exit();
		__rrr_msg_data_cleanup(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
	out_final:
		rrr_allocator_cleanup();
		return ret;
}
