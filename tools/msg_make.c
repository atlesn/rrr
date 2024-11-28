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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "../build_timestamp.h"
#include "../src/main.h"
#include "../src/lib/version.h"
#include "../src/lib/allocator.h"
#include "../src/lib/rrr_strerror.h"
#include "../src/lib/array.h"
#include "../src/lib/rrr_types.h"
#include "../src/lib/cmdlineparser/cmdline.h"
#include "../src/lib/messages/msg_msg.h"
#include "../src/lib/messages/msg.h"
#include "../src/lib/messages/msg_addr.h"
#include "../src/lib/messages/msg_log.h"
#include "../src/lib/stats/stats_message.h"
#include "../src/lib/util/rrr_time.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("array_parse");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG,         '\0',   "type",                 "{msg|log|array|stats|addr}"},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

static int msg_make_checksum_and_output(struct rrr_msg *msg, rrr_length msg_size) {
	int ret = 0;

	rrr_msg_checksum_and_to_network_endian(msg);

	if (write(1, msg, msg_size) != msg_size) {
		RRR_MSG_0("Failed to write message to standard output: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int msg_make_msg(void) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = rrr_msg_msg_new_with_data (
			&msg,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			"topic",
			5,
			"data",
			4
	)) != 0) {
		goto out;
	}

	rrr_length msg_size = MSG_TOTAL_SIZE(msg);

	rrr_msg_msg_prepare_for_network(msg);

	if ((ret = msg_make_checksum_and_output((struct rrr_msg *) msg, msg_size)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int msg_make_log(void) {
	int ret = 0;

	struct rrr_msg_log *msg = NULL;

	if ((ret = rrr_msg_msg_log_new (
			&msg,
			__FILE__,
			__LINE__,
			7,
			1,
			"prefix",
			"message"
	)) != 0) {
		goto out;
	}

	rrr_length msg_size = MSG_TOTAL_SIZE(msg);

	rrr_msg_msg_log_prepare_for_network(msg);

	if ((ret = msg_make_checksum_and_output((struct rrr_msg *) msg, msg_size)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int msg_make_array(void) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;
	struct rrr_array array = {0};

	if ((ret = rrr_array_push_value_str_with_tag(&array, "str", "value of string")) != 0) {
		RRR_MSG_0("Failed to push str value to array\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_u64_with_tag(&array, "u64", 1234)) != 0) {
		RRR_MSG_0("Failed to push u64 value to array\n");
		goto out;
	}

	if ((ret = rrr_array_push_value_vain_with_tag(&array, "vain")) != 0) {
		RRR_MSG_0("Failed to push vain value to array\n");
		goto out;
	}

	if ((ret = rrr_array_new_message_from_array (
			&msg,
			&array,
			rrr_time_get_64(),
			"topic",
			5
	)) != 0) {
		goto out;
	}

	rrr_length msg_size = MSG_TOTAL_SIZE(msg);

	rrr_msg_msg_prepare_for_network(msg);

	if ((ret = msg_make_checksum_and_output((struct rrr_msg *) msg, msg_size)) != 0) {
		goto out;
	}

	out:
	rrr_array_clear(&array);
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}

static int msg_make_stats(void) {
	int ret = 0;

	struct rrr_msg_stats msg;
	struct rrr_msg_stats_packed msg_packed;
	rrr_length msg_size;

	if ((ret = rrr_msg_stats_init (
			&msg,
			RRR_STATS_MESSAGE_TYPE_TEXT,
			RRR_STATS_MESSAGE_FLAGS_LOG,
			"postfix",
			"log message",
			11
	)) != 0) {
		RRR_MSG_0("Failed to init stats message\n");
		goto out;
	}

	rrr_msg_stats_pack_and_flip(&msg_packed, &msg_size, &msg);

	rrr_msg_populate_head (
			(struct rrr_msg *) &msg_packed,
			RRR_MSG_TYPE_STATS,
			msg_size,
			(rrr_u32) (rrr_time_get_64() / 1000 / 1000)
	);

	if ((ret = msg_make_checksum_and_output((struct rrr_msg *) &msg_packed, msg_size)) != 0) {
		goto out;
	}

	out:
	return ret;

}

static int msg_make_addr(void) {
	struct rrr_msg_addr msg;

	rrr_msg_addr_init(&msg);
	RRR_MSG_ADDR_SET_ADDR_LEN(&msg, 32);

	rrr_length msg_size = MSG_TOTAL_SIZE(&msg);

	rrr_msg_addr_prepare_for_network(&msg);

	return msg_make_checksum_and_output((struct rrr_msg *) &msg, msg_size);
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;

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

	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out_cleanup_cmd;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_cmd;
	}

	const char *type = cmd_get_value(&cmd, "type", 0);

	if (strcmp(type, "msg") == 0) {
		if (msg_make_msg() != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}
	}
	else if (strcmp(type, "log") == 0) {
		if (msg_make_log() != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}
	}
	else if (strcmp(type, "array") == 0) {
		if (msg_make_array() != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}
	}
	else if (strcmp(type, "stats") == 0) {
		if (msg_make_stats() != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}
	}
	else if (strcmp(type, "addr") == 0) {
		if (msg_make_addr() != 0) {
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}
	}
	else {
		RRR_MSG_0("Unknown message type %s\n", type);
		ret = 1;
	}

	out_cleanup_cmd:
		cmd_destroy(&cmd);
	//out_cleanup_log:
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
