/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

// Allow S_IFMT etc.
#undef _DEFAULT_SOURCE
#undef __XSI_VISIBLE
#define _DEFAULT_SOURCE
#define __XSI_VISIBLE 1
#	include <sys/stat.h>
#undef _DEFAULT_SOURCE
#undef __XSI_VISIBLE

#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <limits.h>

#include "main.h"
#include "lib/rrr_config.h"
#include "lib/version.h"
#include "../build_timestamp.h"
#include "lib/log.h"
#include "lib/rrr_strerror.h"
#include "lib/posix.h"
#include "lib/rrr_time.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/linked_list.h"
#include "lib/map.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_msg.h"
#include "lib/socket/rrr_socket_read.h"
#include "lib/read.h"
#include "lib/socket/rrr_socket_constants.h"
#include "lib/rrr_readdir.h"
#include "lib/stats/stats_message.h"
#include "lib/stats/stats_tree.h"
#include "lib/macro_utils.h"

#ifdef _GNU_SOURCE
#	error "Cannot use _GNU_SOURCE, would cause use of incorrect basename() function"
#endif


#define RRR_STATS_DEFAULT_SOCKET_SEARCH_PATH \
	RRR_TMP_PATH "/" RRR_STATS_SOCKET_PREFIX

#define RRR_STATS_FIRST_PACKET_WAIT_LIMIT_MS	1000
#define RRR_STATS_CONNECTION_TIMEOUT_MS			RRR_STATS_FIRST_PACKET_WAIT_LIMIT_MS
#define RRR_STATS_TICK_SLEEP_MS					100
#define RRR_STATS_RECONNECT_SLEEP_MS			500
#define RRR_STATS_KEEPALIVE_INTERVAL_MS			(RRR_SOCKET_CLIENT_TIMEOUT_S / 2) * 1000
#define RRR_STATS_MESSAGE_LIFETIME_MS			1500

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_stats");

static volatile int rrr_stats_abort = 0;

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG_MULTI,'\0',	"socket",				"[RRR SOCKET (PREFIX)] ..."},
		{0,							'e',	"exact_path",			"[-e|--exact_path]"},
		{0,							'j',	"journal",				"[-j|--journal]"},
/*		{CMD_ARG_FLAG_HAS_ARGUMENT,	'f',	"file",					"[-f|--file[=]FILENAME|-]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA,	'r',	"readings",				"[-r|--readings[=]reading1,reading2,...]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA,	'a',	"array_definition",		"[-a|--array_definition[=]ARRAY DEFINITION]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'c',	"count",				"[-c|--count[=]MAX FILE ELEMENTS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	't',	"topic",				"[-t|--topic[=]MQTT TOPIC]"},
		{0,							's',	"sync",					"[-s|--sync]"},
		{0,							'q',	"quiet",				"[-q|--quiet]"},*/
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{0,							'h',	"help",					"[-h|--help]"},
		{0,							'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_stats_data {
	struct rrr_read_session_collection read_sessions;
	struct rrr_map socket_prefixes;
	struct rrr_stats_tree message_tree;
	char *socket_path_active;
	int socket_fd;
	int socket_path_exact;
	int print_journal;
};

static void __rrr_stats_signal_handler (int s) {
/*	if (s == SIGUSR1) {
		rrr_post_print_stats = 1;
	}*/
	if (s == SIGPIPE) {
		RRR_MSG_0("Received SIGPIPE, ignoring\n");
	}
	else if (s == SIGTERM) {
		RRR_MSG_0("Received SIGTERM, exiting\n");
		exit(EXIT_FAILURE);
	}
	else if (s == SIGINT) {
		// Allow double ctrl+c to close program immediately
		signal(SIGINT, SIG_DFL);
		rrr_stats_abort = 1;
	}
}

static int __rrr_stats_data_init (struct rrr_stats_data *data) {
	memset(data, '\0', sizeof(*data));
	if (rrr_stats_tree_init(&data->message_tree) != 0) {
		RRR_MSG_0("Could not initialize message tree in __rrr_stats_data_init\n");
		return 1;
	}
	rrr_read_session_collection_init(&data->read_sessions);
	return 0;
}

static void __rrr_stats_data_cleanup (struct rrr_stats_data *data) {
	rrr_read_session_collection_clear(&data->read_sessions);
	rrr_map_clear(&data->socket_prefixes);
	rrr_stats_tree_clear(&data->message_tree);
	RRR_FREE_IF_NOT_NULL(data->socket_path_active);
}

static int __rrr_stats_socket_prefix_register (struct rrr_stats_data *data, const char *prefix) {
	int ret = 0;

	struct rrr_map_item *node = malloc(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_stats_socket_prefix_register\n");
		ret = 1;
		goto out;
	}
	memset(node, '\0', sizeof(*node));

	node->tag = malloc(strlen(prefix) + 1);
	if (node->tag == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_stats_socket_prefix_register\n");
		ret = 1;
		goto out;
	}

	strcpy(node->tag, prefix);

	RRR_LL_APPEND(&data->socket_prefixes, node);
	node = NULL;

	out:
	if (node != NULL) {
		rrr_map_item_destroy(node);
	}
	return ret;
}

struct rrr_stats_read_message_callback_data {
	struct rrr_stats_data *data;
	unsigned int message_count_ok;
	unsigned int message_count_err;
};

static int __rrr_stats_read_message_callback_counter (const struct rrr_stats_message *message, void *private_arg) {
	struct rrr_stats_read_message_callback_data *data = private_arg;

	data->message_count_ok++;

	RRR_DBG_3("RX MSG path '%s'\n", message->path);

	return 0;
}

static int __rrr_stats_read_message (
		struct rrr_read_session_collection *read_sessions,
		int fd,
		int (*callback)(const struct rrr_stats_message *message, void *private_arg),
		struct rrr_stats_read_message_callback_data *callback_data
) {
	int ret = 0;

	struct rrr_stats_message_unpack_callback_data msg_callback_data = {
			callback, callback_data
	};

	uint64_t bytes_read = 0;

	return rrr_socket_read_message_default (
			&bytes_read,
			read_sessions,
			fd,
			sizeof(struct rrr_socket_msg),
			1024,
			0,
			0,
			RRR_SOCKET_READ_METHOD_RECV,
			rrr_read_common_get_session_target_length_from_message_and_checksum,
			NULL,
			rrr_stats_message_unpack_callback,
			&msg_callback_data // <-- CHECK THAT CALLBACK CORRECT STRUCT IS SENT
	);

	return ret;
}

static int __rrr_stats_parse_config (struct rrr_stats_data *data, struct cmd_data *cmd) {
	if (cmd_exists(cmd, "exact_path", 0)) {
		data->socket_path_exact = 1;
	}

	if (cmd_exists(cmd, "journal", 0)) {
		data->print_journal = 1;
	}

	int i = 0;
	while (cmd_exists(cmd, "socket", i)) {
		const char *path = NULL;
		if ((path = cmd_get_value(cmd, "socket", i)) != NULL) {
			if (__rrr_stats_socket_prefix_register(data, path) != 0) {
				RRR_MSG_0("Could not register socket prefix in __rrr_stats_parse_config\n");
				return 1;
			}
		}
		i++;
	}

	return 0;
}

static int __rrr_stats_attempt_connect_exact (struct rrr_stats_data *data, const char *path) {
	if (data->socket_fd != 0) {
		RRR_BUG("socket fd was not 0 in __rrr_stats_attempt_connect_exact\n");
	}

	int ret = 0;

	int fd;
	if ((ret = rrr_socket_unix_create_and_connect(&fd, "rrr_stats_connector", path, 1)) != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_DBG_1("Attempt to connect to %s did not succeed (soft error).\n", path);
			ret = 0; // This is just an attempt, non-critical error
			goto out;
		}

		RRR_MSG_0("Hard error while connecting to socket %s in __rrr_stats_attempt_connect_exact\n", path);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Connected to socket %s, attempting to read a packet\n", path);

	uint64_t time_limit = rrr_time_get_64() + RRR_STATS_FIRST_PACKET_WAIT_LIMIT_MS * 1000; // 500ms

	struct rrr_stats_read_message_callback_data callback_data = {
			data, 0, 0
	};

	while (rrr_time_get_64() < time_limit && callback_data.message_count_ok == 0) {
		if ((ret = __rrr_stats_read_message (
				&data->read_sessions,
				fd,
				__rrr_stats_read_message_callback_counter,
				&callback_data
		)) != 0) {
			if (ret == RRR_SOCKET_READ_INCOMPLETE) {
				ret = 0;
			}
			else {
				RRR_DBG_1("Error while reading first packet from socket %s, cannot use it.\n", path);
				ret = 0;
				goto out_close;
			}
		}

		rrr_posix_usleep(50000); // 50ms
	}

	if (callback_data.message_count_ok == 0) {
		RRR_DBG_1("No packets received on socket %s within time limit, cannot use it.\n", path);
		ret = 0;
		goto out_close;
	}

	RRR_DBG_1("Using socket %s\n", path);

	RRR_FREE_IF_NOT_NULL(data->socket_path_active);
	if ((data->socket_path_active = strdup(path)) == NULL) {
		RRR_MSG_0("Could not save socket path name in __rrr_stats_attempt_connect_exact\n");
		ret = 1;
		goto out_close;
	}

	data->socket_fd = fd;

	goto out;

	out_close:
	if (fd != 0) {
		rrr_socket_close(fd);
	}

	out:
	return ret;
}

static int __rrr_stats_attempt_connect_prefix_match (const char *filename, const char *prefix) {
	size_t filename_length = strlen(filename);
	size_t prefix_length = strlen(prefix);

	if (prefix_length == 0) {
		return 1;
	}

	if (filename_length < prefix_length) {
		return 0;
	}

	for (size_t i = 0; i < prefix_length; i++) {
		if (filename[i] != prefix[i]) {
			return 0;
		}
	}

	return 1;
}

struct rrr_stats_attempt_connect_prefix_callback_data {
	struct rrr_stats_data *data;
	const char *dir_name;
	const char *base_name;
};

static int __rrr_stats_attempt_connect_prefix_callback (
		struct dirent *entry,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct rrr_stats_attempt_connect_prefix_callback_data *data = private_data;

/*	printf ("in callback: %s - %s - %s type %u resolved path %s\n",
			data->dir_name,
			data->base_name,
			entry->d_name,
			type,
			resolved_path
	);*/

	if (__rrr_stats_attempt_connect_prefix_match(entry->d_name, data->base_name)) {
		if (type == DT_SOCK) {
			RRR_DBG_1 ("Found socket %s\n", resolved_path);

			// We could have done this at the top of the function, but it's desirable
			// to have the debug message printed for all matching files
			if (data->data->socket_fd != 0) {
				// Already connected
				return 0;
			}

			if (__rrr_stats_attempt_connect_exact(data->data, resolved_path) != 0) {
				RRR_MSG_0("Error while connecting to socket %s\n", resolved_path);
				return 1;
			}
		}
	}

	return 0;
}

static int __rrr_stats_attempt_connect_prefix (struct rrr_stats_data *data, const char *prefix) {
	char *prefix_copy_a = NULL;
	char *prefix_copy_b = NULL;

	if (data->socket_path_exact != 0) {
		return __rrr_stats_attempt_connect_exact(data, prefix);
	}

	int ret = 0;

	if (strlen(prefix) > PATH_MAX) {
		RRR_MSG_0("Prefix was too long in __rrr_stats_attempt_connect_prefix\n");
		ret = 1;
		goto out;
	}

	struct stat stat_buf = {0};

	char resolved_path[PATH_MAX + 1];
	strcpy(resolved_path, prefix);

	/*
	 * 1. If prefix does not exists as an entry:
	 *         Search all files in the directory of the prefix and match filenames against prefix
	 * 2. If prefix exists and is a directory or a symlink pointing to a directory:
	 *         Search all files in the directory to which the symlink points
	 * 3. If prefix exists and is a symlink pointing to something else:
	 *         Ignore symlink resolving and do step 1
	 */

	int symlink_max = 100;
	while (--symlink_max > 0 && lstat(resolved_path, &stat_buf) == 0 && (stat_buf.st_mode & S_IFMT) == S_IFLNK) {
		if (realpath(prefix, resolved_path) == NULL) {
			// After realpath error, contents of resolved_path is undefined
			strcpy(resolved_path, prefix);
			break;
		}
	}

	if (symlink_max <= 100) {
		// We end up here if we have a prefix like '../lnk_to_dir/rrr_' where lnk_to_dir is a
		// symlink to a directory. Simply continue if this happens, we will manage to open the
		// directory anyway.
	}

	if (lstat(resolved_path, &stat_buf) == 0 && (stat_buf.st_mode & S_IFMT) == S_IFDIR) {
		struct rrr_stats_attempt_connect_prefix_callback_data callback_data = {
			data, prefix, ""
		};

		if ((ret = rrr_readdir_foreach(prefix, __rrr_stats_attempt_connect_prefix_callback, &callback_data)) != 0) {
			RRR_MSG_0("Error while going through directory %s\n", prefix);
		}
	}
	else {
		prefix_copy_a = strdup(prefix);
		prefix_copy_b = strdup(prefix);

		if (prefix_copy_a == NULL || prefix_copy_b == NULL) {
			RRR_MSG_0("Could not duplicate path in __rrr_stats_attempt_connect_prefix\n");
			ret = 1;
			goto out;
		}

		// These two should not be freed
		char *dir_name = dirname(prefix_copy_a);
		char *base_name = basename(prefix_copy_b);

		struct rrr_stats_attempt_connect_prefix_callback_data callback_data = {
				data, dir_name, base_name
		};

		if ((ret = rrr_readdir_foreach(dir_name, __rrr_stats_attempt_connect_prefix_callback, &callback_data)) != 0) {
			RRR_MSG_0("Error while going through directory %s\n", dir_name);
		}
	}



	out:
	RRR_FREE_IF_NOT_NULL(prefix_copy_a);
	RRR_FREE_IF_NOT_NULL(prefix_copy_b);
	return ret;
}

static int __rrr_stats_attempt_connect (struct rrr_stats_data *data) {
	int ret = 0;

	if (RRR_LL_COUNT(&data->socket_prefixes) == 0) {
		if (__rrr_stats_socket_prefix_register(data, RRR_STATS_DEFAULT_SOCKET_SEARCH_PATH) != 0) {
			RRR_MSG_0("Could not register default socket prefix in __rrr_stats_attempt_connect\n");
			ret = 1;
			goto out;
		}
	}

	RRR_MAP_ITERATE_BEGIN(&data->socket_prefixes);
		if (data->socket_fd != 0) {
			RRR_DBG_1("Not attempting to use prefix %s, already connected\n", node_tag);
		}
		else {
			RRR_DBG_1("Attempting to use prefix %s\n", node_tag);
			if (__rrr_stats_attempt_connect_prefix(data, node->tag) != 0) {
				RRR_MSG_0("Error while attempting to connect to socket prefix %s\n", node_tag);
				ret = 1;
				goto out;
			}
		}
	RRR_MAP_ITERATE_END();

	out:
	// NOTE : Connection failure is not always an error
	return ret;
}

static int __rrr_stats_send_message (int fd, const struct rrr_stats_message *message) {
	struct rrr_stats_message_packed message_packed;
	size_t total_size;

	rrr_stats_message_pack_and_flip (
			&message_packed,
			&total_size,
			message
	);

	rrr_socket_msg_populate_head (
			(struct rrr_socket_msg *) &message_packed,
			RRR_SOCKET_MSG_TYPE_TREE_DATA,
			total_size,
			message->timestamp
	);

	rrr_socket_msg_checksum_and_to_network_endian (
			(struct rrr_socket_msg *) &message_packed
	);

	RRR_DBG_3("TX size %lu sticky %i path %s\n",
			total_size,
			RRR_STATS_MESSAGE_FLAGS_IS_STICKY(message),
			message->path
	);

	return rrr_socket_send_blocking(fd, &message_packed, total_size);
}

static int __rrr_stats_send_keepalive (struct rrr_stats_data *data) {
	if (data->socket_fd == 0) {
		return 0;
	}

	struct rrr_stats_message message;

	if (rrr_stats_message_init(&message, RRR_STATS_MESSAGE_TYPE_KEEPALIVE, 0, "", NULL, 0) != 0) {
		RRR_MSG_0("Could not initialize keepalive message in __rrr_stats_send_keepalive\n");
		return 1;
	}

	switch (__rrr_stats_send_message(data->socket_fd, &message)) {
		case RRR_SOCKET_OK:
			return 0;
		case RRR_SOCKET_SOFT_ERROR:
			RRR_DBG_1("Soft error while sending message, disconnecting from stats server\n");
			data->socket_fd = 0;
			break;
		default:
			RRR_MSG_0("Hard error while sending message to server\n");
			return 1;
	};

	return 0;
}

static int __rrr_stats_print_journal_message (const struct rrr_stats_message *message, void *private_arg) {
	struct rrr_stats_read_message_callback_data *callback_data = private_arg;

	int ret = 0;

	if (message->type != RRR_STATS_MESSAGE_TYPE_TEXT) {
		callback_data->message_count_err++;
		goto out;
	}

	// TODO : A lot of memory copying etc. just to check the end of the path

	struct rrr_stats_tree tree_tmp;
	if (rrr_stats_tree_init(&tree_tmp) != 0) {
		RRR_MSG_ERR("Could not initialize tree in __rrr_stats_print_journal_message\n");
		ret = 1;
		goto out;
	}

	if (rrr_stats_tree_insert_or_update(&tree_tmp, message) != 0) {
		RRR_MSG_0("Could not insert message into tree in __rrr_stats_print_journal_message\n");
		ret = 1;
		goto out_cleanup_tree;
	}

	if (rrr_stats_tree_has_leaf(&tree_tmp, RRR_STATS_MESSAGE_PATH_GLOBAL_LOG_JOURNAL)) {
		printf("%s", message->data);
		callback_data->message_count_ok++;
	}
	else {
		callback_data->message_count_err++;
	}

	out_cleanup_tree:
		rrr_stats_tree_clear(&tree_tmp);
	out:
		return ret;
}

static int __rrr_stats_process_message (const struct rrr_stats_message *message, void *private_arg) {
	struct rrr_stats_read_message_callback_data *callback_data = private_arg;

	(void)(message);

	callback_data->message_count_ok += 1;

	int ret = 0;
	if ((ret = rrr_stats_tree_insert_or_update(&callback_data->data->message_tree, message)) != 0) {
		if (ret == RRR_STATS_TREE_SOFT_ERROR) {
			RRR_MSG_0("Message with path %s was invalid, not added to tree\n", message->path);
			ret = 0;
			goto out;
		}

		RRR_MSG_0("Error while inserting message in tree in __rrr_stats_process_message\n");
		ret = 1;
		goto out;

	}

	out:
	return ret;
}

static int __rrr_stats_tick (struct rrr_stats_data *data) {
	if (data->socket_fd == 0) {
		return 0;
	}

	int (*callback)(const struct rrr_stats_message *message, void *private_arg) = NULL;
	if (data->print_journal == 1) {
		callback = __rrr_stats_print_journal_message;
	}
	else {
		callback = __rrr_stats_process_message;
	}

	struct rrr_stats_read_message_callback_data callback_data = { data, 0, 0 };

	unsigned int total_message_count_ok = 0;
	unsigned int total_message_count_err = 0;

	do {
		callback_data.message_count_ok = 0;
		callback_data.message_count_err = 0;

		switch (__rrr_stats_read_message (
				&data->read_sessions,
				data->socket_fd,
				callback,
				&callback_data
		)) {
			case RRR_SOCKET_OK:
				break;
			case RRR_SOCKET_READ_INCOMPLETE:
				break;
			case RRR_SOCKET_SOFT_ERROR:
				RRR_DBG_1("Soft error while reading from stats server, disconnecting\n");
				data->socket_fd = 0;
				break;
			default:
				RRR_MSG_0("Error while reading messages from RRR\n");
				data->socket_fd = 0;
				return 1;
		};

		total_message_count_ok += callback_data.message_count_ok;
		total_message_count_err += callback_data.message_count_err;
	}
	while (data->socket_fd != 0 && (callback_data.message_count_ok != 0 || callback_data.message_count_err != 0));

	if (total_message_count_ok > 0 || total_message_count_err > 0) {
		RRR_DBG_3("Received %u OK messages and %u unknown messages\n",
				total_message_count_ok, total_message_count_err);
	}

	if (data->print_journal == 0) {
		printf ("- TICK MS %" PRIu64 "\n", rrr_time_get_64() / 1000);

		unsigned int purged_total = 0;

		rrr_stats_tree_dump(&data->message_tree);
		rrr_stats_tree_purge_old_branches(&purged_total, &data->message_tree, rrr_time_get_64() - RRR_STATS_MESSAGE_LIFETIME_MS * 1000);
		printf ("------ Purged: %u\n", purged_total);
	}

	return 0;
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
	struct rrr_stats_data data = {0};

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (__rrr_stats_data_init(&data) != 0) {
		RRR_MSG_0("Could not initialize stats data\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if ((ret = rrr_main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	if (rrr_main_print_help_and_version(&cmd, 1) != 0) {
		goto out_cleanup_cmd;
	}

	if (__rrr_stats_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	struct sigaction action;
	action.sa_handler = __rrr_stats_signal_handler;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	// We generally ignore sigpipe and use NONBLOCK on all sockets
	sigaction (SIGPIPE, &action, NULL);
	// Used to set rrr_stats_abort = 1. The signal is set to default afterwards
	// so that a second SIGINT will terminate the process
	sigaction (SIGINT, &action, NULL);
	// Used to print statistics (disabled)
	// sigaction (SIGUSR1, &action, NULL);
	// Exit immediately with EXIT_FAILURE
	sigaction (SIGTERM, &action, NULL);

	uint64_t next_keep_alive = 0;

	while (rrr_stats_abort != 1) {
		rrr_socket_close_all();
		rrr_read_session_collection_clear(&data.read_sessions);
		data.socket_fd = 0;

		if (__rrr_stats_attempt_connect(&data) != 0) {
			RRR_MSG_0("Error while attempting to connect to socket\n");
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}

		while (rrr_stats_abort != 1 && data.socket_fd != 0) {
			if (__rrr_stats_tick(&data) != 0) {
				ret = EXIT_FAILURE;
				goto out_cleanup_cmd;
			}

			if (rrr_time_get_64() > next_keep_alive) {
				if (__rrr_stats_send_keepalive(&data) != 0) {
					ret = EXIT_FAILURE;
					goto out_cleanup_cmd;
				}
				next_keep_alive = rrr_time_get_64() + (RRR_STATS_KEEPALIVE_INTERVAL_MS * 1000);
			}

			rrr_posix_usleep (RRR_STATS_TICK_SLEEP_MS * 1000);
		}

		if (rrr_stats_abort != 1 && data.socket_fd == 0) {
			rrr_posix_usleep (RRR_STATS_RECONNECT_SLEEP_MS * 1000);
		}
	}

	out_cleanup_cmd:
		rrr_config_set_debuglevel_on_exit();
		rrr_socket_close_all();
		cmd_destroy(&cmd);
	out_cleanup_data:
		__rrr_stats_data_cleanup(&data);
	out:
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_final:
		return ret;
}
