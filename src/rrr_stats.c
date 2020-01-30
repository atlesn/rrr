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

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>

#include "global.h"
#include "main.h"
#include "lib/version.h"
#include "lib/cmdlineparser/cmdline.h"
#include "../build_timestamp.h"
#include "lib/linked_list.h"
#include "lib/rrr_socket.h"
#include "lib/rrr_readdir.h"

#ifdef _GNU_SOURCE
#	error "Cannot use _GNU_SOURCE, would cause use of incorrect basename() function"
#endif

#define RRR_STATS_DEFAULT_SOCKET_SEARCH_PATH \
	RRR_TMP_PATH "/" RRR_STATS_SOCKET_PREFIX

static volatile int rrr_stats_abort = 0;

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"socket",				"[RRR SOCKET (PREFIX)]"},
		{0,							'e',	"exact_path",			"[-e|--exact_path]"},
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
	struct rrr_linked_list socket_prefixes;
	char *socket_path_active;
	int socket_fd;
	int socket_path_exact;
};

static void __rrr_stats_signal_handler (int s) {
/*	if (s == SIGUSR1) {
		rrr_post_print_stats = 1;
	}*/
	if (s == SIGPIPE) {
		VL_MSG_ERR("Received SIGPIPE, ignoring\n");
	}
	else if (s == SIGTERM) {
		VL_MSG_ERR("Received SIGTERM, exiting\n");
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
	return 0;
}

static void __rrr_stats_data_cleanup (struct rrr_stats_data *data) {
	rrr_linked_list_clear(&data->socket_prefixes);
	RRR_FREE_IF_NOT_NULL(data->socket_path_active);
}

static int __rrr_stats_socket_prefix_register (struct rrr_stats_data *data, const char *prefix) {
	int ret = 0;

	struct rrr_linked_list_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_stats_socket_prefix_register\n");
		ret = 1;
		goto out;
	}
	memset(node, '\0', sizeof(*node));

	node->data = malloc(strlen(prefix) + 1);
	if (node->data == NULL) {
		VL_MSG_ERR("Could not allocate memory in __rrr_stats_socket_prefix_register\n");
		ret = 1;
		goto out;
	}

	strcpy(node->data, prefix);

	RRR_LL_APPEND(&data->socket_prefixes, node);
	node = NULL;

	out:
	if (node != NULL) {
		rrr_linked_list_destroy_node(node);
	}
	return ret;
}

static int __rrr_stats_parse_config (struct rrr_stats_data *data, struct cmd_data *cmd) {
	if (cmd_exists(cmd, "exact_path", 0)) {
		data->socket_path_exact = 1;
	}

	int i = 0;
	while (cmd_exists(cmd, "socket", i)) {
		const char *path = NULL;
		if ((path = cmd_get_value(cmd, "socket", i)) != NULL) {
			if (__rrr_stats_socket_prefix_register(data, path) != 0) {
				VL_MSG_ERR("Could not register socket prefix in __rrr_stats_parse_config\n");
				return 1;
			}
		}
		i++;
	}

	return 0;
}

static int __rrr_stats_attempt_connect_exact (struct rrr_stats_data *data, const char *path) {
	if (data->socket_fd != 0) {
		VL_BUG("socket fd was not 0 in __rrr_stats_attempt_connect_exact\n");
	}

	int ret = 0;

	int fd;
	if ((ret = rrr_socket_unix_create_and_connect(&fd, "rrr_stats_connector", path, 1)) != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			VL_DEBUG_MSG_1("Attempt to connect to %s did not succeed (soft error).\n", path);
			ret = 0; // This is just an attempt, non-critical error
			goto out;
		}

		VL_MSG_ERR("Hard error while connecting to socket %s in __rrr_stats_attempt_connect_exact\n", path);
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_1("Connected to socket %s\n", path);

	data->socket_fd = fd;
	RRR_FREE_IF_NOT_NULL(data->socket_path_active);

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
			VL_DEBUG_MSG_1 ("Found socket %s\n", resolved_path);

			// We could have done this at the top of the function, but it's desirable
			// to have the debug message printed for all matching files
			if (data->data->socket_fd != 0) {
				// Already connected
				return 0;
			}

			if (__rrr_stats_attempt_connect_exact(data->data, resolved_path) != 0) {
				VL_MSG_ERR("Error while connecting to socket %s\n", resolved_path);
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
		VL_MSG_ERR("Prefix was too long in __rrr_stats_attempt_connect_prefix\n");
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
			VL_MSG_ERR("Error while going through directory %s\n", prefix);
		}
	}
	else {
		prefix_copy_a = strdup(prefix);
		prefix_copy_b = strdup(prefix);

		if (prefix_copy_a == NULL || prefix_copy_b == NULL) {
			VL_MSG_ERR("Could not duplicate path in __rrr_stats_attempt_connect_prefix\n");
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
			VL_MSG_ERR("Error while going through directory %s\n", dir_name);
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
			VL_MSG_ERR("Could not register default socket prefix in __rrr_stats_attempt_connect\n");
			ret = 1;
			goto out;
		}
	}

	RRR_LL_ITERATE_BEGIN(&data->socket_prefixes, struct rrr_linked_list_node);
		if (data->socket_fd != 0) {
			// We are connected
			RRR_LL_ITERATE_BREAK();
		}
		if (__rrr_stats_attempt_connect_prefix(data, node->data) != 0) {
			VL_MSG_ERR("Error while attempting to connect to socket prefix %s\n", (char *) node->data);
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	// NOTE : Connection failure is not always an error
	return ret;
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct cmd_data cmd;
	struct rrr_stats_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (__rrr_stats_data_init(&data) != 0) {
		VL_MSG_ERR("Could not initialize stats data\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if ((ret = main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	if (rrr_print_help_and_version(&cmd, 1) != 0) {
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

	while (rrr_stats_abort != 1) {
		rrr_socket_close_all();
		data.socket_fd = 0;

		if (__rrr_stats_attempt_connect(&data) != 0) {
			VL_MSG_ERR("Error while attempting to connect to socket\n");
			ret = EXIT_FAILURE;
			goto out_cleanup_cmd;
		}

		usleep (100000);

		break;
	}

	out_cleanup_cmd:
		rrr_set_debuglevel_on_exit();
		rrr_socket_close_all();
		cmd_destroy(&cmd);
	out_cleanup_data:
		__rrr_stats_data_cleanup(&data);
	out:
		return ret;
}
