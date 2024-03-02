/*

Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

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
#include "lib/common.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/event/event.h"
#include "lib/event/event_collection.h"
#include "lib/event/event_collection_struct.h"
#include "lib/rrr_strerror.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/map.h"
#include "lib/read.h"
#include "lib/socket/rrr_socket.h"
#include "lib/socket/rrr_socket_read.h"
#include "lib/messages/msg.h"
#include "lib/messages/msg_msg.h"
#include "lib/messages/msg_dump.h"
#include "lib/socket/rrr_socket_constants.h"
#include "lib/socket/rrr_socket_client.h"
#include "lib/stats/stats_message.h"
#include "lib/stats/stats_tree.h"
#include "lib/util/rrr_time.h"
#include "lib/util/linked_list.h"
#include "lib/util/rrr_readdir.h"
#include "lib/util/macro_utils.h"
#include "lib/util/posix.h"

#ifdef _GNU_SOURCE
#	error "Cannot use _GNU_SOURCE, would cause use of incorrect basename() function"
#endif


#define RRR_STATS_DEFAULT_SOCKET_SEARCH_PATH \
    RRR_RUN_DIR "/" RRR_STATS_SOCKET_PREFIX

#define RRR_STATS_CONNECTION_TIMEOUT_MS         RRR_STATS_FIRST_PACKET_WAIT_LIMIT_MS
#define RRR_STATS_MESSAGE_LIFETIME_MS           1500
#define RRR_STATS_DUMP_TREE_INTERVAL_S          2

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_stats");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG_MULTI,  '\0',    "socket",                "[RRR SOCKET (PREFIX)] ..."},
        {0,                            'p',    "exact-path",            "[-p|--exact-path]"},
        {0,                            'E',    "events",                "[-E|--events]"},
        {0,                            'J',    "journal",               "[-J|--journal]"},
        {0,                            'M',    "messages",              "[-M|--messages]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                  "[-h|--help]"},
        {0,                            'v',    "version",               "[-v|--version]"},
        {0,                            '\0',    NULL,                   NULL}
};

struct rrr_stats_data {
	struct rrr_read_session_collection read_sessions;
	struct rrr_map socket_prefixes;
	struct rrr_stats_tree message_tree;
	char *socket_path_active;

	int do_socket_path_exact;
	int do_print_journal;
	int do_print_messages;
	int do_print_events;

	struct rrr_socket_client_collection *connections;

	struct rrr_event_queue *queue;
	rrr_event_receiver_handle queue_handle;
	struct rrr_event_collection events;

	rrr_event_handle event_keepalive;
	rrr_event_handle event_dump_tree;
};

struct rrr_stats_connection {
	struct rrr_msg_stats *message_preface;
};

static int __rrr_stats_connection_new (void **target, int fd, void *private_arg) {
	(void)(fd);
	(void)(private_arg);

	struct rrr_stats_connection *connection;

	if ((connection = rrr_allocate_zero(sizeof(*connection))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return 1;
	}

	*target = connection;

	return 0;
}

static void __rrr_stats_connection_destroy (void *target) {
	struct rrr_stats_connection *connection = target;

	if (connection->message_preface != NULL) {
		rrr_msg_stats_destroy(connection->message_preface);
	}

	rrr_free(connection);
}

static int __rrr_stats_connection_msg_preface_set (
		struct rrr_stats_connection *connection,
		const struct rrr_msg_stats *message
) {
	int ret = 0;

	if (connection->message_preface != NULL) {
		rrr_msg_stats_destroy(connection->message_preface);
	}

	if ((ret = rrr_msg_stats_duplicate(&connection->message_preface, message)) != 0) {
		RRR_MSG_0("Could not duplicate message in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static volatile int main_running = 1;
static volatile int sigusr2 = 0;

int rrr_stats_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, &sigusr2, s, arg);
}

static int __rrr_stats_data_init (
		struct rrr_stats_data *data
) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	rrr_read_session_collection_init(&data->read_sessions);

	if ((ret = rrr_stats_tree_init(&data->message_tree)) != 0) {
		RRR_MSG_0("Could not initialize message tree in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_event_queue_new(&data->queue)) != 0) {
		RRR_MSG_0("Could not create event queue in %s\n", __func__);
		goto out_clear_stats_tree;
	}

	if ((ret = rrr_event_receiver_new (
			&data->queue_handle,
			data->queue,
			data
	)) != 0) {
		RRR_MSG_0("Could not create event receiver in %s\n", __func__);
		goto out_destroy_event_queue;
	}

	rrr_event_collection_init(&data->events, data->queue);

	if ((ret = rrr_socket_client_collection_new(&data->connections, data->queue, "rrr_stats")) != 0) {
		goto out_destroy_event_queue;
	}

	goto out;
//	out_destroy_client_collection:
//		rrr_socket_client_collection_destroy(data->connections);
	out_destroy_event_queue:
		rrr_event_queue_destroy(data->queue);
	out_clear_stats_tree:
		rrr_stats_tree_clear(&data->message_tree);
	out:
		return ret;
}

static void __rrr_stats_data_cleanup (
		struct rrr_stats_data *data
) {
	rrr_read_session_collection_clear(&data->read_sessions);
	rrr_map_clear(&data->socket_prefixes);
	rrr_stats_tree_clear(&data->message_tree);
	RRR_FREE_IF_NOT_NULL(data->socket_path_active);
	rrr_socket_client_collection_destroy(data->connections);
	rrr_event_collection_clear(&data->events);
	rrr_event_queue_destroy(data->queue);
}

static int __rrr_stats_socket_prefix_register (
		struct rrr_stats_data *data,
		const char *prefix
) {
	int ret = 0;

	struct rrr_map_item *node = rrr_allocate(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}
	memset(node, '\0', sizeof(*node));

	node->tag = rrr_strdup(prefix);
	if (node->tag == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_LL_APPEND(&data->socket_prefixes, node);
	node = NULL;

	out:
	if (node != NULL) {
		rrr_map_item_destroy(node);
	}
	return ret;
}

static int __rrr_stats_parse_config (
		struct rrr_stats_data *data,
		struct cmd_data *cmd
) {
	if (cmd_exists(cmd, "exact-path", 0)) {
		data->do_socket_path_exact = 1;
	}

	if (cmd_exists(cmd, "journal", 0)) {
		data->do_print_journal = 1;
	}

	if (cmd_exists(cmd, "messages", 0)) {
		data->do_print_messages = 1;
	}

	if (cmd_exists(cmd, "events", 0)) {
		data->do_print_events = 1;
	}

	if (data->do_print_journal + data->do_print_messages + data->do_print_events > 1) {
		RRR_MSG_0("Cannot print messages, events and/or journal simultaneously. Check arguments.\n");
		return 1;
	}

	cmd_arg_count i = 0;
	while (cmd_exists(cmd, "socket", i)) {
		const char *path = NULL;
		if ((path = cmd_get_value(cmd, "socket", i)) != NULL) {
			if (__rrr_stats_socket_prefix_register(data, path) != 0) {
				RRR_MSG_0("Could not register socket prefix in $%s\n");
				return 1;
			}
		}
		i++;
	}

	return 0;
}

static int __rrr_stats_attempt_connect_exact (
		struct rrr_stats_data *data,
		const char *path
) {
	int ret = 0;

	if (rrr_socket_get_fd_from_filename(path) >= 0) {
		// Already connected
		goto out;
	}

	int fd;
	if ((ret = rrr_socket_unix_connect(&fd, "rrr_stats_connector", path, 1)) != RRR_SOCKET_OK) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_DBG_1("Attempt to connect to %s did not succeed (soft error).\n", path);
			ret = 0; // This is just an attempt, non-critical error
			goto out;
		}

		RRR_MSG_0("Hard error while connecting to socket %s in %s\n", path, __func__);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Connected to socket %s\n", path);

	RRR_FREE_IF_NOT_NULL(data->socket_path_active);
	if ((data->socket_path_active = rrr_strdup(path)) == NULL) {
		RRR_MSG_0("Could not save socket path name in %s\n", __func__);
		ret = 1;
		goto out_close;
	}

	if ((ret = rrr_socket_client_collection_connected_fd_push(data->connections, fd, RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND)) != 0) {
		goto out_close;
	}

	goto out;

	out_close:
	if (fd != 0) {
		rrr_socket_close(fd);
	}

	out:
	return ret;
}

struct rrr_stats_attempt_connect_prefix_callback_data {
	struct rrr_stats_data *data;
};

static int __rrr_stats_attempt_connect_prefix_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct rrr_stats_attempt_connect_prefix_callback_data *data = private_data;

	(void)(orig_path);
	(void)(entry);

/*	printf ("in callback: %s - %s - %s type %u resolved path %s\n",
			data->dir_name,
			data->base_name,
			entry->d_name,
			type,
			resolved_path
	);*/

	if (type == DT_SOCK) {
		RRR_DBG_1 ("Found socket %s\n", resolved_path);

		if (__rrr_stats_attempt_connect_exact(data->data, resolved_path) != 0) {
			RRR_MSG_0("Error while connecting to socket %s\n", resolved_path);
			return 1;
		}
	}

	return 0;
}

static int __rrr_stats_attempt_connect_prefix (
		struct rrr_stats_data *data,
		const char *prefix
) {
	char *prefix_copy_a = NULL;
	char *prefix_copy_b = NULL;

	int ret = 0;

	if (strlen(prefix) > PATH_MAX) {
		RRR_MSG_0("Prefix was too long in %s\n", __func__);
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
			data
		};

		if ((ret = rrr_readdir_foreach (
				prefix,
				__rrr_stats_attempt_connect_prefix_callback,
				&callback_data
	)) != 0) {
			RRR_MSG_0("Error while going through directory %s\n", prefix);
		}
	}
	else {
		prefix_copy_a = rrr_strdup(prefix);
		prefix_copy_b = rrr_strdup(prefix);

		if (prefix_copy_a == NULL || prefix_copy_b == NULL) {
			RRR_MSG_0("Could not duplicate path in %s\n", __func__);
			ret = 1;
			goto out;
		}

		// These two should not be freed
		char *dir_name = dirname(prefix_copy_a);
		char *base_name = basename(prefix_copy_b);

		struct rrr_stats_attempt_connect_prefix_callback_data callback_data = {
				data
		};

		if ((ret = rrr_readdir_foreach_prefix(
				dir_name,
				base_name,
				__rrr_stats_attempt_connect_prefix_callback,
				&callback_data
		)) != 0) {
			RRR_MSG_0("Error while going through directory %s\n", dir_name);
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(prefix_copy_a);
	RRR_FREE_IF_NOT_NULL(prefix_copy_b);
	return ret;
}

static int __rrr_stats_attempt_connect (
		struct rrr_stats_data *data
) {
	int ret = 0;

	if (RRR_LL_COUNT(&data->socket_prefixes) == 0) {
		if (__rrr_stats_socket_prefix_register(data, RRR_STATS_DEFAULT_SOCKET_SEARCH_PATH) != 0) {
			RRR_MSG_0("Could not register default socket prefix in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	RRR_MAP_ITERATE_BEGIN(&data->socket_prefixes);
		if (data->do_socket_path_exact) {
			RRR_DBG_1("Attempting to use excact path %s\n", node_tag);
			if ((ret = __rrr_stats_attempt_connect_exact(data, node_tag)) != 0) {
				RRR_MSG_0("Error while attempting to connect to socket excact path %s\n", node_tag);
				goto out;
			}
		}
		else {
			RRR_DBG_1("Attempting to use prefix %s\n", node_tag);
			if ((ret = __rrr_stats_attempt_connect_prefix(data, node_tag)) != 0) {
				RRR_MSG_0("Error while attempting to connect to socket prefix %s\n", node_tag);
				goto out;
			}
		}
	RRR_MAP_ITERATE_END();

	out:
	return ret;
}

static int __rrr_stats_send_message (
		struct rrr_stats_data *data,
		const struct rrr_msg_stats *message
) {
	struct rrr_msg_stats_packed message_packed;
	rrr_length total_size;

	rrr_msg_stats_pack_and_flip (
			&message_packed,
			&total_size,
			message
	);

	rrr_msg_populate_head (
			(struct rrr_msg *) &message_packed,
			RRR_MSG_TYPE_STATS,
			total_size,
			(rrr_u32) (message->timestamp / 1000 / 1000)
	);

	rrr_msg_checksum_and_to_network_endian (
			(struct rrr_msg *) &message_packed
	);

	RRR_DBG_3("TX size %" PRIrrrl " sticky %i path %s\n",
			total_size,
			RRR_STATS_MESSAGE_FLAGS_IS_STICKY(message),
			message->path
	);

	rrr_length send_chunk_count_dummy = 0;
	rrr_socket_client_collection_send_push_const_multicast (
			&send_chunk_count_dummy,
			data->connections,
			&message_packed,
			total_size,
			10 // Send chunk count limit
	); 

	return 0;
}

static int __rrr_stats_send_keepalive (
		struct rrr_stats_data *data
) {
	struct rrr_msg_stats message;

	if (rrr_msg_stats_init(&message, RRR_STATS_MESSAGE_TYPE_KEEPALIVE, 0, "", NULL, 0) != 0) {
		RRR_MSG_0("Could not initialize keepalive message in %s\n", __func__);
		return 1;
	}

	return __rrr_stats_send_message(data, &message);
}

static int __rrr_stats_process_journal_message (
		const struct rrr_msg_stats *message,
		void *private_arg1,
		void *private_arg2
) {
	struct rrr_stats_data *data = private_arg2;

	(void)(private_arg1);
	(void)(data);

	int ret = 0;

	if (message->type != RRR_STATS_MESSAGE_TYPE_TEXT) {
		goto out;
	}

	if (!RRR_STATS_MESSAGE_FLAGS_IS_LOG(message)) {
		goto out;
	}

	// TODO : Try to do this (check if path is log message) without generating the tree.

	struct rrr_stats_tree tree_tmp;
	if ((ret = rrr_stats_tree_init(&tree_tmp)) != 0) {
		RRR_MSG_0("Could not initialize tree in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_stats_tree_insert_or_update(&tree_tmp, message)) != 0) {
		RRR_MSG_0("Could not insert message into tree in %s\n", __func__);
		goto out_cleanup_tree;
	}

	if (rrr_stats_tree_has_leaf(&tree_tmp, RRR_STATS_MESSAGE_PATH_GLOBAL_LOG_HOOK)) {
		printf("%s", message->data);
	}

	out_cleanup_tree:
		rrr_stats_tree_clear(&tree_tmp);
	out:
		return ret;
}

static int __rrr_stats_process_stats_message (
		const struct rrr_msg_stats *message,
		void *private_arg1,
		void *private_arg2
) {
	struct rrr_stats_connection *connection = private_arg1;
	struct rrr_stats_data *data = private_arg2;

	(void)(connection);

	int ret = 0;

	if (RRR_STATS_MESSAGE_FLAGS_IS_RRR_MSG_PREFACE(message) ||
	    RRR_STATS_MESSAGE_FLAGS_IS_EVENT(message) ||
	    RRR_STATS_MESSAGE_FLAGS_IS_LOG(message)
	) {
		goto out;
	}

	if ((ret = rrr_stats_tree_insert_or_update(&data->message_tree, message)) != 0) {
		if (ret == RRR_STATS_TREE_SOFT_ERROR) {
			RRR_MSG_0("Message with path %s was invalid, not added to tree in %s\n", message->path, __func__);
			ret = 0;
			goto out;
		}

		RRR_MSG_0("Error while inserting message in tree in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static int  __rrr_stats_process_event_message  (
		const struct rrr_msg_stats *message,
		void *private_arg1,
		void *private_arg2
) {
	struct rrr_stats_connection *connection = private_arg1;
	struct rrr_stats_data *data = private_arg2;

	(void)(connection);
	(void)(data);

	int ret = 0;

	struct rrr_stats_tree tree_tmp;

	if (!RRR_STATS_MESSAGE_FLAGS_IS_EVENT(message)) {
		goto out;
	}

	if ((ret = rrr_stats_tree_init(&tree_tmp)) != 0) {
		RRR_MSG_0("Could not initialize tree in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_stats_tree_insert_or_update(&tree_tmp, message)) != 0) {
		if (ret == RRR_STATS_TREE_SOFT_ERROR) {
			RRR_MSG_0("Message with path %s was invalid, not added to tree in %s\n", message->path, __func__);
			ret = 0;
			goto out_cleanup_tree;
		}

		RRR_MSG_0("Error while inserting message in tree in %s\n", __func__);
		goto out_cleanup_tree;
	}

	rrr_stats_tree_dump(&tree_tmp);

	out_cleanup_tree:
		rrr_stats_tree_clear(&tree_tmp);
	out:
		return ret;
}

static int __rrr_stats_process_preface_message (
		const struct rrr_msg_stats *message,
		void *private_arg1,
		void *private_arg2
) {
	struct rrr_stats_connection *connection = private_arg1;
	struct rrr_stats_data *data = private_arg2;

	(void)(data);

	int ret = 0;

	if (!RRR_STATS_MESSAGE_FLAGS_IS_RRR_MSG_PREFACE(message)) {
		goto out;
	}

	if ((ret = __rrr_stats_connection_msg_preface_set(connection, message)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int __rrr_stats_process_rrr_message (
		struct rrr_msg_msg **message,
		void *private_arg1,
		void *private_arg2
) {
	struct rrr_stats_connection *connection = private_arg1;
	struct rrr_stats_data *data = private_arg2;

	(void)(data);

	int ret = 0;

	struct rrr_stats_tree tree_tmp;
	struct rrr_msg_stats *message_preface = NULL;

	if (connection->message_preface == NULL) {
		goto out;
	}

	message_preface = connection->message_preface;
	connection->message_preface = NULL;

	assert(RRR_STATS_MESSAGE_FLAGS_IS_RRR_MSG_PREFACE(message_preface) && "Preface flag must be set");

	if ((ret = rrr_stats_tree_init(&tree_tmp)) != 0) {
		RRR_MSG_0("Could not initialize tree in %s\n", __func__);
		goto out_destroy_preface;
	}

	if ((ret = rrr_stats_tree_insert_or_update(&tree_tmp, message_preface)) != 0) {
		RRR_MSG_0("Could not insert message into tree in %s\n", __func__);
		goto out_cleanup_tree;
	}

	rrr_stats_tree_dump(&tree_tmp);

	if ((ret = rrr_msg_dump_msg (*message)) != 0) {
		RRR_MSG_0("Failed to dump message in %s\n", __func__);
		goto out_cleanup_tree;
	}

	out_cleanup_tree:
		rrr_stats_tree_clear(&tree_tmp);
	out_destroy_preface:
		rrr_msg_stats_destroy(message_preface);
	out:
		return ret;
}

static void __rrr_stats_event_keepalive (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_stats_data *data = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if (__rrr_stats_send_keepalive(data) != 0) {
		rrr_event_dispatch_break(data->queue);
	}
}

static void __rrr_stats_event_dump_tree (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_stats_data *data = arg;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if (!data->do_print_journal && !data->do_print_messages && !data->do_print_events) {
		printf ("- TICK MS %" PRIu64 "\n", rrr_time_get_64() / 1000);

		unsigned int purged_total = 0;

		rrr_stats_tree_dump(&data->message_tree);
		rrr_stats_tree_purge_old_branches(&purged_total, &data->message_tree, rrr_time_get_64() - RRR_STATS_MESSAGE_LIFETIME_MS * 1000);
		printf ("------ Purged: %u\n", purged_total);
	}
}

static int __rrr_stats_events_setup (struct rrr_stats_data *data) {
	int ret = 0;

	if ((ret = rrr_event_collection_push_periodic (
			&data->event_keepalive,
			&data->events,
			__rrr_stats_event_keepalive,
			data,
			(RRR_SOCKET_CLIENT_HARD_TIMEOUT_S / 2) * 1000 * 1000
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_event_collection_push_periodic (
			&data->event_dump_tree,
			&data->events,
			__rrr_stats_event_dump_tree,
			data,
			RRR_STATS_DUMP_TREE_INTERVAL_S * 1000 * 1000
	)) != 0) {
		goto out;
	}

	EVENT_ADD(data->event_keepalive);
	EVENT_ADD(data->event_dump_tree);

	out:
	return ret;
}

static int __rrr_stats_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_stats_data *data = arg;

	if (!main_running) {
		return RRR_EVENT_EXIT;
	}

	if (sigusr2) {
		RRR_MSG_0("Received SIGUSR2, but this is not implemented in statistics client\n");
		sigusr2 = 0;
	}

	if (__rrr_stats_attempt_connect(data) != 0) {
		return 1;
	}

	rrr_allocator_maintenance_nostats();

	return 0;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}
	rrr_strerror_init();

	struct cmd_data cmd;
	struct rrr_stats_data data = {0};
	struct rrr_signal_handler *signal_handler = NULL;

	cmd_init(&cmd, cmd_rules, argc, argv);

	signal_handler = rrr_signal_handler_push(rrr_stats_signal_handler, NULL);
	rrr_signal_default_signal_actions_register();

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

	if (__rrr_stats_data_init(&data) != 0) {
		RRR_MSG_0("Could not initialize stats data\n");
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 1) != 0) {
		goto out_cleanup_data;
	}

	if (__rrr_stats_parse_config(&data, &cmd) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	int (*message_callback)(const struct rrr_msg_stats *, void *, void *) = NULL;

	if (data.do_print_journal) {
		message_callback = __rrr_stats_process_journal_message;
	}
	else if (data.do_print_messages) {
		message_callback = __rrr_stats_process_preface_message;
	}
	else if (data.do_print_events) {
		message_callback = __rrr_stats_process_event_message;
	}
	else {
		message_callback = __rrr_stats_process_stats_message;
	}

	rrr_socket_client_collection_event_setup (
			data.connections,
			__rrr_stats_connection_new,
			__rrr_stats_connection_destroy,
			NULL,
			4096,
			RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
			NULL,
			NULL,
			__rrr_stats_process_rrr_message,
			NULL,
			NULL,
			NULL,
			message_callback,
			&data
	);

	if (__rrr_stats_attempt_connect(&data) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	if (__rrr_stats_events_setup (&data) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if (rrr_event_function_periodic_set (
			data.queue,
			data.queue_handle,
			1 * 1000 * 1000, // 1s
			__rrr_stats_event_periodic
	) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	if (rrr_event_dispatch (data.queue) != 0) {
		ret = EXIT_FAILURE;
	}

	out_cleanup_data:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		__rrr_stats_data_cleanup(&data);
	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_signal_handler_remove(signal_handler);
		rrr_config_set_debuglevel_on_exit();
		cmd_destroy(&cmd);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
		rrr_socket_close_all();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
