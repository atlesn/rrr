/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#ifdef RRR_WITH_JEMALLOC
#	include <jemalloc/jemalloc.h>
#endif

#include "main.h"
#include "lib/rrr_config.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/rrr_shm.h"
#include "lib/event/event.h"
#include "lib/common.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/version.h"
#include "lib/threads.h"
#include "lib/version.h"
#include "lib/socket/rrr_socket.h"
#include "lib/stats/stats_engine.h"
#include "lib/stats/stats_message.h"
#include "lib/messages/msg_msg.h"
#include "lib/rrr_strerror.h"
#include "lib/message_broker.h"
#include "lib/map.h"
#include "lib/fork.h"
#include "lib/rrr_umask.h"
#include "lib/allocator.h"
#include "lib/rrr_mmap_stats.h"
#include "lib/message_holder/message_holder_struct.h"
#include "lib/util/rrr_readdir.h"
#include "lib/util/gnu.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr");

#define RRR_CONFIG_FILE_SUFFIX	".conf"
#define RRR_GLOBAL_UMASK		S_IROTH | S_IWOTH | S_IXOTH

#ifndef RRR_MODULE_PATH
#	define	RRR_MODULE_PATH "."
#endif
#ifndef RRR_CMODULE_PATH
#	define	RRR_CMODULE_PATH "."
#endif

const char *module_library_paths[] = {
		RRR_MODULE_PATH,
		RRR_CMODULE_PATH,
		"/usr/lib/rrr",
		"/lib/rrr",
		"/usr/local/lib/rrr",
		"/usr/lib/",
		"/lib/",
		"/usr/local/lib/",
		"./src/modules/.libs",
		"./src/modules",
		"./src/tests/modules/.libs",
		"./src/tests/modules",
		"./modules",
		"./",
		""
};

#ifndef RRR_BUILD_TIMESTAMP
#define RRR_BUILD_TIMESTAMP 1
#endif

// Used so that debugger output at program exit can show function names
// on the stack correctly
//#define RRR_NO_MODULE_UNLOAD

static int some_fork_has_stopped = 0;
static int main_running = 1;
int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG_MULTI,   '\0',   "config",                "{CONFIGURATION FILE OR DIRECTORY}"},
		{0,                            'W',    "no-watchdog-timers",    "[-W|--no-watchdog-timers]"},
		{0,                            'T',    "no-thread-restart",     "[-T|--no-thread-restart]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    't',    "start-interval",        "[-t|--start-interval]"},
		{0,                            's',    "stats",                 "[-s|--stats]"},
		{0,                            'E',    "event-hooks",           "[-E|--event-hooks]"},
		{0,                            'M',    "message-hooks",         "[-M|--message-hooks]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'r',    "run-directory",         "[-r|--run-directory[=]RUN DIRECTORY]"},
		{0,                            'l',    "loglevel-translation",  "[-l|--loglevel-translation]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'o',    "output-buffer-warn-limit", "[-o|--output-buffer-warn-limit[=]LIMIT]"},
		{0,                            'b',    "banner",                "[-b|--banner]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",    "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
		{0,                            'h',    "help",                  "[-h|--help]"},
		{0,                            'v',    "version",               "[-v|--version]"},
		{0,                            'i',    "install-directories",   "[-i|--install-directories]"},
		{0,                            '\0',    NULL,                   NULL}
};

#define DUMP_INSTALL_DIRECTORY(name,value) \
	printf("%s:%s\n", name, value)

void dump_install_directories (void) {
	DUMP_INSTALL_DIRECTORY("module-dir", RRR_MODULE_PATH);
	DUMP_INSTALL_DIRECTORY("cmodule-dir", RRR_CMODULE_PATH);
}

struct stats_data {
	unsigned int handle;
	int log_hook_handle;
	struct rrr_stats_engine engine;
};

static int main_stats_post_text_message (struct stats_data *stats_data, const char *path, const char *text, uint32_t flags) {
	struct rrr_msg_stats message;

	if (rrr_msg_stats_init (
			&message,
			RRR_STATS_MESSAGE_TYPE_TEXT,
			flags,
			path,
			text,
			rrr_u16_from_biglength_bug_const (strlen(text) + 1)
	) != 0) {
		RRR_BUG("Could not initialize main statistics message\n");
	}

	if (rrr_stats_engine_post_message(&stats_data->engine, stats_data->handle, "main", &message) != 0) {
		RRR_MSG_0("Could not post main statistics message\n");
		return 1;
	}

	return 0;
}

static int main_stats_post_unsigned_message (struct stats_data *stats_data, const char *path, uint64_t value, uint32_t flags) {
	struct rrr_msg_stats message;

	char text[125];
	sprintf(text, "%" PRIu64, value);

	if (rrr_msg_stats_init (
			&message,
			RRR_STATS_MESSAGE_TYPE_BASE10_TEXT,
			flags,
			path,
			text,
			rrr_u16_from_biglength_bug_const (strlen(text) + 1)
	) != 0) {
		RRR_BUG("Could not initialize main statistics message\n");
	}

	if (rrr_stats_engine_post_message(&stats_data->engine, stats_data->handle, "main", &message) != 0) {
		RRR_MSG_0("Could not post main statistics message\n");
		return 1;
	}

	return 0;
}

static int main_stats_post_sticky_messages (struct stats_data *stats_data, struct rrr_instance_collection *instances) {
	int ret = 0;

	char msg_text[RRR_STATS_MESSAGE_DATA_MAX_SIZE + 1];

	if (snprintf (
			msg_text,
			RRR_STATS_MESSAGE_DATA_MAX_SIZE,
			"RRR running with %i instances",
			rrr_instance_collection_count(instances)
	) >= RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		RRR_BUG("Statistics message too long in main\n");
	}

	if ((ret = main_stats_post_text_message(stats_data, "status", msg_text, RRR_STATS_MESSAGE_FLAGS_STICKY)) != 0) {
		goto out;
	}

	unsigned int i = 0;
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;
		char path[128];
		sprintf(path, "instance_metadata/%u", i);

		if ((ret = main_stats_post_text_message(stats_data, path, instance->module_data->instance_name, RRR_STATS_MESSAGE_FLAGS_STICKY)) != 0) {
			goto out;
		}

		sprintf(path, "instance_metadata/%u/module", i);
		if ((ret = main_stats_post_text_message(stats_data, path, instance->module_data->module_name, RRR_STATS_MESSAGE_FLAGS_STICKY)) != 0) {
			goto out;
		}

		unsigned int j = 0;
		RRR_LL_ITERATE_BEGIN(&instance->senders, struct rrr_instance_friend);
			sprintf(path, "instance_metadata/%u/senders/%u", i, j);
			if ((ret = main_stats_post_text_message(stats_data, path, node->instance->module_data->instance_name, RRR_STATS_MESSAGE_FLAGS_STICKY)) != 0) {
				goto out;
			}
			j++;
		RRR_LL_ITERATE_END();

		i++;
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int main_loop_log_hook_retry_callback (
		void *arg
) {
	struct stats_data *stats_data = arg;

 	(void)(stats_data);

	fprintf(stderr, "Error: Too many log events, a build-up has occured. This may happen if log messages are generated when sending data to statistics clients. Consider disconnecting statistics client or disabling some debug levels.\n");

	main_running = 0;

	return RRR_EVENT_ERR;
}

static void main_stats_message_pre_buffer_hook (
		RRR_MESSAGE_BROKER_HOOK_MSG_ARGS
) {
	struct stats_data *stats_data = arg;

	int hop_count = 0;
	char **hop_names = NULL;
	const struct rrr_msg_msg *message = entry_locked->message;
	char path[128];
	int bytes;

	assert(RRR_MSG_IS_RRR_MESSAGE(message));

	if ((hop_names = rrr_allocate (
			sizeof(*hop_names) * (RRR_LL_COUNT(&entry_locked->nexthops) + 1)
	)) == NULL) {
		RRR_BUG("Could not allocate memory for hop names\n");
	}

	RRR_LL_ITERATE_BEGIN(&entry_locked->nexthops, struct rrr_instance_friend);
		if ((hop_names[hop_count] = rrr_strdup(INSTANCE_M_NAME(node->instance))) == NULL) {
			RRR_BUG("Could not allocate memory for hop name\n");
		}
		hop_count++;
	RRR_LL_ITERATE_END();

	bytes = snprintf(path, sizeof(path), "pre_buffer/%s", costumer);
	assert(bytes >= 0);
	if ((unsigned int) bytes >= sizeof(path)) {
		RRR_BUG("Path buffer too small\n");
	}

	if (rrr_stats_engine_push_rrr_message (
			&stats_data->engine,
			stats_data->handle,
			"main",
			path,
			message,
			(const char **) hop_names,
			(uint32_t) hop_count
	) != 0) {
		RRR_BUG("Could not send message int %s\n", __func__);
	}

	for (int i = 0; i < hop_count; i++) {
		rrr_free(hop_names[i]);
	}

	rrr_free(hop_names);
}

void main_loop_event_hook(RRR_EVENT_HOOK_ARGS) {
	struct stats_data *stats_data = arg;

	char text[256];

	snprintf(text, sizeof(text), "pid: % 8lli tid: % 8lli func: %-45s fd: % 4i time: %" PRIu64 " flags: %i pollin: %i pollout: %i pollhup: %i pollerr: %i",
		(long long int) getpid(),
		(long long int) rrr_gettid(),
		source_func,
		fd,
		rrr_time_get_64(),
		flags,
		(flags & POLLIN) != 0,
		(flags & POLLOUT) != 0,
		(flags & POLLHUP) != 0,
		(flags & POLLERR) != 0
	);

	if (rrr_stats_engine_push_event_message (
			&stats_data->engine,
			stats_data->handle,
			"main",
			text
	) != 0) {
		RRR_BUG("Could not initialize main statistics message\n");
	}
}

static void main_loop_log_hook (RRR_LOG_HOOK_ARGS) {
	struct stats_data *stats_data = private_arg;

	(void)(file);
	(void)(line);
	(void)(loglevel_orig);
	(void)(loglevel_translated);
	(void)(prefix);

	*write_amount = 0;

	if (rrr_stats_engine_push_log_message (
			&stats_data->engine,
			stats_data->handle,
			"main",
			message
	) != 0) {
		RRR_BUG("Could not push message in %s\n", __func__);
	}

	*write_amount = 1;
}

struct main_loop_event_callback_data {
	uint64_t prev_periodic_time;
	struct rrr_thread_collection **collection;
	struct rrr_instance_collection *instances;
	struct rrr_instance_config_collection *config;
	struct cmd_data *cmd;
	struct stats_data *stats_data;
	struct rrr_message_broker *message_broker;
	struct rrr_fork_handler *fork_handler;
	const char *config_file;
	struct rrr_event_queue *queue;
};

static void main_loop_close_sockets_except (
		int stats_socket,
		struct rrr_event_queue *queue
) {
	int fds[RRR_EVENT_QUEUE_FD_MAX + 1];
	size_t fds_count;
	rrr_event_queue_fds_get (fds, &fds_count, queue);

	fds[fds_count++] = stats_socket;

	rrr_socket_close_all_except_array_no_unlink (fds, fds_count);
}

static int main_mmap_periodic (struct stats_data *stats_data) {
	struct rrr_mmap_stats mmap_stats = {0};

	rrr_allocator_maintenance(&mmap_stats);

	int ret = 0;

	if (stats_data != NULL && stats_data->handle != 0) {
		ret |= main_stats_post_unsigned_message (stats_data, "mmap/count", mmap_stats.mmap_total_count, 0);
		ret |= main_stats_post_unsigned_message (stats_data, "mmap/empty_count", mmap_stats.mmap_total_empty_count, 0);
		ret |= main_stats_post_unsigned_message (stats_data, "mmap/bad_count", mmap_stats.mmap_total_bad_count, 0);
		ret |= main_stats_post_unsigned_message (stats_data, "mmap/heap_size", mmap_stats.mmap_total_heap_size, 0);
	}

	if (ret != 0) {
		RRR_MSG_0("Error while posting mmap statistics\n");
	}

	return ret;
}

static void main_loop_periodic_message_broker_report_buffer_callback (const char *name, rrr_length count, void *arg) {
	struct main_loop_event_callback_data *callback_data = arg;
	struct stats_data *stats_data = callback_data->stats_data;

	if (rrr_config_global.output_buffer_warn_limit > 0 && count > rrr_config_global.output_buffer_warn_limit) {
		RRR_MSG_0("Warning: Output buffer of instance %s has %" PRIrrrl " entries\n",
			name, count);
	}

	if (stats_data != NULL && stats_data->handle != 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "message_broker/costumers/%s/buffer/count", name);
		main_stats_post_unsigned_message (stats_data, buf, count, 0);
	}
}

static void main_loop_periodic_message_broker_report_buffer_split_buffer_callback (const char *name, const char *receiver_name, rrr_length count, void *arg) {
	struct main_loop_event_callback_data *callback_data = arg;
	struct stats_data *stats_data = callback_data->stats_data;

	if (rrr_config_global.output_buffer_warn_limit > 0 && count > rrr_config_global.output_buffer_warn_limit) {
		RRR_MSG_0("Warning: Split output buffer of instance %s to receiver %s has %" PRIrrrl " entries\n",
			name, receiver_name, count);
	}

	if (stats_data != NULL && stats_data->handle != 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "message_broker/costumers/%s/split_buffer/%s/count", name, receiver_name);
		main_stats_post_unsigned_message (stats_data, buf, count, 0);
	}
}

static void main_loop_periodic_thread_collection_destroy (
		struct rrr_thread_collection **collection,
		const char *config_file
) {
	int ghost_count = 0;

	rrr_thread_collection_destroy(&ghost_count, *collection);
	*collection = NULL;

	if (ghost_count > 0) {
		// We cannot continue in ghost situations as the ghosts may
		// occupy split buffer slots causing a crash on assertion in
		// the message broker if we restart as not enough slots are
		// available.
		//
		// It is also useful to get a coredump showing the state of
		// the ghost thread, hence we abort here.
		RRR_BUG("%i threads are ghost for configuration %s. Aborting now.\n", config_file);
	}
}

static int main_loop_stats_handle_reset (struct stats_data *stats_data) {
	if (stats_data->handle != 0) {
		rrr_stats_engine_handle_unregister(&stats_data->engine, stats_data->handle);
		stats_data->handle = 0;
	}

	if (rrr_stats_engine_handle_obtain(&stats_data->handle, &stats_data->engine) != 0) {
		RRR_MSG_0("Error while obtaining statistics handle\n");
		return 1;
	}

	return 0;
}

static int main_loop_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct main_loop_event_callback_data *callback_data = arg;

	// Note : Thread collection must be destroyed and pointer set to NULL
	//        before we return from this function, and if not, we will
	//        bugtrap.

	rrr_config_set_debuglevel_orig();

	if (*(callback_data->collection) == NULL) {
		main_loop_close_sockets_except (callback_data->stats_data->engine.socket, callback_data->queue);

		if (rrr_instances_create_and_start_threads (
				callback_data->collection,
				callback_data->instances,
				callback_data->config,
				callback_data->cmd,
				&callback_data->stats_data->engine,
				callback_data->message_broker,
				callback_data->fork_handler
		) != 0) {
			goto out_event_exit;
		}

		if (callback_data->stats_data->engine.initialized) {
			// Reset stats handle to get rid of sticky messages describing any old threads

			if (main_loop_stats_handle_reset(callback_data->stats_data) != 0 ||
			    main_stats_post_sticky_messages(callback_data->stats_data, callback_data->instances) != 0
			) {
				goto out_destroy_thread_collection;
			}
		}
	}

	if (!main_running) {
		RRR_DBG_1 ("Main no longer running for configuration %s\n", callback_data->config_file);
		goto out_destroy_thread_collection;
	}

	rrr_fork_handle_sigchld_and_notify_if_needed(callback_data->fork_handler, 0);

	if (rrr_instance_check_threads_stopped(callback_data->instances)) {
		RRR_DBG_1 ("One or more threads have finished for configuration %s\n", callback_data->config_file);

		rrr_config_set_debuglevel_on_exit();

		main_loop_periodic_thread_collection_destroy(callback_data->collection, callback_data->config_file);

		// If main is still supposed to be active and restart is active, sleep
		// for one second and continue.
		if (main_running && !rrr_config_global.no_thread_restart) {
			rrr_message_broker_unregister_all(callback_data->message_broker);
			rrr_posix_usleep(1000000); // 1s
		}
		else {
			goto out_event_exit;
		}
	}

	const uint64_t now_time = rrr_time_get_64();
	if (now_time - callback_data->prev_periodic_time >= 1000000) {
		// One second interval tasks
		rrr_message_broker_report_buffers (
			callback_data->message_broker,
			main_loop_periodic_message_broker_report_buffer_callback,
			main_loop_periodic_message_broker_report_buffer_split_buffer_callback,
			callback_data
		);
		callback_data->prev_periodic_time = now_time;
	}

	if (main_mmap_periodic(callback_data->stats_data) != 0) {
		RRR_MSG_0("Error while posting mmap statistics in main loop\n");
		goto out_destroy_thread_collection;
	}

	return RRR_EVENT_OK;

	out_destroy_thread_collection:
		rrr_config_set_debuglevel_on_exit();
		main_loop_periodic_thread_collection_destroy(callback_data->collection, callback_data->config_file);
	out_event_exit:
		rrr_config_set_debuglevel_on_exit();
		return RRR_EVENT_EXIT;
}

// We have one loop per fork and one fork per configuration file
// Parent fork only monitors child forks
static int main_loop (
		struct cmd_data *cmd,
		const char *config_file,
		struct rrr_fork_handler *fork_handler
) {
	int ret = 0;

	struct stats_data stats_data = {0};
	struct rrr_message_broker *message_broker = NULL;
	struct rrr_message_broker_hooks hooks = {0};
	struct rrr_event_queue *queue = NULL;

	struct rrr_instance_config_collection *config = NULL;
	struct rrr_instance_collection instances = {0};
	struct rrr_thread_collection *collection = NULL;

	rrr_config_set_log_prefix(config_file);

	if ((ret = rrr_event_queue_new(&queue)) != 0) {
		goto out;
	}

	if ((ret = rrr_instance_config_parse_file(&config, config_file)) != 0) {
		RRR_MSG_0("Configuration file parsing failed for %s\n", config_file);
		goto out_destroy_events;
	}

	RRR_DBG_1("RRR found %d instances in configuration file '%s'\n",
			rrr_instance_config_collection_count(config), config_file);

	if (RRR_DEBUGLEVEL_1) {
		if ((ret = rrr_instance_config_dump(config)) != 0) {
			RRR_MSG_0("Error occured while dumping configuration\n");
			goto out_destroy_config;
		}
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

	if ((ret = rrr_instances_create_from_config(&instances, config, module_library_paths)) != 0) {
		goto out_destroy_instance_metadata;
	}

	if (cmd_exists(cmd, "stats", 0)) {
		if ((ret = rrr_stats_engine_init(&stats_data.engine, queue)) != 0) {
			RRR_MSG_0("Could not initialize statistics engine\n");
			goto out_destroy_instance_metadata;
		}

		if ((ret = rrr_stats_engine_handle_obtain(&stats_data.handle, &stats_data.engine)) != 0) {
			RRR_MSG_0("Error while obtaining statistics handle\n");
			goto out_destroy_instance_metadata;
		}

		if (cmd_exists(cmd, "message-hooks", 0)) {
			RRR_DBG_1("Enabling message hooks for statistics\n");

			hooks.pre_buffer = main_stats_message_pre_buffer_hook;
			hooks.arg = &stats_data;
		}

		if (cmd_exists(cmd, "event-hooks", 0)) {
			rrr_event_hook_set (main_loop_event_hook, &stats_data);
		}

		rrr_log_hook_register (
				&stats_data.log_hook_handle,
				main_loop_log_hook,
				&stats_data,
				queue,
				main_loop_log_hook_retry_callback,
				&stats_data
		);

	}

	if ((ret = rrr_message_broker_new(&message_broker, &hooks)) != 0) {
		goto out_destroy_stats_engine;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	struct main_loop_event_callback_data event_callback_data = {
		0,
		&collection,
		&instances,
		config,
		cmd,
		&stats_data,
		message_broker,
		fork_handler,
		config_file,
		queue
	};

	rrr_event_dispatch (
			queue,
			250 * 1000, // 250 ms
			main_loop_periodic,
			&event_callback_data
	);

	RRR_DBG_1 ("Main loop finished\n");

	if (collection != NULL) {
		RRR_BUG("Thread collection was not cleared after loop finished in %s\n", __func__);
	}

	if (stats_data.log_hook_handle != 0) {
		rrr_log_hook_unregister(stats_data.log_hook_handle);
	}

	if (stats_data.handle != 0) {
		rrr_stats_engine_handle_unregister(&stats_data.engine, stats_data.handle);
	}

	RRR_DBG_1("Debuglevel on exit is: %i\n", rrr_config_global.debuglevel);

#ifndef RRR_NO_MODULE_UNLOAD
	rrr_instance_unload_all(&instances);
#endif
	rrr_message_broker_destroy(message_broker);

	out_destroy_stats_engine:
		rrr_stats_engine_cleanup(&stats_data.engine);
	out_destroy_instance_metadata:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_instance_collection_clear(&instances);
	out_destroy_config:
		rrr_instance_config_collection_destroy(config);
	out_destroy_events:
		rrr_event_queue_destroy(queue);
	out:
		return ret;
}

static int get_config_files_test_open (const char *path) {
	int fd_tmp = open(path, O_RDONLY);
	if (fd_tmp == -1) {
		return 1;
	}
	close(fd_tmp);
	return 0;
}

static int get_config_files_suffix_ok (const char *check_path) {
	const char *suffix = RRR_CONFIG_FILE_SUFFIX;

	const char *check_pos = check_path + strlen(check_path) - 1;
	const char *suffix_pos = suffix + strlen(suffix) - 1;

	while (check_pos >= check_path && suffix_pos >= suffix) {
		if (*check_pos != *suffix_pos) {
			return 0;
		}
		check_pos--;
		suffix_pos--;
	}

	return 1;
}

static int get_config_files_callback (
		struct dirent *entry,
		const char *orig_path,
		const char *resolved_path,
		unsigned char type,
		void *private_data
) {
	struct rrr_map *target = private_data;

	(void)(orig_path);
	(void)(entry);
	(void)(type);

	int ret = 0;

	if (!get_config_files_suffix_ok(resolved_path)) {
		RRR_DBG_1("Note: File '%s' found in a configuration directory did not have the correct suffix '%s', ignoring it.\n",
				resolved_path, RRR_CONFIG_FILE_SUFFIX);
		goto out;
	}

	if ((ret = get_config_files_test_open(resolved_path)) != 0) {
		RRR_MSG_0("Configuration file '%s' could not be opened: %s\n", orig_path, rrr_strerror(errno));
		goto out;
	}

	if ((ret = rrr_map_item_add_new(target, resolved_path, "")) != 0) {
		RRR_MSG_0("Could not add configuration file to map\n");
		goto out;
	}

	out:
	return ret;
}

static int get_config_files (struct rrr_map *target, struct cmd_data *cmd) {
	int ret = 0;

	const char *config_string;
	cmd_arg_count config_i = 0;
	while ((config_string = cmd_get_value(cmd, "config", config_i)) != NULL) {
		if (*config_string == '\0') {
			break;
		}

		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			RRR_MSG_0("getcwd() failed in while getting config files: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		if (chdir(config_string) == 0) {
			if (chdir(cwd) != 0) {
				RRR_MSG_0("Could not chdir() to original directory %s: %s\n", cwd, rrr_strerror(errno));
				ret = 1;
				goto out;
			}
			if ((ret = rrr_readdir_foreach (
					config_string,
					get_config_files_callback,
					target
			)) != 0) {
				RRR_MSG_0("Error while reading configuration files in directory %s\n", config_string);
				goto out;
			}
		}
		else if (errno == ENOTDIR) {
			// OK (for now), not a directory
			if (get_config_files_test_open(config_string) != 0) {
				goto out_print_errno;
			}
			if ((ret = rrr_map_item_add_new(target, config_string, "")) != 0) {
				RRR_MSG_0("Could not add configuration file to map\n");
				goto out;
			}
		}
		else {
			goto out_print_errno;
		}

		config_i++;
	}

	goto out;
	out_print_errno:
		RRR_MSG_0("Error while accessing configuration file or directory %s: %s\n",
				config_string, rrr_strerror(errno));
		ret = 1;
	out:
		return ret;
}

struct main_periodic_callback_data {
	struct rrr_fork_handler *fork_handler;
};

static int main_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct main_periodic_callback_data *callback_data = arg;

	if (!main_running) {
		return RRR_EVENT_EXIT;
	}

	rrr_fork_handle_sigchld_and_notify_if_needed(callback_data->fork_handler, 0);

	if (some_fork_has_stopped) {
		RRR_MSG_0("One or more forks has exited\n");
		return RRR_EVENT_EXIT;
	}

	if (main_mmap_periodic(NULL) != 0) {
		RRR_MSG_0("Error while posting mmap statistics in main\n");
		return RRR_EVENT_EXIT;
	}

	return RRR_EVENT_OK;
}

int main (int argc, const char *argv[], const char *env[]) {
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

	int is_child = 0;

	struct rrr_event_queue *queue = NULL;

	struct rrr_signal_handler *signal_handler_fork = NULL;
	struct rrr_signal_handler *signal_handler = NULL;

	struct rrr_fork_handler *fork_handler = NULL;

	struct rrr_fork_default_exit_notification_data exit_notification_data = {
			&some_fork_has_stopped
	};

	struct rrr_map config_file_map = {0};

	struct cmd_data cmd;

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_fork_handler_new (&fork_handler) != 0) {
		ret = EXIT_FAILURE;
		goto out_run_cleanup_methods;
	}

	// The fork signal handler must be first
	signal_handler_fork = rrr_signal_handler_push(rrr_fork_signal_handler, NULL);
	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);

	rrr_signal_default_signal_actions_register();

	// Everything which might print debug stuff must be called after this
	// as the global debuglevel is 0 up to now
	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out_cleanup_signal;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_signal;
	}
	else if (cmd_exists(&cmd, "install-directories", 0)) {
		dump_install_directories();
		goto out_cleanup_signal;
	}

	rrr_umask_onetime_set_global(RRR_GLOBAL_UMASK);

	if (get_config_files (&config_file_map, &cmd) != 0) {
		goto out_cleanup_signal;
	}

	if (RRR_MAP_COUNT(&config_file_map) == 0) {
		RRR_MSG_0("No configuration files were found\n");
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	RRR_DBG_1("RRR debuglevel is: %u\n", RRR_DEBUGLEVEL);

	// Load configuration and fork
	int config_i = 0;
	RRR_MAP_ITERATE_BEGIN(&config_file_map);
	 	 // We fork one child for every specified config file

		if (config_i > 0 && rrr_config_global.start_interval > 0) {
			RRR_DBG_1("Delaying next fork by %lu milliseconds per arguments.\n",
				(long unsigned int) rrr_config_global.start_interval);

			const size_t delay_us = (unsigned long int) rrr_config_global.start_interval / 10 * 1000;
			for (int i = 0; i < 10; i++) {
				if (rrr_posix_usleep(delay_us) != 0) {
					RRR_DBG_1("Delayed startup aborted\n");
					RRR_LL_ITERATE_LAST();
					main_running = 0;
				}
			}
		}

		const char *config_string = node->tag;

		// This message is to force creation of a common log fd prior to
		// forking for log libraries requiring this (like SystemD journald)
		if (RRR_DEBUGLEVEL_1 || rrr_config_global.do_journald_output) {
			RRR_MSG_1("RRR starting configuration <%s>\n", config_string);
		}

		pid_t pid = rrr_fork (
				fork_handler,
				rrr_fork_default_exit_notification,
				&exit_notification_data
		);
		if (pid < 0) {
			RRR_MSG_0("Could not fork child process in main(): %s\n", rrr_strerror(errno));
			ret = EXIT_FAILURE;
			goto out_cleanup_signal;
		}
		else if (pid > 0) {
			goto increment;
		}

		// CHILD CODE
		is_child = 1;

		if (main_loop (
				&cmd,
				config_string,
				fork_handler
		) != 0) {
			ret = EXIT_FAILURE;
		}

		if (is_child) {
			goto out_cleanup_signal;
		}

		increment:
		config_i++;
	RRR_MAP_ITERATE_END();

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	// Create queue after forking to prevent it and it's FDs from existing in the forks
	if (rrr_event_queue_new(&queue) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	struct main_periodic_callback_data callback_data = {
		fork_handler
	};

	rrr_event_dispatch (
			queue,
			250 * 1000, // 250 ms
			main_periodic,
			&callback_data
	);

	out_cleanup_signal:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

		if (queue != NULL) {
			rrr_event_queue_destroy(queue);
		}

		rrr_signal_handler_remove(signal_handler);
		rrr_signal_handler_remove(signal_handler_fork);

		if (is_child) {
			// Child forks must skip *ALL* the fork-cleanup stuff. It's possible that a
			// child which regularly calls rrr_fork_handle_sigchld_and_notify_if_needed
			// will hande a SIGCHLD before we send signals to all forks, in which case
			// it will clean up properly anyway.
			goto out_run_cleanup_methods;
		}

		rrr_fork_send_sigusr1_and_wait(fork_handler);
		rrr_fork_handle_sigchld_and_notify_if_needed(fork_handler, 1);
		rrr_fork_handler_destroy (fork_handler);

	out_run_cleanup_methods:
		rrr_exit_cleanup_methods_run_and_free();
		rrr_socket_close_all();
		if (ret == EXIT_SUCCESS) {
			RRR_MSG_1("Exiting program without errors\n");
		}
		else {
			RRR_MSG_ERR("Exiting program following one or more errors\n");
		}
		cmd_destroy(&cmd);
		rrr_map_clear(&config_file_map);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
		rrr_shm_holders_cleanup();
	out_final:
		return ret;
}
