/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include "main.h"
#include "lib/rrr_config.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/event/event.h"
#include "lib/common.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/version.h"
#include "lib/configuration.h"
#include "lib/threads.h"
#include "lib/version.h"
#include "lib/socket/rrr_socket.h"
#include "lib/stats/stats_engine.h"
#include "lib/stats/stats_message.h"
#include "lib/rrr_strerror.h"
#include "lib/message_broker.h"
#include "lib/map.h"
#include "lib/fork.h"
#include "lib/rrr_umask.h"
#include "lib/allocator.h"
#include "lib/rrr_mmap_stats.h"
#include "lib/util/rrr_readdir.h"

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
		{0,                            's',    "stats",                 "[-s|--stats]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,    'r',    "run-directory",         "[-r|--run-directory[=]RUN DIRECTORY]"},
		{0,                            'l',    "loglevel-translation",  "[-l|--loglevel-translation]"},
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
			strlen(text) + 1
	) != 0) {
		RRR_BUG("Could not initialize main statistics message\n");
	}

	if (rrr_stats_engine_post_message(&stats_data->engine, stats_data->handle, "main", &message) != 0) {
		RRR_MSG_0("Could not post main statistics message\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
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
			strlen(text) + 1
	) != 0) {
		RRR_BUG("Could not initialize main statistics message\n");
	}

	if (rrr_stats_engine_post_message(&stats_data->engine, stats_data->handle, "main", &message) != 0) {
		RRR_MSG_0("Could not post main statistics message\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int main_stats_post_sticky_messages (struct stats_data *stats_data, struct rrr_instance_collection *instances) {
	int ret = 0;
	if (rrr_stats_engine_handle_obtain(&stats_data->handle, &stats_data->engine) != 0) {
		RRR_MSG_0("Error while obtaining statistics handle in main\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	char msg_text[RRR_STATS_MESSAGE_DATA_MAX_SIZE + 1];

	if (snprintf (
			msg_text,
			RRR_STATS_MESSAGE_DATA_MAX_SIZE,
			"RRR running with %u instances",
			rrr_instance_collection_count(instances)
	) >= RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		RRR_BUG("Statistics message too long in main\n");
	}

	if (main_stats_post_text_message(stats_data, "status", msg_text, RRR_STATS_MESSAGE_FLAGS_STICKY) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	unsigned int i = 0;
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;
		char path[128];
		sprintf(path, "instance_metadata/%u", i);

		if (main_stats_post_text_message(stats_data, path, instance->module_data->instance_name, RRR_STATS_MESSAGE_FLAGS_STICKY) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}

		sprintf(path, "instance_metadata/%u/module", i);
		if (main_stats_post_text_message(stats_data, path, instance->module_data->module_name, RRR_STATS_MESSAGE_FLAGS_STICKY) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}

		unsigned int j = 0;
		RRR_LL_ITERATE_BEGIN(&instance->senders, struct rrr_instance_friend);
			sprintf(path, "instance_metadata/%u/senders/%u", i, j);
			if (main_stats_post_text_message(stats_data, path, node->instance->module_data->instance_name, RRR_STATS_MESSAGE_FLAGS_STICKY) != 0) {
				ret = EXIT_FAILURE;
				goto out;
			}
			j++;
		RRR_LL_ITERATE_END();

		i++;
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

struct main_loop_event_callback_data {
	struct rrr_thread_collection **collection;
	struct rrr_instance_collection *instances;
	struct rrr_config *config;
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

static int main_loop_threads_restart (
	struct main_loop_event_callback_data *callback_data
) {
	int ret = 0;

	main_loop_close_sockets_except (callback_data->stats_data->engine.socket, callback_data->queue);

	if ((ret = rrr_main_create_and_start_threads (
			callback_data->collection,
			callback_data->instances,
			callback_data->config,
			callback_data->cmd,
			&callback_data->stats_data->engine,
			callback_data->message_broker,
			callback_data->fork_handler
	)) != 0) {
		goto out;
	}

	// This is messy. Handle gets registered inside of main_stats_post_sticky_messages
	// and then gets unregistered here.
	if (callback_data->stats_data->handle != 0) {
		rrr_stats_engine_handle_unregister(&callback_data->stats_data->engine, callback_data->stats_data->handle);
		callback_data->stats_data->handle = 0;
	}

	if (callback_data->stats_data->engine.initialized != 0) {
		if (main_stats_post_sticky_messages(callback_data->stats_data, callback_data->instances) != 0) {
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
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

	return 0;
}

static int main_loop_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	if (!main_running) {
		return RRR_EVENT_EXIT;
	}

	struct main_loop_event_callback_data *callback_data = arg;

	rrr_config_set_debuglevel_orig();

	if (*(callback_data->collection) == NULL) {
		if (main_loop_threads_restart (callback_data) != 0) {
			return RRR_EVENT_EXIT;
		}
	}

	rrr_fork_handle_sigchld_and_notify_if_needed(callback_data->fork_handler, 0);

	if (rrr_instance_check_threads_stopped(callback_data->instances) == 1) {
		RRR_DBG_1 ("One or more threads have finished for configuration %s\n", callback_data->config_file);

		rrr_config_set_debuglevel_on_exit();
		rrr_main_threads_stop_and_destroy(*(callback_data->collection));
		*(callback_data->collection) = NULL;

		// Allow re-use of costumer names. Any ghosts currently using a handle will be detected
		// as the handle usercount will be > 1. This handle will not be destroyed untill the
		// ghost breaks out of it's hanged state. It's nevertheless not possible for anyone else
		// to find the handle as it will be removed from the costumer handle list.
		rrr_message_broker_unregister_all(callback_data->message_broker);

		if (main_running && rrr_config_global.no_thread_restart == 0) {
			rrr_posix_usleep(1000000); // 1s
		}
		else {
			return RRR_EVENT_EXIT;
		}
	}

	int count;
	rrr_thread_cleanup_postponed_run(&count);
	if (count > 0) {
		RRR_MSG_0("Main cleaned up after %i ghost(s) (in loop) in configuration %s\n", count, callback_data->config_file);
	}

	return main_mmap_periodic(callback_data->stats_data);
}

// We have one loop per fork and one fork per configuration file
// Parent fork only monitors child forks
static int main_loop (
		struct cmd_data *cmd,
		const char *config_file,
		struct rrr_fork_handler *fork_handler
) {
	int ret = EXIT_SUCCESS;

	struct stats_data stats_data = {0};
	struct rrr_message_broker *message_broker = NULL;
	struct rrr_event_queue *queue = NULL;

	struct rrr_config *config = NULL;
	struct rrr_instance_collection instances = {0};
	struct rrr_thread_collection *collection = NULL;

	rrr_config_set_log_prefix(config_file);

	if (rrr_event_queue_new(&queue) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_config_parse_file(&config, config_file) != 0) {
		RRR_MSG_0("Configuration file parsing failed for %s\n", config_file);
		ret = EXIT_FAILURE;
		goto out_destroy_events;
	}

	RRR_DBG_1("RRR found %d instances in configuration file '%s'\n",
			config->module_count, config_file);

	if (RRR_DEBUGLEVEL_1) {
		if (config != NULL && rrr_config_dump(config) != 0) {
			ret = EXIT_FAILURE;
			RRR_MSG_0("Error occured while dumping configuration\n");
			goto out_destroy_config;
		}
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	if (rrr_instance_create_from_config(&instances, config, module_library_paths) != 0) {
		ret = EXIT_FAILURE;
		goto out_destroy_instance_metadata;
	}

	if (cmd_exists(cmd, "stats", 0)) {
		if (rrr_stats_engine_init(&stats_data.engine, queue) != 0) {
			RRR_MSG_0("Could not initialize statistics engine\n");
			ret = EXIT_FAILURE;
			goto out_destroy_instance_metadata;
		}
	}

	if (rrr_message_broker_new(&message_broker) != 0) {
		ret = EXIT_FAILURE;
		goto out_destroy_stats_engine;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	struct main_loop_event_callback_data event_callback_data = {
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
		rrr_main_threads_stop_and_destroy(collection);
	}

	if (stats_data.handle != 0) {
		rrr_stats_engine_handle_unregister(&stats_data.engine, stats_data.handle);
	}
	rrr_config_set_debuglevel_on_exit();
	RRR_DBG_1("Debuglevel on exit is: %i\n", rrr_config_global.debuglevel);
	int count;

	rrr_thread_cleanup_postponed_run(&count);
	if (count > 0) {
		RRR_MSG_0("Main cleaned up after %i ghost(s) (after loop)\n", count);
	}

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
		rrr_config_destroy(config);
	out_destroy_events:
		rrr_event_queue_destroy(queue);
	out:
		rrr_allocator_cleanup();
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
				return 1;
		}
		check_pos--;
		suffix_pos--;
	}

	return 0;
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

	if (get_config_files_suffix_ok(resolved_path) != 0) {
		RRR_DBG_1("Note: File '%s' found in a configuration directory did not have the correct suffix '%s', ignoring it.\n",
				resolved_path, RRR_CONFIG_FILE_SUFFIX);
		ret = 0;
		goto out;
	}

	if (get_config_files_test_open(resolved_path) != 0) {
		RRR_MSG_0("Configuration file '%s' could not be opened: %s\n", orig_path, rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_map_item_add_new(target, resolved_path, "")) != 0) {
		RRR_MSG_0("Could not add configuration file to list in get_config_files_callback\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int get_config_files (struct rrr_map *target, struct cmd_data *cmd) {
	int ret = 0;

	const char *config_string;
	int config_i = 0;
	while ((config_string = cmd_get_value(cmd, "config", config_i)) != NULL) {
		if (*config_string == '\0') {
			break;
		}

		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			RRR_MSG_0("getcwd() failed in get_config_files: %s\n", rrr_strerror(errno));
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
				ret = 1;
				goto out;
			}
		}
		else if (errno == ENOTDIR) {
			// OK (for now), not a directory
			if (get_config_files_test_open(config_string) != 0) {
				goto out_print_errno;
			}
			if ((ret = rrr_map_item_add_new(target, config_string, "")) != 0) {
				RRR_MSG_0("Could not add configuration file to list in get_config_files\n");
				ret = 1;
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

	return main_mmap_periodic(NULL);
}

int main (int argc, const char *argv[], const char *env[]) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	if (rrr_log_init() != 0) {
		goto out;
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
		ret = 1;
		goto out_cleanup_signal;
	}

	RRR_DBG_1("RRR debuglevel is: %u\n", RRR_DEBUGLEVEL);

	// Load configuration and fork
	int config_i = 0;
	RRR_MAP_ITERATE_BEGIN(&config_file_map);
	 	 // We fork one child for every specified config file

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
			ret = 1;
			goto out_cleanup_signal;
		}
		else if (pid > 0) {
			goto increment;
		}

		// CHILD CODE
		is_child = 1;

		ret = main_loop (
				&cmd,
				config_string,
				fork_handler
		);

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
		if (ret == 0) {
			RRR_MSG_1("Exiting program without errors\n");
		}
		else {
			RRR_MSG_ERR("Exiting program following one or more errors\n");
		}
		cmd_destroy(&cmd);
		rrr_map_clear(&config_file_map);
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out:
		rrr_allocator_cleanup();
		return ret;
}
