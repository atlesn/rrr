/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#include "main.h"
#include "lib/log.h"
#include "lib/common.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/threads.h"

struct rrr_main_check_wait_for_data {
	struct rrr_instance_metadata_collection *instances;
};

static int __rrr_main_start_threads_check_wait_for_callback (int *do_start, struct rrr_thread *thread, void *arg) {
	struct rrr_main_check_wait_for_data *data = arg;
	struct rrr_instance_metadata *instance = rrr_instance_find_by_thread(data->instances, thread);

	if (instance == NULL) {
		RRR_BUG("Instance not found in __main_start_threads_check_wait_for_callback\n");
	}

	*do_start = 1;

	// TODO : Check for wait loops

	RRR_LL_ITERATE_BEGIN(&instance->wait_for, struct rrr_instance_collection_entry);
		struct rrr_instance_metadata *check = node->instance;
		if (check == instance) {
			RRR_MSG_0("Instance %s was set up to wait for itself before starting with wait_for, this is an error.\n",
					INSTANCE_M_NAME(instance));
			return 1;
		}

		if (	rrr_thread_get_state(check->thread_data->thread) == RRR_THREAD_STATE_RUNNING ||
				rrr_thread_get_state(check->thread_data->thread) == RRR_THREAD_STATE_RUNNING_FORKED ||
				rrr_thread_get_state(check->thread_data->thread) == RRR_THREAD_STATE_STOPPED
		) {
			// OK
		}
		else {
			RRR_DBG_1 ("Instance %s waiting for instance %s to start\n",
					INSTANCE_M_NAME(instance), INSTANCE_M_NAME(check));
			*do_start = 0;
		}
	RRR_LL_ITERATE_END();

	return 0;
}

int rrr_main_start_threads (
		struct rrr_thread_collection **thread_collection,
		struct rrr_instance_metadata_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
) {
	int ret = 0;

	// Initialize dynamic_data thread data
	RRR_INSTANCE_LOOP(instance,instances) {
		if (instance->dynamic_data == NULL) {
			break;
		}

		struct rrr_instance_thread_init_data init_data;
		init_data.module = instance->dynamic_data;
		init_data.senders = &instance->senders;
		init_data.cmd_data = cmd;
		init_data.global_config = global_config;
		init_data.instance_config = instance->config;
		init_data.stats = stats;
		init_data.message_broker = message_broker;
		init_data.fork_handler = fork_handler;

		RRR_DBG_1("Initializing instance %p '%s'\n", instance, instance->config->name);

		if ((instance->thread_data = rrr_instance_new_thread(&init_data)) == NULL) {
			goto out;
		}
	}

	// Create thread collection
	if (rrr_thread_new_collection (thread_collection) != 0) {
		RRR_MSG_0("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	// Preload threads. Signals must be disabled as the modules might write to
	// the signal handler linked list

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	RRR_INSTANCE_LOOP(instance,instances) {
		if (instance->dynamic_data == NULL) {
			break;
		}

		if (rrr_instance_preload_thread(*thread_collection, instance->thread_data) != 0) {
			// This might actually not be a bug but we cannot recover from preload failure
			RRR_BUG("Error while preloading thread for instance %s, can't proceed\n",
					instance->dynamic_data->instance_name);
		}
	}
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	int threads_total = 0;
	RRR_INSTANCE_LOOP(instance,instances) {
		if (rrr_instance_start_thread (instance->thread_data) != 0) {
			RRR_BUG("Error while starting thread for instance %s, can't proceed\n",
					instance->dynamic_data->instance_name);
		}

		threads_total++;
	}

	if (threads_total == 0) {
		RRR_MSG_0("No instances started, exiting\n");
		return EXIT_FAILURE;
	}

	struct rrr_main_check_wait_for_data callback_data = { instances };

	if (rrr_thread_start_all_after_initialized (
			*thread_collection,
			__rrr_main_start_threads_check_wait_for_callback,
			&callback_data
	) != 0) {
		RRR_MSG_0("Error while waiting for threads to initialize\n");
		return EXIT_FAILURE;
	}

	out:
	return ret;
}

// The thread framework calls us back to here if a thread is marked as ghost.
// Make sure we do not free the memory the thread uses.
void rrr_main_ghost_handler (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	thread_data->used_by_ghost = 1;
	thread->free_private_data_by_ghost = 1;
}

void rrr_main_threads_stop (struct rrr_thread_collection *collection, struct rrr_instance_metadata_collection *instances) {
	rrr_thread_stop_and_join_all(collection, rrr_main_ghost_handler);
	rrr_instance_free_all_thread_data(instances);
}

int rrr_main_parse_cmd_arguments(struct cmd_data *cmd, cmd_conf config) {
	if (cmd_parse(cmd, config) != 0) {
		RRR_MSG_0("Error while parsing command line\n");
		return EXIT_FAILURE;
	}

	unsigned int debuglevel = 0;
	unsigned int debuglevel_on_exit = 0;

	const char *debuglevel_string = cmd_get_value(cmd, "debuglevel", 0);
	if (debuglevel_string != NULL) {
		int debuglevel_tmp;
		if (strcmp(debuglevel_string, "all") == 0) {
			debuglevel_tmp = __RRR_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_string, &debuglevel_tmp) != 0) {
			RRR_MSG_0(
					"Could not understand debuglevel argument '%s', use a number or 'all'\n",
					debuglevel_string);
			return EXIT_FAILURE;
		}
		if (debuglevel_tmp < 0 || debuglevel_tmp > __RRR_DEBUGLEVEL_ALL) {
			RRR_MSG_0(
					"Debuglevel must be 0 <= debuglevel <= %i, %i was given.\n",
					__RRR_DEBUGLEVEL_ALL, debuglevel_tmp);
			return EXIT_FAILURE;
		}
		debuglevel = debuglevel_tmp;
	}

	const char *debuglevel_on_exit_string = cmd_get_value(cmd, "debuglevel_on_exit", 0);
	if (debuglevel_on_exit_string != NULL) {
		int debuglevel_on_exit_tmp;
		if (strcmp(debuglevel_on_exit_string, "all") == 0) {
			debuglevel_on_exit_tmp = __RRR_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_on_exit_string, &debuglevel_on_exit_tmp) != 0) {
			RRR_MSG_0(
					"Could not understand debuglevel_on_exit argument '%s', use a number or 'all'\n",
					debuglevel_on_exit_string);
			return EXIT_FAILURE;
		}
		if (debuglevel_on_exit_tmp < 0 || debuglevel_on_exit_tmp > __RRR_DEBUGLEVEL_ALL) {
			RRR_MSG_0(
					"Debuglevel must be 0 <= debuglevel_on_exit <= %i, %i was given.\n",
					__RRR_DEBUGLEVEL_ALL, debuglevel_on_exit_tmp);
			return EXIT_FAILURE;
		}
		debuglevel_on_exit = debuglevel_on_exit_tmp;
	}

	unsigned int no_watchdog_timers = 0;
	unsigned int no_thread_restart = 0;
	unsigned int rfc5424_loglevel_output = 0;

	if (cmd_exists(cmd, "no_watchdog_timers", 0)) {
		no_watchdog_timers = 1;
	}

	if (cmd_exists(cmd, "no_thread_restart", 0)) {
		no_thread_restart = 1;
	}

	if (cmd_exists(cmd, "loglevel-translation", 0)) {
		rfc5424_loglevel_output = 1;
	}

	rrr_config_init (
			debuglevel,
			debuglevel_on_exit,
			no_watchdog_timers,
			no_thread_restart,
			rfc5424_loglevel_output
	);

	return 0;
}

int rrr_main_print_help_and_version (
		struct cmd_data *cmd,
		int argc_minimum
) {
	int help_or_version_printed = 0;
	if (cmd_exists(cmd, "version", 0)) {
		RRR_MSG_0(PACKAGE_NAME " version " RRR_CONFIG_VERSION " build timestamp %li\n", RRR_BUILD_TIMESTAMP);
		help_or_version_printed = 1;
	}

	if ((cmd->argc < argc_minimum || strcmp(cmd->command, "help") == 0) || cmd_exists(cmd, "help", 0)) {
		cmd_print_usage(cmd);
		help_or_version_printed = 1;
	}

	if (help_or_version_printed) {
		return 1;
	}

	return 0;
}
