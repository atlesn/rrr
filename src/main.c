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

#define RRR_MAIN_DEFAULT_MESSAGE_TTL_S 30
#define RRR_MAIN_DEFAULT_THREAD_WATCHDOG_TIMER_MS 5000

struct rrr_main_check_wait_for_data {
	struct rrr_instance_collection *instances;
};

static int __rrr_main_start_threads_check_wait_for_callback (int *do_start, struct rrr_thread *thread, void *arg) {
	struct rrr_main_check_wait_for_data *data = arg;
	struct rrr_instance *instance = rrr_instance_find_by_thread(data->instances, thread);

	if (instance == NULL) {
		RRR_BUG("Instance not found in __main_start_threads_check_wait_for_callback\n");
	}

	*do_start = 1;

	// TODO : Check for wait_for loops in configuration

	RRR_LL_ITERATE_BEGIN(&instance->wait_for, struct rrr_instance_friend);
		struct rrr_instance *check = node->instance;
		if (check == instance) {
			RRR_MSG_0("Instance %s was set up to wait for itself before starting with wait_for, this is an error.\n",
					INSTANCE_M_NAME(instance));
			return 1;
		}

		if (	rrr_thread_get_state(check->thread) == RRR_THREAD_STATE_RUNNING ||
				rrr_thread_get_state(check->thread) == RRR_THREAD_STATE_RUNNING_FORKED ||
				rrr_thread_get_state(check->thread) == RRR_THREAD_STATE_STOPPED
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

// This function allocates runtime data and thread data.
// - runtime data is ALWAYS destroyed by the thread. If a thread does not
//   start, we must BUG() out
// - thread data is freed by main unless thread has become ghost in which the
//   thread will free it if it wakes up

int rrr_main_create_and_start_threads (
		struct rrr_thread_collection **thread_collection,
		struct rrr_instance_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
) {
	int ret = 0;

	struct rrr_instance_runtime_data **runtime_data = NULL;

	// Preload threads. Signals must be disabled as the modules might write to
	// the signal handler linked list

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

	if (RRR_LL_COUNT(instances) == 0) {
		RRR_MSG_0("No instances started, exiting\n");
		ret = 1;
		goto out;
	}

	runtime_data = malloc(sizeof(*runtime_data) * RRR_LL_COUNT(instances)); // Size of pointer

	// Create thread collection
	if (rrr_thread_new_collection (thread_collection) != 0) {
		RRR_MSG_0("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	// Initialize thread data and runtime data
	int threads_total = 0;
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;

		if (instance->module_data == NULL) {
			RRR_BUG("BUG: Dynamic data was NULL in rrr_main_create_and_start_threads\n");
		}

		struct rrr_instance_runtime_init_data init_data;
		init_data.module = instance->module_data;
		init_data.senders = &instance->senders;
		init_data.cmd_data = cmd;
		init_data.global_config = global_config;
		init_data.instance_config = instance->config;
		init_data.stats = stats;
		init_data.message_broker = message_broker;
		init_data.fork_handler = fork_handler;
		init_data.topic_first_token = instance->topic_first_token;
		init_data.topic_str = instance->topic_filter;
		init_data.instance = instance;

		RRR_DBG_1("Initializing instance %p '%s'\n", instance, instance->config->name);

		if ((runtime_data[threads_total] = rrr_instance_runtime_data_new(&init_data)) == NULL) {
			RRR_BUG("Error while creating runtime data for instance %s, can't proceed\n",
					INSTANCE_M_NAME(instance));
		}

		struct rrr_thread *thread = rrr_thread_allocate_preload_and_register (
				*thread_collection,
				rrr_instance_thread_entry_intermediate,
				instance->module_data->operations.preload,
				instance->module_data->operations.poststop,
				instance->module_data->operations.cancel_function,
				instance->module_data->start_priority,
				instance->module_data->instance_name,
				RRR_MAIN_DEFAULT_THREAD_WATCHDOG_TIMER_MS * 1000,
				runtime_data[threads_total]
		);

		if (thread == NULL) {
			// This might actually not be a bug but we cannot recover from preload failure
			RRR_BUG("Error while preloading thread for instance %s, can't proceed\n",
					instance->module_data->instance_name);
		}

		// Set shortcuts
		node->thread = thread;

		threads_total++;
	RRR_LL_ITERATE_END();

	for (int i = 0; i < threads_total; i++) {
		RRR_DBG_1 ("Starting thread %s\n", INSTANCE_M_NAME(runtime_data[i]->init_data.instance));
		if (rrr_thread_start(INSTANCE_M_THREAD(runtime_data[i]->init_data.instance)) != 0) {
			RRR_BUG ("Error while starting thread for instance %s, can't proceed\n",
					INSTANCE_M_NAME(runtime_data[i]->init_data.instance));
		}
	}

	struct rrr_main_check_wait_for_data callback_data = { instances };

	if (rrr_thread_start_all_after_initialized (
			*thread_collection,
			__rrr_main_start_threads_check_wait_for_callback,
			&callback_data
	) != 0) {
		RRR_MSG_0("Error while waiting for threads to initialize\n");
		ret = 1;
		goto out;
	}

	out:
	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);
	RRR_FREE_IF_NOT_NULL(runtime_data);
	return ret;
}

void rrr_main_threads_stop_and_destroy (struct rrr_thread_collection *collection) {
	rrr_thread_stop_and_join_all_no_unlock(collection);
	rrr_thread_destroy_collection (collection);
}

int rrr_main_parse_cmd_arguments(struct cmd_data *cmd, cmd_conf config) {
	if (cmd_parse(cmd, config) != 0) {
		RRR_MSG_0("Error while parsing command line\n");
		return EXIT_FAILURE;
	}

	unsigned int no_watchdog_timers = 0;
	unsigned int no_thread_restart = 0;
	unsigned int rfc5424_loglevel_output = 0;
	uint64_t message_ttl_us = RRR_MAIN_DEFAULT_MESSAGE_TTL_S * 1000 * 1000;
	unsigned int debuglevel = 0;
	unsigned int debuglevel_on_exit = 0;

	const char *message_ttl_s_string = cmd_get_value(cmd, "time-to-live", 0);
	if (message_ttl_s_string != NULL) {
		if (cmd_convert_uint64_10(message_ttl_s_string, &message_ttl_us) != 0) {
			RRR_MSG_0(
					"Could not understand time-to-live argument '%s', use a number\n",
					message_ttl_s_string);
			return EXIT_FAILURE;
		}

		// Make sure things does not get outahand during multiplication. Input from user
		// is in seconds, convert to microseconds
		if (message_ttl_us > UINT32_MAX) {
			RRR_MSG_0("Value of time-to-live was too big, maximum is %lu\n", UINT32_MAX);
			return EXIT_FAILURE;
		}

		message_ttl_us *= 1000 * 1000;
	}

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

	if (cmd_exists(cmd, "no_watchdog_timers", 0)) {
		no_watchdog_timers = 1;
	}

	if (cmd_exists(cmd, "no_thread_restart", 0)) {
		no_thread_restart = 1;
	}

	if (cmd_exists(cmd, "loglevel-translation", 0)) {
		rfc5424_loglevel_output = 1;
	}

	if (cmd_exists(cmd, "loglevel-translation", 0)) {
		rfc5424_loglevel_output = 1;
	}

	rrr_config_init (
			debuglevel,
			debuglevel_on_exit,
			no_watchdog_timers,
			no_thread_restart,
			rfc5424_loglevel_output,
			message_ttl_us
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
