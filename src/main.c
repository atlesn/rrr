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

#include "global.h"

#include "main.h"
#include "lib/common.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/threads.h"

int main_start_threads (
		struct rrr_thread_collection **thread_collection,
		struct instance_metadata_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd
) {
	/*
#ifdef VL_WITH_OPENSSL
	vl_crypt_initialize_locks();
#endif
*/

	int ret = 0;

	// Initialize dynamic_data thread data
	RRR_INSTANCE_LOOP(instance,instances) {
		if (instance->dynamic_data == NULL) {
			break;
		}

		struct instance_thread_init_data init_data;
		init_data.module = instance->dynamic_data;
		init_data.senders = &instance->senders;
		init_data.cmd_data = cmd;
		init_data.global_config = global_config;
		init_data.instance_config = instance->config;

		RRR_DBG_1("Initializing instance %p '%s'\n", instance, instance->config->name);

		if ((instance->thread_data = rrr_instance_init_thread(&init_data)) == NULL) {
			goto out;
		}
	}

	// Create thread collection
	if (rrr_thread_new_collection (thread_collection) != 0) {
		RRR_MSG_ERR("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	// Preload threads. Signals must be disabled as the modules might write to
	// the signal handler linked list

	instances->signal_functions->set_active(RRR_SIGNALS_NOT_ACTIVE);
	RRR_INSTANCE_LOOP(instance,instances) {
		if (instance->dynamic_data == NULL) {
			break;
		}

		if (rrr_instance_preload_thread(*thread_collection, instance->thread_data) != 0) {
			RRR_BUG("Error while preloading thread for instance %s, can't proceed\n",
					instance->dynamic_data->instance_name);
		}
	}
	instances->signal_functions->set_active(RRR_SIGNALS_ACTIVE);

	int threads_total = 0;
	RRR_INSTANCE_LOOP(instance,instances) {
		if (rrr_instance_start_thread (instance->thread_data) != 0) {
			RRR_BUG("Error while starting thread for instance %s, can't proceed\n",
					instance->dynamic_data->instance_name);
		}

		threads_total++;
	}

	if (threads_total == 0) {
		RRR_MSG_ERR("No instances started, exiting\n");
		return EXIT_FAILURE;
	}

	if (rrr_thread_start_all_after_initialized(*thread_collection) != 0) {
		RRR_MSG_ERR("Error while waiting for threads to initialize\n");
		return EXIT_FAILURE;
	}

	out:
	return ret;
}

// The thread framework calls us back to here if a thread is marked as ghost.
// Make sure we do not free the memory the thread uses.
void main_ghost_handler (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	thread_data->used_by_ghost = 1;
	thread->free_private_data_by_ghost = 1;
}

void main_threads_stop (struct rrr_thread_collection *collection, struct instance_metadata_collection *instances) {
	rrr_threads_stop_and_join(collection, main_ghost_handler);
	rrr_instance_free_all_thread_data(instances);
/*
#ifdef VL_WITH_OPENSSL
	vl_crypt_free_locks();
#endif
*/
}

int main_parse_cmd_arguments(struct cmd_data *cmd, cmd_conf config) {
	if (cmd_parse(cmd, config) != 0) {
		RRR_MSG_ERR("Error while parsing command line\n");
		return EXIT_FAILURE;
	}

	unsigned int debuglevel = 0;
	unsigned int debuglevel_on_exit = 0;
	int no_watchdog_timers = 0;
	int no_thread_restart = 0;

	const char *debuglevel_string = cmd_get_value(cmd, "debuglevel", 0);
	if (debuglevel_string != NULL) {
		int debuglevel_tmp;
		if (strcmp(debuglevel_string, "all") == 0) {
			debuglevel_tmp = __RRR_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_string, &debuglevel_tmp) != 0) {
			RRR_MSG_ERR(
					"Could not understand debuglevel argument '%s', use a number or 'all'\n",
					debuglevel_string);
			return EXIT_FAILURE;
		}
		if (debuglevel_tmp < 0 || debuglevel_tmp > __RRR_DEBUGLEVEL_ALL) {
			RRR_MSG_ERR(
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
			RRR_MSG_ERR(
					"Could not understand debuglevel_on_exit argument '%s', use a number or 'all'\n",
					debuglevel_on_exit_string);
			return EXIT_FAILURE;
		}
		if (debuglevel_on_exit_tmp < 0 || debuglevel_on_exit_tmp > __RRR_DEBUGLEVEL_ALL) {
			RRR_MSG_ERR(
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

	rrr_init_global_config(debuglevel, debuglevel_on_exit, no_watchdog_timers, no_thread_restart);

	return 0;
}
