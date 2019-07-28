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
#include "lib/cmdlineparser/cmdline.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/threads.h"

#ifdef VL_WITH_OPENSSL
#include "lib/crypt.h"
#endif

static int signal_handlers_active = 0;
static struct rrr_signal_handler *first_handler = NULL;
pthread_mutex_t signal_lock = PTHREAD_MUTEX_INITIALIZER;

void rrr_signal_handler_set_active (int active) {
	pthread_mutex_lock(&signal_lock);
	signal_handlers_active = active;
	pthread_mutex_unlock(&signal_lock);
}

struct rrr_signal_handler *rrr_signal_handler_push(int (*handler)(int signal, void *private_arg), void *private_arg) {
	struct rrr_signal_handler *h = malloc(sizeof(*h));
	h->handler = handler;
	h->private_arg = private_arg;

	pthread_mutex_lock(&signal_lock);
	h->next = first_handler;
	first_handler = h;
	pthread_mutex_unlock(&signal_lock);
	return h;
}

void rrr_signal_handler_remove(struct rrr_signal_handler *handler) {
	pthread_mutex_lock(&signal_lock);
	int did_remove = 0;
	if (first_handler == handler) {
		first_handler = first_handler->next;
		free(handler);
		did_remove = 1;
	}
	else {
		struct rrr_signal_handler *test = first_handler;
		while (test) {
			if (test->next == handler) {
				test->next = test->next->next;
				free(handler);
				did_remove = 1;
				break;
			}
			test = test->next;
		}
	}
	if (did_remove != 1) {
		VL_BUG("Attempted to remove signal handler which did not exist\n");
	}
	pthread_mutex_unlock(&signal_lock);
}

void rrr_signal (int s) {
    VL_DEBUG_MSG_1("Received signal %i\n", s);

	struct rrr_signal_handler *test = first_handler;

	if (signal_handlers_active == 1) {
		int handler_res = 1;
		while (test) {
			printf ("-> calling handler\n");
			int ret = test->handler(s, test->private_arg);
			if (ret == 0) {
				// Handlers may also return non-zero for signal to continue
				handler_res = 0;
				break;
			}
			test = test->next;
		}

		if (handler_res == 0) {
			printf ("Signal processed by handler, stop\n");
			return;
		}
	}
}

int main_start_threads (
		struct vl_thread_collection **thread_collection,
		struct instance_metadata_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd
) {
#ifdef VL_WITH_OPENSSL
	vl_crypt_initialize_locks();
#endif

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

		VL_DEBUG_MSG_1("Initializing instance %p '%s'\n", instance, instance->config->name);

		if ((instance->thread_data = instance_init_thread(&init_data)) == NULL) {
			goto out;
		}
	}

	// Create thread collection
	if (thread_new_collection (thread_collection) != 0) {
		VL_MSG_ERR("Could not create thread collection\n");
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

		if (instance_preload_thread(*thread_collection, instance->thread_data) != 0) {
			VL_BUG("Error while preloading thread for instance %s, can't proceed\n",
					instance->dynamic_data->instance_name);
		}
	}
	instances->signal_functions->set_active(RRR_SIGNALS_ACTIVE);

	int threads_total = 0;
	RRR_INSTANCE_LOOP(instance,instances) {
		if (instance_start_thread (instance->thread_data) != 0) {
			VL_BUG("Error while starting thread for instance %s, can't proceed\n",
					instance->dynamic_data->instance_name);
		}

		threads_total++;
	}

	if (threads_total == 0) {
		VL_MSG_ERR("No instances started, exiting\n");
		return EXIT_FAILURE;
	}

	if (thread_start_all_after_initialized(*thread_collection) != 0) {
		VL_MSG_ERR("Error while waiting for threads to initialize\n");
		return EXIT_FAILURE;
	}

	out:
	return ret;
}

// The thread framework calls us back to here if a thread is marked as ghost.
// Make sure we do not free the memory the thread uses.
void main_ghost_handler (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	thread_data->used_by_ghost = 1;
	thread->free_private_data_by_ghost = 1;
}

void main_threads_stop (struct vl_thread_collection *collection, struct instance_metadata_collection *instances) {
	threads_stop_and_join(collection, main_ghost_handler);
	instance_free_all_thread_data(instances);

#ifdef VL_WITH_OPENSSL
	vl_crypt_free_locks();
#endif
}

int main_parse_cmd_arguments(struct cmd_data* cmd, int argc, const char* argv[]) {
	if (cmd_parse(cmd, argc, argv, CMD_CONFIG_NOCOMMAND | CMD_CONFIG_SPLIT_COMMA) != 0) {
		VL_MSG_ERR("Error while parsing command line\n");
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
			debuglevel = __VL_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_string, &debuglevel_tmp) != 0) {
			VL_MSG_ERR(
					"Could not understand debuglevel argument '%s', use a number or 'all'\n",
					debuglevel_string);
			return EXIT_FAILURE;
		}
		if (debuglevel_tmp < 0 || debuglevel_tmp > __VL_DEBUGLEVEL_ALL) {
			VL_MSG_ERR(
					"Debuglevel must be 0 <= debuglevel <= %i, %i was given.\n",
					__VL_DEBUGLEVEL_ALL, debuglevel_tmp);
			return EXIT_FAILURE;
		}
		debuglevel = debuglevel_tmp;
	}

	const char *debuglevel_on_exit_string = cmd_get_value(cmd, "debuglevel_on_exit", 0);
	if (debuglevel_on_exit_string != NULL) {
		int debuglevel_on_exit_tmp;
		if (strcmp(debuglevel_on_exit_string, "all") == 0) {
			debuglevel_on_exit = __VL_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_on_exit_string, &debuglevel_on_exit_tmp) != 0) {
			VL_MSG_ERR(
					"Could not understand debuglevel_on_exit argument '%s', use a number or 'all'\n",
					debuglevel_on_exit_string);
			return EXIT_FAILURE;
		}
		if (debuglevel_on_exit_tmp < 0 || debuglevel_on_exit_tmp > __VL_DEBUGLEVEL_ALL) {
			VL_MSG_ERR(
					"Debuglevel must be 0 <= debuglevel_on_exit <= %i, %i was given.\n",
					__VL_DEBUGLEVEL_ALL, debuglevel_on_exit_tmp);
			return EXIT_FAILURE;
		}
		debuglevel_on_exit = debuglevel_on_exit_tmp;
	}

	const char *no_watchdog_timers_string = cmd_get_value(cmd, "no_watchdog_timers", 0);
	if (no_watchdog_timers_string != NULL) {
		if (cmdline_check_yesno(no_watchdog_timers_string, &no_watchdog_timers) != 0) {
			VL_MSG_ERR("Could not understand argument no_watchdog_timer=%s, please specify 'yes' or 'no'\n",
					no_watchdog_timers_string);
			return EXIT_FAILURE;
		}
	}

	const char *no_thread_restart_string = cmd_get_value(cmd, "no_thread_restart", 0);
	if (no_thread_restart_string != NULL) {
		if (cmdline_check_yesno(no_thread_restart_string, &no_thread_restart) != 0) {
			VL_MSG_ERR("Could not understand argument no_thread_restart=%s, please specify 'yes' or 'no'\n",
					no_thread_restart_string);
			return EXIT_FAILURE;
		}
	}

	rrr_init_global_config(debuglevel, debuglevel_on_exit, no_watchdog_timers, no_thread_restart);

	return 0;
}
