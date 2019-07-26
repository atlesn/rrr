/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "main.h"
#include "main_signals.h"
#include "global.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/version.h"
#include "lib/configuration.h"
#include "lib/threads.h"
#include "lib/version.h"

const char *module_library_paths[] = {
		VL_MODULE_PATH,
		"/usr/lib/rrr",
		"/lib/rrr",
		"/usr/local/lib/rrr",
		"/usr/lib/",
		"/lib/",
		"/usr/local/lib/",
		"./src/modules/.libs",
		"./src/modules",
		"./modules",
		"./",
		""
};

#ifndef VL_BUILD_TIMESTAMP
#define VL_BUILD_TIMESTAMP 1
#endif

// Used so that debugger output at program exit can show function names
// on the stack correctly
//#define VL_NO_MODULE_UNLOAD

static volatile int main_running = 1;

pthread_mutex_t signal_lock = PTHREAD_MUTEX_INITIALIZER;

struct rrr_signal_handler *first_handler = NULL;

struct rrr_signal_handler *rrr_signal_handler_push(int (*handler)(int signal, void *private_arg), void *private_arg) {
	pthread_mutex_lock(&signal_lock);
	struct rrr_signal_handler *h = malloc(sizeof(*h));
	h->handler = handler;
	h->next = first_handler;
	h->private_arg = private_arg;
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

static struct rrr_signal_functions signal_functions = {
		rrr_signal_handler_push,
		rrr_signal_handler_remove
};

void signal_interrupt (int s) {
    VL_DEBUG_MSG_1("Received signal %i\n", s);

	struct rrr_signal_handler *test = first_handler;

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

	if (s == SIGCHLD) {
		printf ("Received SIGCHLD\n");
	}
	else if (s == SIGUSR1) {
        main_running = 0;
    }
    else if (s == SIGPIPE) {
        VL_MSG_ERR("Received SIGPIPE, ignoring\n");
    }
    else if (s == SIGTERM) {
    	exit(EXIT_FAILURE);
    }
    else {
        main_running = 0;
    }

    // Allow double ctrl+c to close program
	if (s == SIGINT) {
		signal(SIGINT, SIG_DFL);
	}
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	struct vl_thread_collection *collection = NULL;
	struct instance_metadata_collection *instances;
	const char* config_string;
	struct cmd_data cmd;
	struct rrr_config *config = NULL;
	int ret = EXIT_SUCCESS;
	int count = 0;

	if (instance_metadata_collection_new (&instances, &signal_functions) != 0) {
		ret = EXIT_FAILURE;
		goto out_no_cleanup;
	}

	if ((ret = main_parse_cmd_arguments(&cmd, argc, argv)) != 0) {
		goto out_no_cleanup;
	}

	VL_DEBUG_MSG_1("voltagelogger debuglevel is: %u\n", VL_DEBUGLEVEL);

	config_string = cmd_get_value(&cmd, "config", 0);
	if (config_string != NULL) {
		config = rrr_config_parse_file(config_string);

		if (config == NULL) {
			ret = EXIT_FAILURE;
			VL_MSG_ERR("Configuration file parsing failed\n");
			goto out_unload_modules;
		}

		VL_DEBUG_MSG_1("found %d instances\n", config->module_count);

		ret = instance_process_from_config(instances, config, module_library_paths);

		if (ret != 0) {
			goto out_unload_modules;
		}
	}

	if (VL_DEBUGLEVEL_1) {
		if (config != NULL && rrr_config_dump(config) != 0) {
			VL_MSG_ERR("Error occured while dumping configuration\n");
		}
	}

	// Initialzie dynamic_data thread data
	struct sigaction action;
	action.sa_handler = signal_interrupt;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	threads_restart:

	sigaction (SIGCHLD, &action, NULL);

	rrr_set_debuglevel_orig();
	if ((ret = main_start_threads(&collection, instances, config, &cmd)) != 0) {
		goto out_stop_threads;
	}

	sigaction (SIGINT, &action, NULL);
	sigaction (SIGUSR1, &action, NULL);
	sigaction (SIGPIPE, &action, NULL);

	while (main_running) {
		usleep (100000);

		if (instance_check_threads_stopped(instances) == 1) {
			VL_DEBUG_MSG_1 ("One or more threads have finished or do hard restart. Restart.\n");

			rrr_set_debuglevel_on_exit();
			main_threads_stop(collection, instances);
			thread_destroy_collection (collection);

			if (main_running && rrr_global_config.no_thread_restart == 0) {
				usleep(1000000);
				goto threads_restart;
			}
			else {
				goto out_unload_modules;
			}
		}

		thread_run_ghost_cleanup(&count);
		if (count > 0) {
			VL_MSG_ERR("Main cleaned up after %i ghost(s) (in loop)\n", count);
		}
	}

	VL_DEBUG_MSG_1 ("Main loop finished\n");

	out_stop_threads:
		rrr_set_debuglevel_on_exit();
		VL_DEBUG_MSG_1("Debuglevel on exit is: %i\n", rrr_global_config.debuglevel);
		main_threads_stop(collection, instances);
		thread_destroy_collection (collection);
		thread_run_ghost_cleanup(&count);
		if (count > 0) {
			VL_MSG_ERR("Main cleaned up after %i ghost(s) (after loop)\n", count);
		}

	out_unload_modules:
#ifndef VL_NO_MODULE_UNLOAD
		instance_unload_all(instances);
#endif
		if (config != NULL) {
			rrr_config_destroy(config);
		}

		instance_metadata_collection_destroy(instances);

	out_no_cleanup:
		if (ret == 0) {
			VL_DEBUG_MSG_1("Exiting program without errors\n");
		}
		else {
			VL_DEBUG_MSG_1("Exiting program with errors\n");
		}
		return ret;
}
