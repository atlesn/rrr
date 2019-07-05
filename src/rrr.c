/*
#include <main.h>

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

#include "main.h"
#include "global.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/version.h"
#include "lib/configuration.h"
#include "lib/threads.h"
#include "lib/module_thread.h"
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

void signal_interrupt (int s) {
    main_running = 0;

    VL_DEBUG_MSG_1("Received signal %i\n", s);

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	struct instance_metadata_collection *instances;

	struct cmd_data cmd;
	struct rrr_config *config = NULL;

	int ret = EXIT_SUCCESS;

	if (instance_metadata_collection_new (&instances) != 0) {
		ret = EXIT_FAILURE;
		goto out_no_cleanup;
	}

	struct sigaction action;
	action.sa_handler = signal_interrupt;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGUSR1, &action, NULL);

	if ((ret = main_parse_cmd_arguments(&cmd, argc, argv)) != 0) {
		goto out_no_cleanup;
	}

	VL_DEBUG_MSG_1("voltagelogger debuglevel is: %u\n", VL_DEBUGLEVEL);

	const char* config_string = cmd_get_value(&cmd, "config", 0);
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
		if (rrr_config_dump(config) != 0) {
			VL_MSG_ERR("Error occured while dumping configuration\n");
		}
	}

	// Initialzie dynamic_data thread data
	struct vl_thread_collection *collection = NULL;

	threads_restart:
	if ((ret = main_start_threads(&collection, instances, config, &cmd)) != 0) {
		goto out_stop_threads;
	}

	while (main_running) {
		usleep (100000);

		if (rrr_global_config.no_thread_restart || instance_check_threads_stopped(instances) == 0) {
			VL_DEBUG_MSG_1 ("One or more threads have finished. Restart.\n");

			main_threads_stop(collection, instances);
			thread_destroy_collection (collection);

			if (main_running) {
				goto threads_restart;
			}
			else {
				goto out_unload_modules;
			}
		}
	}

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);

	VL_DEBUG_MSG_1 ("Main loop finished\n");

	out_stop_threads:
		main_threads_stop(collection, instances);
		thread_destroy_collection (collection);

	out_unload_modules:
#ifndef VL_NO_MODULE_UNLOAD
		instance_unload_all(instances);
#endif
		if (config != NULL) {
			rrr_config_destroy(config);
		}

	instance_metadata_collection_destroy(instances);

	out_no_cleanup:
	return ret;
}
