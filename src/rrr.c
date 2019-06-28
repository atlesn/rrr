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

#include "global.h"
#include "instances.h"
#include "lib/instance_config.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/version.h"
#include "lib/configuration.h"

// Used so that debugger output at program exit can show function names
// on the stack correctly
//#define VL_NO_MODULE_UNLOAD

/* TODO : Replace with a struct which holds the array + make non-global + rename to instance_metadata */
static struct module_metadata instances[CMD_ARGUMENT_MAX];

int main_process_instances(struct rrr_config *config) {
	int ret = 0;

	for (int i = 0; i < config->module_count; i++) {
		ret = instance_load(instances, config, config->configs[i]);
		if (ret != 0) {
			VL_MSG_ERR("Loading of instance failed for %s\n", config->configs[i]->name);
			break;
		}
	}

	for (int i = 0; i < config->module_count; i++) {
		ret = instance_add_senders(instances, config, config->configs[i], &instances[i]);
		if (ret != 0) {
			VL_MSG_ERR("Adding senders failed for %s\n", config->configs[i]->name);
			break;
		}
	}

	return ret;
}

int main_parse_cmd_arguments(int argc, const char* argv[], struct cmd_data* cmd) {
	if (cmd_parse(cmd, argc, argv, CMD_CONFIG_NOCOMMAND | CMD_CONFIG_SPLIT_COMMA) != 0) {
		VL_MSG_ERR("Error while parsing command line\n");
		return EXIT_FAILURE;
	}

	unsigned int debuglevel = 0;
	const char* debuglevel_string = cmd_get_value(&*cmd, "debuglevel", 0);
	if (debuglevel_string != NULL) {
		if (strcmp(debuglevel_string, "all") == 0) {
			debuglevel = __VL_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(cmd, debuglevel_string, &debuglevel) != 0) {
			VL_MSG_ERR(
					"Could not understand debuglevel argument '%s', use a number or 'all'\n",
					debuglevel_string);
			return EXIT_FAILURE;
		}
		if (debuglevel < 0 || debuglevel > __VL_DEBUGLEVEL_ALL) {
			VL_MSG_ERR(
					"Debuglevel must be 0 <= debuglevel <= %i, %i was given.\n",
					__VL_DEBUGLEVEL_ALL, debuglevel);
			return EXIT_FAILURE;
		}
	}

	vl_init_global_config(debuglevel);

	return 0;
}

int main_start_threads(
		struct module_metadata modules[CMD_ARGUMENT_MAX],
		struct cmd_data* cmd
) {
	// Initialzie dynamic_data thread data
	rrr_threads_init();

	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_metadata *meta = &modules[i];

		if (meta->dynamic_data == NULL) {
			break;
		}

		struct module_thread_init_data init_data;
		init_data.module = meta->dynamic_data;
		memcpy(init_data.senders, meta->senders, sizeof(init_data.senders));
		init_data.senders_count = meta->senders_count;

		VL_DEBUG_MSG_1("Initializing instance %s\n", meta->dynamic_data->instance_name);

		meta->thread_data = rrr_init_thread(&init_data);
	}

	// Start threads
	int threads_total = 0;
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_metadata *meta = &modules[i];

		if (meta->dynamic_data == NULL) {
			break;
		}

		for (int j = 0; j < meta->senders_count; j++) {
			meta->thread_data->senders[j] = meta->senders[j]->thread_data;
		}

		if (rrr_start_thread(meta->thread_data, cmd) != 0) {
			VL_MSG_ERR("Error when starting thread for instance%s\n",
					meta->dynamic_data->instance_name);
			return EXIT_FAILURE;
		}

		threads_total++;
	}

	if (threads_total == 0) {
		VL_DEBUG_MSG_1("No instances started, exiting\n");
		return EXIT_FAILURE;
	}

	if (thread_start_all_after_initialized() != 0) {
		VL_MSG_ERR("Error while waiting for threads to initialize\n");
		return EXIT_FAILURE;
	}

	return 0;
}

static volatile int main_running = 1;

void signal_interrupt (int s) {
    main_running = 0;

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	struct cmd_data cmd;
	struct rrr_config *config = NULL;

	int ret = EXIT_SUCCESS;

	struct sigaction action;
	action.sa_handler = signal_interrupt;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGUSR1, &action, NULL);

	if ((ret = main_parse_cmd_arguments(argc, argv, &cmd)) != 0) {
		goto out;
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

		ret = main_process_instances(config);

		if (ret != 0) {
			goto out_unload_modules;
		}
	}

	/*
	if ((ret = main_parse_cmd_modules(&cmd)) != 0) {
		goto out_unload_modules;
	}
*/

	threads_restart:

	// Initialzie dynamic_data thread data
	if ((ret = main_start_threads(instances, &cmd)) != 0) {
		goto out_stop_threads;
	}

	while (main_running) {
		usleep (100000);

		if (instance_check_threads_stopped(instances) == 0) {
			VL_DEBUG_MSG_1 ("One or more threads have finished. Restart.\n");

			rrr_threads_stop();
			instance_free_all_threads(instances);
			rrr_threads_destroy();

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
		rrr_threads_stop();
		instance_free_all_threads(instances);

	out_destroy_threads:
		rrr_threads_destroy();

	out_unload_modules:
#ifndef VL_NO_MODULE_UNLOAD
		instance_unload_all(instances);
#endif
		if (config != NULL) {
			rrr_config_destroy(config);
		}

	out:
	return ret;
}
