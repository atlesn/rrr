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
#include "modules.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/version.h"

// Used so that debugger output at program exit can show function names
// on the stack correctly
//#define VL_NO_MODULE_UNLOAD

static struct module_metadata modules[CMD_ARGUMENT_MAX];

int module_check_threads_stopped() {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (modules[i].module == NULL) {
			break;
		}

		if (thread_get_state(modules[i].thread_data->thread) == VL_THREAD_STATE_STOPPED || modules[i].thread_data->thread->is_ghost == 1) {
			return 0;
		}
	}
	return 1;
}

void module_free_all_threads() {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (modules[i].module == NULL) {
			break;
		}

		module_free_thread(modules[i].thread_data);
	}
}

void unload_all_modules() {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (modules[i].module == NULL) {
			break;
		}
		unload_module(modules[i].module);
	}
}

struct module_metadata *save_module(struct module_dynamic_data *module) {
	VL_DEBUG_MSG_1 ("Saving module %s\n", module->name);
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (modules[i].module == NULL) {
			modules[i].module = module;
			return &modules[i];
		}
	}
	VL_MSG_ERR ("Too many different modules defind, max is %i\n", CMD_ARGUMENT_MAX);
	exit(EXIT_FAILURE);
}

struct module_metadata *find_or_load_module(const char *name) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_dynamic_data *module = modules[i].module;
		if (module != NULL && strcmp(module->name, name) == 0) {
			return &modules[i];
		}
	}

	struct module_dynamic_data *module = load_module(name);
	if (module == NULL) {
		VL_MSG_ERR ("Module %s could not be loaded (in find_or_load)\n", name);
		return NULL;
	}

	return save_module(module);
}

struct module_metadata *find_module(const char *name) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_dynamic_data *module = modules[i].module;
		if (module != NULL && strcmp(module->name, name) == 0) {
			return &modules[i];
		}
	}
	return NULL;
}

int main_parse_cmd_modules(struct cmd_data *cmd) {
	memset(modules, '\0', sizeof(modules));

	for (unsigned long int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		const char *module_string = cmd_get_subvalue(cmd, "module", i, 0);

		const char *sender_strings[VL_MODULE_MAX_SENDERS];
		int senders_count = 0;
		for (unsigned long int j = 1; j < VL_MODULE_MAX_SENDERS; j++) {
			const char *sender_string = cmd_get_subvalue(cmd, "module", i, j);
			if (sender_string == NULL || *sender_string == '\0') {
				break;
			}
			sender_strings[senders_count++] =
					cmd_get_subvalue(cmd, "module", i, j);
		}

		if (module_string == NULL || *module_string == '\0') {
			break;
		}

		VL_DEBUG_MSG_1("Loading module '%s'\n", module_string);
		struct module_metadata *module = find_or_load_module(module_string);
		if (module == NULL || module->module == NULL) {
			VL_MSG_ERR("Module %s could not be loaded A\n", module_string);
			return EXIT_FAILURE;
		}

		if (module->module->type == VL_MODULE_TYPE_PROCESSOR) {
			if (senders_count == 0) {
				VL_MSG_ERR("Sender module must be specified for processor module %s\n",
						module_string);
				return EXIT_FAILURE;
			}

			for (unsigned long int j = 0; j < senders_count; j++) {
				VL_DEBUG_MSG_1("Loading sender module '%s' (if not already loaded)\n",
						sender_strings[j]
				);

				struct module_metadata *module_sender =
						find_or_load_module(sender_strings[j]);

				if (module_sender == NULL) {
					VL_MSG_ERR("Module %s could not be loaded B\n",
							sender_strings[j]);
					return EXIT_FAILURE;
				}

				if (module_sender == module || module_sender->module == NULL) {
					VL_MSG_ERR("Module %s set with itself as sender\n",
							sender_strings[j]);
					return EXIT_FAILURE;
				}

				module->senders[module->senders_count++] = module_sender;
			}
		}
		else if (module->module->type == VL_MODULE_TYPE_SOURCE) {
			if (senders_count != 0) {
				VL_MSG_ERR("Sender module cannot be specified for source module %s\n",
						module_string);
				return EXIT_FAILURE;
			}
		}
		else {
			VL_MSG_ERR ("Unknown module type for %s: %i\n",
					module_string, module->module->type
			);
		}
	}

	return 0;
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
	// Initialzie module thread data
	module_threads_init();

	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_metadata *meta = &modules[i];

		if (meta->module == NULL) {
			break;
		}

		struct module_thread_init_data init_data;
		init_data.module = meta->module;
		memcpy(init_data.senders, meta->senders, sizeof(init_data.senders));
		init_data.senders_count = meta->senders_count;

		VL_DEBUG_MSG_1("Initializing %s\n", meta->module->name);

		meta->thread_data = module_init_thread(&init_data);
	}

	// Start threads
	int threads_total = 0;
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_metadata *meta = &modules[i];

		if (meta->module == NULL) {
			break;
		}

		for (int j = 0; j < meta->senders_count; j++) {
			meta->thread_data->senders[j] = meta->senders[j]->thread_data;
		}

		if (module_start_thread(meta->thread_data, cmd) != 0) {
			VL_MSG_ERR("Error when starting thread for module %s\n",
					meta->module->name);
			return EXIT_FAILURE;
		}

		threads_total++;
	}

	if (threads_total == 0) {
		VL_DEBUG_MSG_1("No modules started, exiting\n");
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

	if ((ret = main_parse_cmd_modules(&cmd)) != 0) {
		goto out_unload_modules;
	}

	threads_restart:

	// Initialzie module thread data
	if ((ret = main_start_threads(modules, &cmd)) != 0) {
		goto out_stop_threads;
	}

	while (main_running) {
		usleep (100000);

		if (module_check_threads_stopped() == 0) {
			VL_DEBUG_MSG_1 ("One or more threads have finished. Restart.\n");

			module_threads_stop();
			module_free_all_threads();
			module_threads_destroy();

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
		module_threads_stop();
		module_free_all_threads();

	out_destroy_threads:
		module_threads_destroy();

	out_unload_modules:
#ifndef VL_NO_MODULE_UNLOAD
		unload_all_modules();
#endif

	out:
	return ret;
}
