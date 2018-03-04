/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include "modules.h"
#include "lib/cmdlineparser/cmdline.h"

// Used so that debugger output at program exit can show function names
// on the stack correctly
#define VL_NO_MODULE_UNLOAD

static volatile int main_running = 1;

void signal_interrupt (int s) {
    main_running = 0;
}

struct module_metadata modules[CMD_ARGUMENT_MAX];

int module_check_threads_stopped() {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (modules[i].module == NULL) {
			break;
		}

		if (thread_get_state(modules[i].thread_data->thread) == VL_THREAD_STATE_STOPPED) {
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
	printf ("Saving module %s\n", module->name);
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (modules[i].module == NULL) {
			modules[i].module = module;
			return &modules[i];
		}
	}
	fprintf (stderr, "Too many different modules defind, max is %i\n", CMD_ARGUMENT_MAX);
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
		fprintf (stderr, "Module %s could not be loaded (in find_or_load)\n", name);
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

int main (int argc, const char *argv[]) {
	struct cmd_data cmd;

	int ret = EXIT_SUCCESS;

	if (cmd_parse(&cmd, argc, argv, CMD_CONFIG_NOCOMMAND|CMD_CONFIG_SPLIT_COMMA) != 0) {
		fprintf (stderr, "Error while parsing command line\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	memset(modules, '\0', sizeof(modules));


	for (unsigned long int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		const char *module_string = cmd_get_subvalue(&cmd, "module", i, 0);

		const char *sender_strings[VL_MODULE_MAX_SENDERS];
		int senders_count = 0;
		for (unsigned long int j = 1; j < VL_MODULE_MAX_SENDERS; j++) {
			const char *sender_string = cmd_get_subvalue(&cmd, "module", i, j);
			if (sender_string == NULL || *sender_string == '\0') {
				break;
			}
			sender_strings[senders_count++] = cmd_get_subvalue(&cmd, "module", i, j);
		}

		if (module_string == NULL || *module_string == '\0') {
			break;
		}

		printf ("Loading module '%s'\n", module_string);
		struct module_metadata *module = find_or_load_module(module_string);
		if (module == NULL || module->module == NULL) {
			fprintf (stderr, "Module %s could not be loaded A\n", module_string);
			ret = EXIT_FAILURE;
			goto out_unload_all;
		}

		if (module->module->type == VL_MODULE_TYPE_PROCESSOR) {
			if (senders_count == 0) {
				fprintf (stderr, "Sender module must be specified for processor module %s\n", module_string);
				ret = EXIT_FAILURE;
				goto out_unload_all;
			}

			for (unsigned long int j = 0; j < senders_count; j++) {
				printf ("Loading sender module '%s' (if not already loaded)\n", sender_strings[j]);
				struct module_metadata *module_sender = find_or_load_module(sender_strings[j]);
				if (module_sender == NULL) {
					fprintf (stderr, "Module %s could not be loaded B\n", sender_strings[j]);
					ret = EXIT_FAILURE;
					goto out_unload_all;
				}

				if (module_sender == module || module_sender->module == NULL) {
					fprintf (stderr, "Module %s set with itself as sender\n", sender_strings[j]);
					ret = EXIT_FAILURE;
					goto out_unload_all;
				}
				module->senders[module->senders_count++] = module_sender;
			}
		}
		else if (module->module->type == VL_MODULE_TYPE_SOURCE) {
			if (senders_count != 0) {
				fprintf (stderr, "Sender module cannot be specified for source module %s\n", module_string);
				ret = EXIT_FAILURE;
				goto out;
			}
		}
		else {
			fprintf (stderr, "Unknown module type for %s: %i\n", module_string, module->module->type);
		}
	}

	threads_restart:

	module_threads_init();

	// Init threads
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_metadata *meta = &modules[i];

		if (meta->module == NULL) {
			break;
		}

		struct module_thread_init_data init_data;
		init_data.module = meta->module;
		memcpy(init_data.senders, meta->senders, sizeof(init_data.senders));
		init_data.senders_count = meta->senders_count;

		printf ("Initializing %s\n", meta->module->name);

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

		if (module_start_thread(meta->thread_data, &cmd) != 0) {
			fprintf (stderr, "Error when starting thread for module %s\n", meta->module->name);
			ret = EXIT_FAILURE;
			goto out_stop_threads;
		}

		threads_total++;
	}

	if (threads_total == 0) {
		printf ("No modules started, exiting\n");
		goto out_stop_threads;
	}

	if (thread_start_all_after_initialized() != 0) {
		fprintf (stderr, "Error while waiting for threads to initialize\n");
		goto out_stop_threads;
	}

	struct sigaction action;

	// TODO : remove signal handler when we quit to force exit

	action.sa_handler = signal_interrupt;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	sigaction (SIGINT, &action, NULL);

	while (main_running) {
		usleep (1000000);
		if (module_check_threads_stopped() == 0) {
			printf ("One or more threads have finished. Restart.\n");
			module_threads_stop();
			module_free_all_threads();
			module_threads_destroy();
			goto threads_restart;
		}
	}

	signal(SIGINT, SIG_DFL);

	printf ("Main loop finished\n");

	out_stop_threads:
	module_threads_stop();
	module_free_all_threads();

	out_unload_all:

	module_threads_destroy();

#ifndef VL_NO_MODULE_UNLOAD
	unload_all_modules();
#endif


	out:
	return ret;
}
