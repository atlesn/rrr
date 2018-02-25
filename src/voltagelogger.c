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
#include "cmdlineparser/cmdline.h"

int main_loop() {
	return 0;
}

static volatile int main_running = 1;

void signal_interrupt (int s) {
    main_running = 0;
}

struct module_metadata modules[CMD_ARGUMENT_MAX];

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
		fprintf (stderr, "Module %s could not be loaded\n", name);
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

	module_threads_init();

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
		if (module->module == NULL) {
			fprintf (stderr, "Module %s could not be loaded\n", module_string);
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
				if (module->module == NULL) {
					fprintf (stderr, "Module %s could not be loaded\n", sender_strings[j]);
					ret = EXIT_FAILURE;
					goto out_unload_all;
				}

				if (module_sender == module) {
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


	// Start threads, loop many times untill they are loaded in correct order
	int rounds_nothing_loaded = 0;
	while (1) {
		int not_loaded_this_round = 0;
		for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
			struct module_metadata *meta = &modules[i];
			if (meta->module == NULL) {
				// End of array
				break;
			}
			if (meta->thread_data != NULL) {
				// Already loaded
				continue;
			}
			struct module_metadata *sender_meta = NULL;

			for (int j = 0; j < meta->senders_count; j++) {
				if (meta->senders[j]->thread_data == NULL) {
					not_loaded_this_round++;
					goto dont_load;
				}
			}

			// We have no sender to specify and can be loaded first, or the
			// sender has already been loaded hence we can load now.
			struct module_thread_init_data init_data;
			init_data.module = meta->module;
			memcpy(init_data.senders, meta->senders, sizeof(init_data.senders));
			init_data.senders_count = meta->senders_count;

			printf ("Starting thread for module %s\n", meta->module->name);

			meta->thread_data = module_start_thread(&init_data);

			printf ("Thread data was %p\n", meta->thread_data);
			if (meta->thread_data == NULL) {
				fprintf (stderr, "Error when starting thread for module %s\n", meta->module->name);
				ret = EXIT_FAILURE;
				goto out_stop_threads;
			}
			dont_load:
			continue;
		}
		if (not_loaded_this_round == 0) {
			break;
		}
		else {
			if (rounds_nothing_loaded++ > 0) {
				fprintf (stderr, "Impossible module sender structure detected, cannot continue.\n");
				ret = EXIT_FAILURE;
				goto out_stop_threads;
			}
		}
	}

	// TODO : join threads

	struct sigaction action;

	action.sa_handler = signal_interrupt;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	sigaction (SIGINT, &action, NULL);

	while (main_running) {
		usleep (200000000);
		break;
	}

	printf ("Main loop finished\n");

	out_stop_threads:
	module_threads_stop();
	module_free_all_threads();

	out_unload_all:
	unload_all_modules();

	module_threads_destroy();

	out:
	return ret;
}
