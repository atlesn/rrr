/*

Voltage Logger

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

	// Initialzie dynamic_data thread data
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

	// Start threads
	if (thread_new_collection (thread_collection) != 0) {
		VL_MSG_ERR("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	int threads_total = 0;
	RRR_INSTANCE_LOOP(instance,instances) {
		if (instance->dynamic_data == NULL) {
			break;
		}

		if (instance_start_thread(*thread_collection, instance->thread_data) != 0) {
			VL_MSG_ERR("Error when starting thread for instance%s\n",
					instance->dynamic_data->instance_name);
			return EXIT_FAILURE;
		}

		threads_total++;
	}

	if (threads_total == 0) {
		VL_DEBUG_MSG_1("No instances started, exiting\n");
		return EXIT_FAILURE;
	}

	if (thread_start_all_after_initialized(*thread_collection) != 0) {
		VL_MSG_ERR("Error while waiting for threads to initialize\n");
		return EXIT_FAILURE;
	}

	out:
	return ret;
}

void main_threads_stop (struct vl_thread_collection *collection, struct instance_metadata_collection *instances) {
	threads_stop_and_join(collection);
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
	const char* debuglevel_string = cmd_get_value(&*cmd, "debuglevel", 0);
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

	rrr_init_global_config(debuglevel);

	return 0;
}
