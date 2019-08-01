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
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>

#include "test.h"
#include "../main.h"
#include "../global.h"
#include "../../build_timestamp.h"
#include "../lib/common.h"
#include "../lib/configuration.h"
#include "../lib/version.h"
#include "../lib/instances.h"
#include "../lib/cmdlineparser/cmdline.h"

const char *library_paths[] = {
		VL_MODULE_PATH,
		VL_TEST_MODULE_PATH,
		""
};

int main_get_configuration_test_result(struct instance_metadata_collection *instances) {
	struct instance_metadata *instance = instance_find(instances, "instance_test_module");

	if (instance == NULL) {
		VL_MSG_ERR("Could not find instance for configuration test 'instance_configuration_tester'");
		return 1;
	}

	void *handle = instance->dynamic_data->dl_ptr;

	dlerror();

	int (*get_test_result)(void) = dlsym(handle, "get_test_module_result");

	if (get_test_result == NULL) {
		VL_MSG_ERR("Could not find test result function in test module: %s\n", dlerror());
		return 1;
	}

	return get_test_result();
}

static volatile int main_running = 1;

int signal_interrupt (int s, void *arg) {
    main_running = 0;

    (void)(arg);

    VL_DEBUG_MSG_1("Received signal %i\n", s);

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);

	return 0;
}


int main (int argc, const char **argv) {
	struct rrr_signal_handler *signal_handler = NULL;
	int ret = 0;

	struct rrr_signal_functions signal_functions = {
			rrr_signal_handler_set_active,
			rrr_signal_handler_push,
			rrr_signal_handler_remove
	};

	signal_handler = signal_functions.push_handler(signal_interrupt, NULL);

	if (!rrr_verify_library_build_timestamp(VL_BUILD_TIMESTAMP)) {
		VL_MSG_ERR("Library build version mismatch.\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("Starting test with module path %s\n", VL_MODULE_PATH);
	TEST_MSG("Change to directory %s\n", VL_TEST_PATH);

	if (chdir(VL_TEST_PATH) != 0) {
		TEST_MSG("Error while changing directory\n");
		ret = 1;
		goto out;
	}

	struct cmd_data cmd = cmd_new(argc, argv);
	TEST_BEGIN("PARSE CMD") {
		if (main_parse_cmd_arguments(&cmd) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	VL_DEBUG_MSG_1("debuglevel is: %u\n", VL_DEBUGLEVEL);

	if (ret == 1) {
		goto out;
	}

	struct rrr_config *config;

	TEST_BEGIN("non-existent config file") {
	config = rrr_config_parse_file("nonexistent_file");
	} TEST_RESULT(config == NULL);

	if (config != NULL) {
		free(config);
	}

	TEST_BEGIN("true configuration loading") {
		config = rrr_config_parse_file("test.conf");
	} TEST_RESULT(config != NULL);

	struct instance_metadata_collection *instances;
	TEST_BEGIN("init instances") {
		if (instance_metadata_collection_new (&instances, &signal_functions) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out_cleanup_config;
	}

	TEST_BEGIN("process instances from config") {
		if (instance_process_from_config(instances, config, library_paths) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out_cleanup_instances;
	}

	struct vl_thread_collection *collection = NULL;
	TEST_BEGIN("start threads") {
		if (main_start_threads(&collection, instances, config, &cmd) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out_cleanup_instances;
	}

	struct sigaction action;
	action.sa_handler = rrr_signal;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	// During preload stage, signals are temporarily deactivated.
	instances->signal_functions->set_active(RRR_SIGNALS_ACTIVE);

	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGUSR1, &action, NULL);

	TEST_BEGIN("testing type array parsing") {
		while (main_running && (rrr_global_config.no_thread_restart || instance_check_threads_stopped(instances) == 0)) {
			usleep(10000);
		}

		ret = main_get_configuration_test_result(instances);
		main_threads_stop(collection, instances);

	} TEST_RESULT(ret == 0);

	thread_destroy_collection(collection);

	out_cleanup_instances:
	instance_metadata_collection_destroy(instances);

	out_cleanup_config:
	if (config != NULL) {
		rrr_config_destroy(config);
	}

	out:
	rrr_signal_handler_remove(signal_handler);
	rrr_exit_cleanup_methods_run_and_free();
	return ret;
}
