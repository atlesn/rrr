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
#include "../lib/fixed_point.h"
#include "../lib/stats_engine.h"

const char *library_paths[] = {
		RRR_MODULE_PATH,
		RRR_TEST_MODULE_PATH,
		""
};

// After one or more threads have exited, wait with killing other
// threads to allow for debugging
//#define RRR_TEST_DELAYED_EXIT 1

int main_get_configuration_test_result(struct instance_metadata_collection *instances) {
	struct instance_metadata *instance = rrr_instance_find(instances, "instance_test_module");

	if (instance == NULL) {
		RRR_MSG_ERR("Could not find instance for configuration test 'instance_configuration_tester'");
		return 1;
	}

	void *handle = instance->dynamic_data->dl_ptr;

	dlerror();

	int (*get_test_result)(void) = dlsym(handle, "get_test_module_result");

	if (get_test_result == NULL) {
		RRR_MSG_ERR("Could not find test result function in test module: %s\n", dlerror());
		return 1;
	}

	return get_test_result();
}

static volatile int main_running = 1;

int signal_interrupt (int s, void *arg) {
    main_running = 0;

    (void)(arg);

    RRR_DBG_1("Received signal %i\n", s);

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);

	return 0;
}

static const struct cmd_arg_rule cmd_rules[] = {
		{1, 'd',	"debuglevel", ""},
		{0, '\0',	NULL, ""}
};

static int test_fixp(void) {
	int ret = 0;

	rrr_fixp fixp_a = 0;
	rrr_fixp fixp_b = 0;
	rrr_fixp fixp_c = 0;

	const char *endptr;

	const char *a_str = "+1.5yuiyuiyuiyu";
	const char *b_str = "-1.5##%%¤#";
	const char *c_str = "15.671875";

	ret |= rrr_fixp_str_to_fixp(&fixp_a, a_str, strlen(a_str), &endptr);
	if (endptr - a_str != 4) {
		TEST_MSG("End pointer position was incorrect for A\n");
		ret = 1;
		goto out;
	}

	ret |= rrr_fixp_str_to_fixp(&fixp_b, b_str, strlen(b_str), &endptr);
	if (endptr - b_str != 4) {
		TEST_MSG("End pointer position was incorrect for B\n");
		ret = 1;
		goto out;
	}

	ret |= rrr_fixp_str_to_fixp(&fixp_c, c_str, strlen(c_str), &endptr);

	if (ret != 0) {
		TEST_MSG("Conversion from string to fixed point failed\n");
		goto out;
	}

	if (fixp_a == 0) {
		TEST_MSG("Zero returned while converting string to fixed point\n");
		ret = 1;
		goto out;
	}

	ret = fixp_a + fixp_b;
	if (ret != 0) {
		TEST_MSG("Expected 0 while adding 1.5 and -1.5, got %i\n", ret);
		ret = 1;
		goto out;
	}

	char buf[512];
	if ((ret = rrr_fixp_to_str(buf, 511, fixp_a)) != 0) {
		TEST_MSG("Conversion from fixed point to string failed\n");
		goto out;
	}
	if (strncmp(buf, "1.5", 3) != 0) {
		TEST_MSG("Wrong output while converting fixed point to string, expected '1.5' but got '%s'\n", buf);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_to_str(buf, 511, fixp_c)) != 0) {
		TEST_MSG("Conversion from fixed point to string failed\n");
		goto out;
	}
	if (strncmp(buf, "15.671875", 8) != 0) {
		TEST_MSG("Wrong output while converting fixed point to string, expected '5.671875' but got '%s'\n", buf);
		ret = 1;
		goto out;
	}

	long double dbl = 0;
	if ((ret = rrr_fixp_to_ldouble(&dbl, fixp_a)) != 0) {
		TEST_MSG("Conversion from fixed point to ldouble failed\n");
		goto out;
	}

	if (dbl != 1.5) {
		TEST_MSG("Wrong output while converting fixed point to double, expected 1.5 but got %Lf\n", dbl);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_fixp_ldouble_to_fixp(&fixp_a, dbl)) != 0) {
		TEST_MSG("Conversion from double to fixed point failed\n");
		goto out;
	}

	ret = fixp_a + fixp_b;
	if (ret != 0) {
		TEST_MSG("Expected 0 while adding 1.5 and -1.5 after conversion from double, got %i\n", ret);
		ret = 1;
		goto out;
	}

	const char *a_hex = "16#+1.8/¤#";
	if (rrr_fixp_str_to_fixp(&fixp_a, a_hex, strlen(a_hex), &endptr) != 0) {
		TEST_MSG("Hexadecimal conversion failed\n");
		ret = 1;
		goto out;
	}

	if (endptr - a_hex != 7) {
		TEST_MSG("End pointer position was incorrect for hex\n");
		ret = 1;
		goto out;
	}

	if (rrr_fixp_to_ldouble(&dbl, fixp_a) != 0) {
		TEST_MSG("Conversion from fixed point to ldouble failed (hex)\n");
		ret = 1;
		goto out;
	}

	if (dbl != 1.5) {
		TEST_MSG("Wrong output while converting fixed point to double (hex test), expected 1.5 but got %Lf\n", dbl);
		ret = 1;
		goto out;
	}

	out:
	return (ret != 0);
}

int main (int argc, const char **argv) {
	struct rrr_signal_handler *signal_handler = NULL;
	int ret = 0;

	rrr_strerror_init();

	// TODO : Implement stats engine for test program
	struct rrr_stats_engine stats_engine = {0};

	struct cmd_data cmd;
	cmd_init(&cmd, cmd_rules, argc, argv);

	struct rrr_signal_functions signal_functions = {
			rrr_signal_handler_set_active,
			rrr_signal_handler_push,
			rrr_signal_handler_remove
	};

	signal_handler = signal_functions.push_handler(signal_interrupt, NULL);

	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		RRR_MSG_ERR("Library build version mismatch.\n");
		ret = 1;
		goto out;
	}

	TEST_MSG("Starting test with module path %s\n", RRR_MODULE_PATH);
	TEST_MSG("Change to directory %s\n", RRR_TEST_PATH);

	if (chdir(RRR_TEST_PATH) != 0) {
		TEST_MSG("Error while changing directory\n");
		ret = 1;
		goto out;
	}

	TEST_BEGIN("PARSE CMD") {
		if (main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	RRR_DBG_1("debuglevel is: %u\n", RRR_DEBUGLEVEL);

	if (ret == 1) {
		goto out;
	}

	struct rrr_config *config;

	TEST_BEGIN("fixed point type") {
		ret = test_fixp();
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out;
	}

	TEST_BEGIN("non-existent config file") {
		config = rrr_config_parse_file("nonexistent_file");
	} TEST_RESULT(config == NULL);

	if (config != NULL) {
		goto out_cleanup_config;
	}

	TEST_BEGIN("true configuration loading") {
		config = rrr_config_parse_file("test.conf");
	} TEST_RESULT(config != NULL);

	if (config == NULL) {
		ret = 1;
		goto out;
	}

	struct instance_metadata_collection *instances;
	TEST_BEGIN("init instances") {
		if (rrr_instance_metadata_collection_new (&instances, &signal_functions) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out_cleanup_config;
	}

	TEST_BEGIN("process instances from config") {
		if (rrr_instance_process_from_config(instances, config, library_paths) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out_cleanup_instances;
	}

	struct rrr_thread_collection *collection = NULL;
	TEST_BEGIN("start threads") {
		if (main_start_threads(&collection, instances, config, &cmd, &stats_engine) != 0) {
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
		while (main_running && (rrr_global_config.no_thread_restart || rrr_instance_check_threads_stopped(instances) == 0)) {
			usleep(10000);
		}

		ret = main_get_configuration_test_result(instances);

#ifdef RRR_TEST_DELAYED_EXIT
		usleep (3600000000); // 3600 seconds
#endif

		main_threads_stop(collection, instances);

	} TEST_RESULT(ret == 0);

	rrr_thread_destroy_collection(collection, 0);

	out_cleanup_instances:
	rrr_instance_metadata_collection_destroy(instances);

	// Don't unload modules in the test suite
	//rrr_instance_unload_all(instances);

	out_cleanup_config:
	if (config != NULL) {
		rrr_config_destroy(config);
	}

	out:
	rrr_signal_handler_remove(signal_handler);
	rrr_exit_cleanup_methods_run_and_free();
	cmd_destroy(&cmd);
	rrr_strerror_cleanup();
	return ret;
}
