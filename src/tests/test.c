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
#include "../../build_timestamp.h"
#include "../lib/log.h"
#include "../lib/rrr_strerror.h"
#include "../lib/common.h"
#include "../lib/configuration.h"
#include "../lib/version.h"
#include "../lib/instances.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../lib/stats/stats_engine.h"
#include "../lib/message_broker.h"
#include "../lib/fork.h"
#include "../lib/rrr_config.h"
#include "../lib/util/posix.h"

#include "test_condition.h"
#include "test_usleep.h"
#include "test_fixp.h"
#include "test_inet.h"
#ifdef RRR_WITH_JSONC
#	include "test_json.h"
#endif
#include "test_conversion.h"
#include "test_msgdb.h"
#include "test_nullsafe.h"
#include "test_increment.h"
#include "test_allocator.h"
#include "test_mmap_channel.h"

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("test");

const char *library_paths[] = {
		RRR_MODULE_PATH,
		RRR_TEST_MODULE_PATH,
		""
};

// After one or more threads have exited, wait with killing other
// threads to allow for debugging
//#define RRR_TEST_DELAYED_EXIT 1

int main_get_test_result(struct rrr_instance_collection *instances) {
	struct rrr_instance *instance = rrr_instance_find(instances, "instance_test_module");

	if (instance == NULL) {
		RRR_MSG_0("Could not find instance for configuration test 'instance_configuration_tester'");
		return 1;
	}

	void *handle = instance->module_data->dl_ptr;

	dlerror();

	int (*get_test_result)(void) = dlsym(handle, "get_test_module_result");

	if (get_test_result == NULL) {
		RRR_MSG_0("Could not find test result function in test module: %s\n", dlerror());
		return 1;
	}

	return get_test_result();
}

static volatile int main_running = 1;

int signal_interrupt (int s, void *arg) {
    (void)(arg);

    RRR_DBG_SIGNAL("Received signal %i\n", s);

    if (s == SIGINT) {
    	main_running = 0;
	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
    }
    
    return 0;
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG,        '\0',   "config",                "{CONFIGURATION FILE}"},
        {0,                           'W',    "no-watchdog-timers",    "[-W|--no-watchdog-timers]"},
        {0,                           'T',    "no-thread-restart",     "[-T|--no-thread-restart]"},
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'r',    "run-directory",         "[-r|--run-directory[=]RUN DIRECTORY]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel DEBUGLEVEL]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'l',    "library-tests",         "[-l|--library-tests]"},
        {0,                           '\0',    NULL,                   ""}
};

int rrr_test_library_functions (struct rrr_fork_handler *fork_handler) {
	int ret = 0;
	int ret_tmp = 0;

	// OR all the return values, don't stop if a test fails

	TEST_BEGIN("rrr_allocator") {
		ret_tmp = rrr_test_allocator(fork_handler);
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("rrr_mmap_channel") {
		ret_tmp = rrr_test_mmap_channel(fork_handler);
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("rrr_condition") {
		ret_tmp = rrr_test_condition();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("rrr_posix_usleep") {
		ret_tmp = rrr_test_usleep();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("fixed point type") {
		ret_tmp = rrr_test_fixp();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("inet functions") {
		ret_tmp = rrr_test_inet();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

#ifdef RRR_WITH_JSONC
	TEST_BEGIN("JSON parsing") {
		ret_tmp = rrr_test_json();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

	TEST_BEGIN("type conversion") {
		ret_tmp = rrr_test_conversion();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("message database") {
		ret_tmp = rrr_test_msgdb(fork_handler);
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("nullsafe") {
		ret_tmp = rrr_test_nullsafe();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("increment") {
		ret_tmp = rrr_test_increment();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	return ret;
}

int main (int argc, const char **argv, const char **env) {
	struct rrr_signal_handler *signal_handler_fork = NULL;
	struct rrr_signal_handler *signal_handler_interrupt = NULL;
	int ret = 0;

	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	if (rrr_log_init() != 0) {
		goto out_final;
	}
	rrr_strerror_init();

	// TODO : Implement stats engine for test program
	struct rrr_stats_engine stats_engine = {0};
	struct rrr_message_broker *message_broker = NULL;
	struct rrr_config *config = NULL;
	struct rrr_fork_handler *fork_handler = NULL;

	struct cmd_data cmd;
	cmd_init(&cmd, cmd_rules, argc, argv);

	signal_handler_fork = rrr_signal_handler_push(rrr_fork_signal_handler, NULL);
	signal_handler_interrupt = rrr_signal_handler_push(signal_interrupt, NULL);

	rrr_signal_default_signal_actions_register();

	if (rrr_message_broker_new(&message_broker) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_fork_handler_new (&fork_handler) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_message_broker;
	}

	TEST_MSG("Starting test with module path %s\n", RRR_MODULE_PATH);
	TEST_MSG("Change to directory %s\n", RRR_TEST_PATH);

	if (chdir(RRR_TEST_PATH) != 0) {
		TEST_MSG("Error while changing directory\n");
		ret = 1;
		goto out_cleanup_message_broker;
	}

	TEST_BEGIN("PARSE CMD") {
		if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);
	if (ret == 1) {
		// Some data might have been stored also upon error
		goto out_cleanup_cmd;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_cmd;
	}

	RRR_DBG_1("debuglevel is: %u\n", RRR_DEBUGLEVEL);

	if (cmd_exists(&cmd, "library-tests", 0)) {
		TEST_MSG("Library tests requested by argument, doing that now.\n");
		ret = rrr_test_library_functions(fork_handler);
		goto out_cleanup_cmd;
	}

	const char *config_file = cmd_get_value(&cmd, "config", 0);
	if (config_file == NULL) {
		RRR_MSG_0("No configuration file specified for test program\n");
		ret = 1;
		goto out_cleanup_cmd;
	}

	TEST_BEGIN("configuration loading") {
		ret = rrr_config_parse_file(&config, config_file);
	} TEST_RESULT(ret == 0);

	if (config == NULL) {
		ret = 1;
		goto out_cleanup_cmd;
	}

	struct rrr_instance_collection instances = {0};

	if (ret != 0) {
		goto out_cleanup_config;
	}

	TEST_BEGIN("process instances from config") {
		if (rrr_instance_create_from_config(&instances, config, library_paths) != 0) {
			ret = 1;
		}
	} TEST_RESULT(ret == 0);

	if (ret != 0) {
		goto out_cleanup_instances;
	}

	struct rrr_thread_collection *collection = NULL;
	TEST_BEGIN("start threads") {
		if (rrr_main_create_and_start_threads (
				&collection,
				&instances,
				config,
				&cmd,
				&stats_engine,
				message_broker,
				fork_handler
		) != 0) {
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

	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGUSR1, &action, NULL);

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);
	TEST_BEGIN(config_file) {
		while (main_running && (rrr_config_global.no_thread_restart || rrr_instance_check_threads_stopped(&instances) == 0)) {
			rrr_posix_usleep(100000);
			rrr_fork_handle_sigchld_and_notify_if_needed (fork_handler, 0);
		}

		ret = main_get_test_result(&instances);

#ifdef RRR_TEST_DELAYED_EXIT
		rrr_posix_usleep (3600000000); // 3600 seconds
#endif

		rrr_main_threads_stop_and_destroy(collection);
	} TEST_RESULT(ret == 0);

	out_cleanup_instances:
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
		rrr_instance_collection_clear(&instances);

		// Don't unload modules in the test suite
		//rrr_instance_unload_all(instances);

	out_cleanup_config:
		if (config != NULL) {
			rrr_config_destroy(config);
		}

	out_cleanup_cmd:
		cmd_destroy(&cmd);

	out_cleanup_message_broker:
		rrr_message_broker_destroy(message_broker);

//	out_cleanup_fork_handler:
		rrr_fork_send_sigusr1_and_wait(fork_handler);
		rrr_fork_handle_sigchld_and_notify_if_needed(fork_handler, 1);
		rrr_fork_handler_destroy (fork_handler);

	out_cleanup_signal:
		rrr_signal_handler_remove(signal_handler_interrupt);
		rrr_signal_handler_remove(signal_handler_fork);
		rrr_exit_cleanup_methods_run_and_free();
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_final:
		return ret;
}
