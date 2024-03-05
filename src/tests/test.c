/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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

#include "../lib/util/bsd.h"
#include "../lib/util/posix.h"

#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>

#include "test.h"
#include "../main.h"
#include "../../build_timestamp.h"
#include "../lib/allocator.h"
#include "../lib/log.h"
#include "../lib/rrr_strerror.h"
#include "../lib/common.h"
#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/version.h"
#include "../lib/instances.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../lib/stats/stats_engine.h"
#include "../lib/message_broker.h"
#include "../lib/fork.h"
#include "../lib/rrr_config.h"

#include "test_condition.h"
#include "test_time.h"
#include "test_msleep_signal_safe.h"
#include "test_fixp.h"
#include "test_mqtt_topic.h"
#include "test_parse.h"
#include "test_inet.h"
#include "test_modbus.h"
#ifdef RRR_WITH_TLS
#	include "test_tls.h"
#endif
#ifdef RRR_WITH_JSONC
#	include "test_json.h"
#endif
#ifdef RRR_WITH_ZLIB
#	include "test_zlib.h"
#endif
#ifdef RRR_WITH_LUA
#	include "test_lua.h"
#endif
#ifdef RRR_WITH_JS
#	include "lib/testjs.h"
#endif
#ifdef RRR_WITH_HTTP3
#	include "test_quic.h"
#endif
#include "test_conversion.h"
#include "test_msgdb.h"
#include "test_nullsafe.h"
#include "test_increment.h"
#include "test_discern_stack.h"
#include "test_allocator.h"
#include "test_mmap_channel.h"
#include "test_linked_list.h"
#include "test_hdlc.h"
#include "test_readdir.h"
#include "test_send_loop.h"
#include "test_http.h"

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

	void *handle = instance->module_data->module_load_data.dl_ptr;

	dlerror();

	int (*get_test_result)(void) = dlsym(handle, "test_module_result_get");

	if (get_test_result == NULL) {
		RRR_MSG_0("Could not find test result function in test module: %s\n", dlerror());
		return 1;
	}

	return get_test_result();
}

static volatile int some_fork_has_stopped = 0;
static volatile int main_running = 1;
static volatile int encourage_stop = 0;
static volatile int sigusr2 = 0;

int rrr_signal_handler(int s, void *arg) {
	int ret = rrr_signal_default_handler(&main_running, &sigusr2, s, arg);

	encourage_stop = some_fork_has_stopped || !main_running;

	return ret;
}

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG,        '\0',   "config",                "{CONFIGURATION FILE}"},
        {0,                           'W',    "no-watchdog-timers",    "[-W|--no-watchdog-timers]"},
	{0,                           'S',    "single-thread",         "[-S|--single-thread]"},
/*      {0,                           'T',    "no-thread-restart",     "[-T|--no-thread-restart]"}, // Not used by test program */
	{CMD_ARG_FLAG_HAS_ARGUMENT,   'r',    "run-directory",         "[-r|--run-directory[=]RUN DIRECTORY]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'e',    "environment-file",      "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'd',    "debuglevel",            "[-d|--debuglevel[=]DEBUGLEVEL]"},
        {CMD_ARG_FLAG_NO_ARGUMENT,    'l',    "library-tests",         "[-l|--library-tests]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,   'f',    "fork-executable",       "[-f|--fork-executable[=]EXECUTABLE]"},
        {0,                           '\0',    NULL,                   ""}
};

int rrr_test_library_functions (
		const volatile int *main_running,
		struct rrr_fork_handler *fork_handler,
		struct rrr_event_queue *event_queue
) {
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

	TEST_BEGIN("time functions") {
		ret_tmp = rrr_test_time();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("rrr_posix_msleep_signal_safe") {
		ret_tmp = rrr_test_msleep_signal_safe();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("fixed point type") {
		ret_tmp = rrr_test_fixp();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("MQTT topics") {
		ret_tmp = rrr_test_mqtt_topic();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("parsing") {
		ret_tmp = rrr_test_parse();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("inet functions") {
		ret_tmp = rrr_test_inet();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

#ifdef RRR_WITH_TLS
	TEST_BEGIN("TLS functions") {
		ret_tmp = rrr_test_tls(main_running, event_queue);
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

#ifdef RRR_WITH_JSONC
	TEST_BEGIN("JSON parsing") {
		ret_tmp = rrr_test_json();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

#ifdef RRR_WITH_ZLIB
	TEST_BEGIN("zlib compression and decompression") {
		ret_tmp = rrr_test_zlib();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

#ifdef RRR_WITH_LUA
	TEST_BEGIN("Lua library functions") {
		ret_tmp = rrr_test_lua();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

#ifdef RRR_WITH_HTTP3
	TEST_BEGIN("quic handshake") {
		ret_tmp = rrr_test_quic(main_running, event_queue);
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;
#endif

#ifdef RRR_WITH_JS
	TEST_BEGIN("js library functions") {
		ret_tmp = rrr_test_js();
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

	TEST_BEGIN("discern stack parsing") {
		ret_tmp = rrr_test_discern_stack();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("linked list") {
		ret_tmp = rrr_test_linked_list();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("HDLC frames") {
		ret_tmp = rrr_test_hdlc();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("Readdir") {
		ret_tmp = rrr_test_readdir();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("Send loop") {
		ret_tmp = rrr_test_send_loop();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("modbus functions") {
		ret_tmp = rrr_test_modbus();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	TEST_BEGIN("http functions") {
		ret_tmp = rrr_test_http();
	} TEST_RESULT(ret_tmp == 0);

	ret |= ret_tmp;

	return ret;
}

int rrr_test_fork_executable (const char *fork_executable) {
	TEST_MSG("Running executable %s in fork\n", fork_executable);
	// This function does not return unless there is an error
	if (execl(fork_executable, fork_executable, (char *) NULL) == -1) {
		TEST_MSG("Failed to execute %s: %s\n", fork_executable, rrr_strerror(errno));
	}
	return 1;
}

struct main_loop_event_callback_data {
	struct rrr_instance_collection *instances;
	struct rrr_fork_handler *fork_handler;
};

static int rrr_test_main_loop_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct main_loop_event_callback_data *callback_data = arg;

	if (!main_running) {
		return RRR_EVENT_EXIT;
	}

	if (some_fork_has_stopped) {
		return RRR_EVENT_ERR;
	}

	if (rrr_instance_check_threads_stopped(callback_data->instances)) {
		return RRR_EVENT_EXIT;
	}

	rrr_fork_handle_sigchld_and_notify_if_needed (callback_data->fork_handler, 0);

	if (sigusr2) {
		RRR_MSG_0("Received SIGUSR2, but this is not implemented in the test suite\n");
		sigusr2 = 0;
	}

	return RRR_EVENT_OK;
}

static int rrr_test_main_loop (
		const char *config_file,
		struct rrr_fork_handler *fork_handler,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats_engine,
		struct rrr_message_broker *message_broker,
		int single_thread
) {
	int ret = 0;

	struct rrr_instance_collection instances = {0};
	struct rrr_thread_collection *collection;
	struct rrr_instance_config_collection *config;
	struct rrr_event_queue *queue;
	rrr_event_receiver_handle queue_handle;

	struct main_loop_event_callback_data callback_data = {
		&instances,
		fork_handler
	};

	if ((ret = rrr_instance_config_parse_file(&config, config_file)) != 0 || config == NULL) {
		goto out;
	}

	if ((ret = rrr_instances_create_from_config (
			&instances,
			config,
			library_paths,
			cmd_exists(cmd, "single-thread", 0)
				? RRR_INSTANCE_MISC_OPTIONS_DISABLE_BUFFER
				: 0
	)) != 0) {
		goto out_cleanup_config;
	}

	if ((ret = rrr_event_queue_new (
			&queue, 
			rrr_instance_event_receiver_count_get(&instances) + 1
	)) != 0) {
		goto out_cleanup_instances;
	}

	if ((ret = rrr_event_receiver_new (
			&queue_handle,
			queue,
			config_file,
			&callback_data
	)) != 0) {
		goto out_destroy_events;
	}

	if ((ret = rrr_event_function_periodic_set (
			queue,
			queue_handle,
			250 * 1000, // 250 ms
			rrr_test_main_loop_periodic
	)) != 0) {
		goto out_destroy_events;
	}

	if (single_thread) {
		if ((ret = rrr_instance_collection_run (
				&instances,
				config,
				cmd,
				queue,
				stats_engine,
				message_broker,
				fork_handler,
				&encourage_stop
		)) != 0) {
			goto out_destroy_events;
		}
	}
	else {
		if ((ret = rrr_instances_create_and_start_threads (
				&collection,
				&instances,
				config,
				cmd,
				stats_engine,
				message_broker,
				fork_handler,
				&encourage_stop
		)) != 0) {
			goto out_destroy_events;
		}

		if ((ret = rrr_event_dispatch(queue)) != 0) {
			goto out_destroy_events;
		}

		int ghost_count = 0;
		rrr_thread_collection_destroy(&ghost_count, collection);
		if (ghost_count > 0) {
			RRR_MSG_0("%i threads were ghost during cleanup\n", ghost_count);
		}
	}

	ret = main_get_test_result(&instances);

	out_destroy_events:
		rrr_event_queue_destroy(queue);
	out_cleanup_instances:
		rrr_instance_collection_clear(&instances);

		// Don't unload modules in the test suite
		// rrr_instance_unload_all(instances);
	out_cleanup_config:
		rrr_instance_config_collection_destroy(config);
	out:
		return ret;
}

int main (int argc, const char *argv[], const char *env[]) {
	struct rrr_signal_handler *signal_handler_fork = NULL;
	struct rrr_signal_handler *signal_handler_interrupt = NULL;

	int ret = 0;

	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_final;
	}
	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_setproctitle_init(argc, argv, env);
	rrr_setproctitle("[main]");
	rrr_strerror_init();

	struct rrr_stats_engine stats_engine = {0};
	struct rrr_fork_handler *fork_handler = NULL;
	struct rrr_event_queue *event_queue = NULL;
	struct rrr_message_broker *message_broker = NULL;
	struct rrr_fork_default_exit_notification_data exit_notification_data = {
		&some_fork_has_stopped
	};
	int is_child = 0;

	struct cmd_data cmd;
	const char *config_file, *fork_executable;
	cmd_init(&cmd, cmd_rules, argc, argv);

	signal_handler_fork = rrr_signal_handler_push(rrr_fork_signal_handler, NULL);
	signal_handler_interrupt = rrr_signal_handler_push(rrr_signal_handler, NULL);

	rrr_signal_default_signal_actions_register();

	if (rrr_message_broker_new(&message_broker, NULL) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_signal;
	}

	if (rrr_fork_handler_new (&fork_handler) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_message_broker;
	}

	// Set receiver count higher if needed by tests
	if (rrr_event_queue_new (&event_queue, 2) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_fork_handler;
	}

	TEST_MSG("Starting test with module path %s\n", RRR_MODULE_PATH);
	TEST_MSG("Change to directory %s\n", RRR_TEST_PATH);

	if (chdir(RRR_TEST_PATH) != 0) {
		TEST_MSG("Error while changing directory\n");
		ret = 1;
		goto out_cleanup_event_queue;
	}

	struct sigaction action;
	action.sa_handler = rrr_signal;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	sigaction (SIGTERM, &action, NULL);
	sigaction (SIGINT, &action, NULL);
	sigaction (SIGUSR1, &action, NULL);

	rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);

	if ((ret = rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out_cleanup_cmd;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 2) != 0) {
		goto out_cleanup_cmd;
	}

	RRR_DBG_1("RRR test debuglevel is: %u\n", RRR_DEBUGLEVEL);

	if (cmd_exists(&cmd, "library-tests", 0)) {
		TEST_MSG("Library tests requested by argument, doing that now.\n");
		ret = rrr_test_library_functions(&main_running, fork_handler, event_queue);
		goto out_cleanup_cmd;
	}

	if ((config_file = cmd_get_value(&cmd, "config", 0)) == NULL) {
		RRR_MSG_0("No configuration file specified for test program\n");
		ret = 1;
		goto out_cleanup_cmd;
	}

	if ((fork_executable = cmd_get_value(&cmd, "fork-executable", 0)) != NULL) {
		pid_t pid = -1;
		TEST_MSG("forking and running external executable\n");
		pid = rrr_fork (
				fork_handler,
				rrr_fork_default_exit_notification,
				&exit_notification_data
		);
		if (pid == 0) {
			is_child = 1;
			ret = rrr_test_fork_executable(fork_executable);
			TEST_MSG("Child fork did not execute external program, waiting to be signalled to stop\n");
			while (main_running) {
				rrr_posix_usleep(50000);
				rrr_fork_handle_sigchld_and_notify_if_needed (fork_handler, 0);
			}
			goto out_cleanup_cmd;
		}
		if (pid < 0) {
			TEST_MSG("Error while forking: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_cleanup_cmd;
		}
	}

	TEST_BEGIN(config_file) {
		if ((ret = rrr_test_main_loop (
				config_file,
				fork_handler,
				&cmd,
				&stats_engine,
				message_broker,
				cmd_exists(&cmd, "single-thread", 0)

		)) != 0) {
			goto out_cleanup_cmd;
		}

#ifdef RRR_TEST_DELAYED_EXIT
		rrr_posix_usleep (3600000000); // 3600 seconds
#endif
	} TEST_RESULT(ret == 0);

	goto out_cleanup_cmd;

	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

	out_cleanup_event_queue:
		rrr_event_queue_destroy(event_queue);

	out_cleanup_fork_handler:
		if (is_child) {
			// Only main runs fork cleanup stuff
			goto out_cleanup_signal;
		}
		rrr_fork_send_sigusr1_and_wait(fork_handler);
		rrr_fork_handle_sigchld_and_notify_if_needed(fork_handler, 1);
		rrr_fork_handler_destroy (fork_handler);

	out_cleanup_message_broker:
		rrr_message_broker_destroy(message_broker);

	out_cleanup_signal:
		rrr_signal_handler_remove(signal_handler_interrupt);
		rrr_signal_handler_remove(signal_handler_fork);
		rrr_exit_cleanup_methods_run_and_free();
		rrr_strerror_cleanup();
		rrr_log_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_final:
		return ret;
}
