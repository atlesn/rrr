/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>

#include "main.h"
#include "lib/log.h"
#include "lib/common.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/threads.h"
#include "lib/environment_file.h"
#include "lib/map.h"
#include "lib/rrr_strerror.h"

#define RRR_MAIN_DEFAULT_THREAD_WATCHDOG_TIMER_MS 5000

struct rrr_main_check_wait_for_data {
	struct rrr_instance_collection *instances;
};

static int __rrr_main_start_threads_check_wait_for_callback (int *do_start, struct rrr_thread *thread, void *arg) {
	struct rrr_main_check_wait_for_data *data = arg;
	struct rrr_instance *instance = rrr_instance_find_by_thread(data->instances, thread);

	if (instance == NULL) {
		RRR_BUG("Instance not found in __main_start_threads_check_wait_for_callback\n");
	}

	*do_start = 1;

	// TODO : Check for wait_for loops in configuration

	RRR_LL_ITERATE_BEGIN(&instance->wait_for, struct rrr_instance_friend);
		struct rrr_instance *check = node->instance;
		if (check == instance) {
			RRR_MSG_0("Instance %s was set up to wait for itself before starting with wait_for, this is an error.\n",
					INSTANCE_M_NAME(instance));
			return 1;
		}

		if (	rrr_thread_state_get(check->thread) == RRR_THREAD_STATE_RUNNING_FORKED ||
				rrr_thread_state_get(check->thread) == RRR_THREAD_STATE_STOPPED
		) {
			// OK
		}
		else {
			RRR_DBG_1 ("Instance %s waiting for instance %s to start\n",
					INSTANCE_M_NAME(instance), INSTANCE_M_NAME(check));
			*do_start = 0;
		}
	RRR_LL_ITERATE_END();

	return 0;
}

// This function allocates runtime data and thread data.
// - runtime data is ALWAYS destroyed by the thread. If a thread does not
//   start, we must BUG() out
// - thread data is freed by main unless thread has become ghost in which the
//   thread will free it if it wakes up

int rrr_main_create_and_start_threads (
		struct rrr_thread_collection **thread_collection,
		struct rrr_instance_collection *instances,
		struct rrr_config *global_config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
) {
	int ret = 0;

	struct rrr_instance_runtime_data **runtime_data = NULL;

	if (RRR_LL_COUNT(instances) == 0) {
		RRR_MSG_0("No instances started, exiting\n");
		ret = 1;
		goto out;
	}

	runtime_data = malloc(sizeof(*runtime_data) * RRR_LL_COUNT(instances)); // Size of pointer

	// Create thread collection
	if (rrr_thread_collection_new (thread_collection) != 0) {
		RRR_MSG_0("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	// Initialize thread data and runtime data
	int threads_total = 0;
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;

		if (instance->module_data == NULL) {
			RRR_BUG("BUG: Dynamic data was NULL in rrr_main_create_and_start_threads\n");
		}

		struct rrr_instance_runtime_init_data init_data;
		init_data.module = instance->module_data;
		init_data.senders = &instance->senders;
		init_data.cmd_data = cmd;
		init_data.global_config = global_config;
		init_data.instance_config = instance->config;
		init_data.stats = stats;
		init_data.message_broker = message_broker;
		init_data.fork_handler = fork_handler;
		init_data.topic_first_token = instance->topic_first_token;
		init_data.topic_str = instance->topic_filter;
		init_data.instance = instance;

		RRR_DBG_1("Initializing instance %p '%s'\n", instance, instance->config->name);

		if ((runtime_data[threads_total] = rrr_instance_runtime_data_new(&init_data)) == NULL) {
			RRR_BUG("Error while creating runtime data for instance %s, can't proceed\n",
					INSTANCE_M_NAME(instance));
		}

		struct rrr_thread *thread = rrr_thread_collection_thread_allocate_preload_and_register (
				*thread_collection,
				rrr_instance_thread_entry_intermediate,
				instance->module_data->operations.preload,
				instance->module_data->operations.poststop,
				instance->module_data->operations.cancel_function,
				instance->module_data->instance_name,
				RRR_MAIN_DEFAULT_THREAD_WATCHDOG_TIMER_MS * 1000,
				runtime_data[threads_total]
		);

		if (thread == NULL) {
			// This might actually not be a bug but we cannot recover from preload failure
			RRR_BUG("Error while preloading thread for instance %s, can't proceed\n",
					instance->module_data->instance_name);
		}

		// Set shortcuts
		node->thread = thread;

		threads_total++;
	RRR_LL_ITERATE_END();

	for (int i = 0; i < threads_total; i++) {
		RRR_DBG_1 ("Starting thread %s\n", INSTANCE_M_NAME(runtime_data[i]->init_data.instance));
		if (rrr_thread_start(INSTANCE_M_THREAD(runtime_data[i]->init_data.instance)) != 0) {
			RRR_BUG ("Error while starting thread for instance %s, can't proceed\n",
					INSTANCE_M_NAME(runtime_data[i]->init_data.instance));
		}
	}

	struct rrr_main_check_wait_for_data callback_data = { instances };

	if (rrr_thread_collection_start_all_after_initialized (
			*thread_collection,
			__rrr_main_start_threads_check_wait_for_callback,
			&callback_data
	) != 0) {
		RRR_MSG_0("Error while waiting for threads to initialize\n");
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(runtime_data);
	return ret;
}

void rrr_main_threads_stop_and_destroy (struct rrr_thread_collection *collection) {
	rrr_thread_collection_stop_and_join_all_no_unlock(collection);
	rrr_thread_collection_destroy (collection);
}

#ifdef HAVE_JOURNALD
// Append = to var to avoid partial match being tolerated. Value may be added after = to match this as well.
static int __rrr_main_has_env (const char **env, const char *var) {
	for (const char **pos = env; *pos != NULL; pos++) {
		if (strncmp(*pos, var, strlen(var)) == 0) {
			return 1;
		}
	}
	return 0;
}

static int __rrr_main_check_do_journald_logging (const char **env) {
	// Check if inode of stderr matches the one in JOURNAL_STREAM (and if the variable exists)
	struct stat stat;
	if (fstat(fileno(stderr), &stat) != 0) {
		RRR_MSG_0("Warning: fstat of stderr failed in __rrr_main_check_do_journald_logging, disabling journald output\n");
		return 0;
	}

	// Type inside of struct may vary (long or long long)
	unsigned long long int dev = stat.st_dev;
	unsigned long long int ino = stat.st_ino;

	char buf[128];
	snprintf(buf, 128, "JOURNAL_STREAM=%llu:%llu", dev, ino);
	buf[127] = '\0';

	int result = __rrr_main_has_env(env, buf);
	return result;
}
#endif

#define SETENV_STR(name, var)																					\
	do { if (setenv(name, var, 1) != 0) {																		\
		RRR_MSG_0("Failed to set environment variable %s in rrr_main_parse_cmd_arguments_and_env\n", name);		\
		ret = EXIT_FAILURE;																						\
		goto out;																								\
	}} while(0)

#define SETENV(name, type, var)							\
	do { char buf[128]; sprintf(buf, type, var);		\
		SETENV_STR(name, buf);							\
	} while(0)

#define GETENV_YESNO(name, target)													\
	do { char *env; if ((env = getenv(name)) != 0) {								\
		target = (strcasecmp(env, "no") != 0 && strcasecmp(env, "0") != 0) ? 1 : 0;	\
	}} while(0)

#define GETENV_U(name, target)														\
	do { char *env; if ((env = getenv(name)) != 0) {								\
		char *endptr; errno = 0; target = strtoul(env, &endptr, 10);							\
		if (*env != '\0' && (errno != 0 || *endptr != '\0')) {						\
			RRR_MSG_0("Invalid value '%s' in environment variable " name ": %s\n", env, rrr_strerror(errno));\
			ret = EXIT_FAILURE; goto out;											\
		}																			\
	}} while(0)

int rrr_main_parse_cmd_arguments_and_env (struct cmd_data *cmd, const char **env, cmd_conf config) {
	int ret = EXIT_SUCCESS;

	struct rrr_map environment_map = {0};

	unsigned int debuglevel = 0;
	unsigned int debuglevel_on_exit = 0;
	unsigned int no_watchdog_timers = 0;
	unsigned int no_thread_restart = 0;
	unsigned int rfc5424_loglevel_output = 0;

	if (cmd_parse(cmd, config) != 0) {
		RRR_MSG_0("Error while parsing command line\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	const char *environment_file = cmd_get_value(cmd, "environment-file", 0);
	if (environment_file != NULL) {
		if (rrr_environment_file_parse(&environment_map, environment_file) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	RRR_MAP_ITERATE_BEGIN(&environment_map);
		SETENV_STR(node_tag, node_value);
	RRR_MAP_ITERATE_END();

	GETENV_U(RRR_ENV_DEBUGLEVEL, debuglevel);
	GETENV_U(RRR_ENV_DEBUGLEVEL_ON_EXIT, debuglevel_on_exit);
	GETENV_YESNO(RRR_ENV_NO_WATCHDOG_TIMERS, no_watchdog_timers);
	GETENV_YESNO(RRR_ENV_NO_THREAD_RESTART, no_thread_restart);
	GETENV_YESNO(RRR_ENV_LOGLEVEL_TRANSLATION, rfc5424_loglevel_output);

	const char *debuglevel_string = cmd_get_value(cmd, "debuglevel", 0);
	if (debuglevel_string != NULL) {
		int debuglevel_tmp;
		if (strcmp(debuglevel_string, "all") == 0) {
			debuglevel_tmp = __RRR_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_string, &debuglevel_tmp) != 0) {
			RRR_MSG_0(
					"Could not understand debuglevel argument '%s', use a number or 'all'\n",
					debuglevel_string);
			ret = EXIT_FAILURE;
			goto out;
		}
		if (debuglevel_tmp < 0 || debuglevel_tmp > __RRR_DEBUGLEVEL_ALL) {
			RRR_MSG_0(
					"Debuglevel must be 0 <= debuglevel <= %i, %i was given.\n",
					__RRR_DEBUGLEVEL_ALL, debuglevel_tmp);
			ret = EXIT_FAILURE;
			goto out;
		}
		debuglevel = debuglevel_tmp;
	}

	const char *debuglevel_on_exit_string = cmd_get_value(cmd, "debuglevel-on-exit", 0);
	if (debuglevel_on_exit_string != NULL) {
		int debuglevel_on_exit_tmp;
		if (strcmp(debuglevel_on_exit_string, "all") == 0) {
			debuglevel_on_exit_tmp = __RRR_DEBUGLEVEL_ALL;
		}
		else if (cmd_convert_integer_10(debuglevel_on_exit_string, &debuglevel_on_exit_tmp) != 0) {
			RRR_MSG_0(
					"Could not understand debuglevel_on_exit argument '%s', use a number or 'all'\n",
					debuglevel_on_exit_string);
			ret = EXIT_FAILURE;
			goto out;
		}
		if (debuglevel_on_exit_tmp < 0 || debuglevel_on_exit_tmp > __RRR_DEBUGLEVEL_ALL) {
			RRR_MSG_0(
					"Debuglevel must be 0 <= debuglevel_on_exit <= %i, %i was given.\n",
					__RRR_DEBUGLEVEL_ALL, debuglevel_on_exit_tmp);
			ret = EXIT_FAILURE;
			goto out;
		}
		debuglevel_on_exit = debuglevel_on_exit_tmp;
	}

	if (cmd_exists(cmd, "no-watchdog-timers", 0)) {
		no_watchdog_timers = 1;
	}

	if (cmd_exists(cmd, "no-thread-restart", 0)) {
		no_thread_restart = 1;
	}

	if (cmd_exists(cmd, "loglevel-translation", 0)) {
		rfc5424_loglevel_output = 1;
	}

	SETENV(RRR_ENV_DEBUGLEVEL,				"%u",	debuglevel);
	SETENV(RRR_ENV_DEBUGLEVEL_ON_EXIT,		"%u",	debuglevel_on_exit);
	SETENV(RRR_ENV_NO_WATCHDOG_TIMERS,		"%u",	no_watchdog_timers);
	SETENV(RRR_ENV_NO_THREAD_RESTART,		"%u",	no_thread_restart);
	SETENV(RRR_ENV_LOGLEVEL_TRANSLATION,	"%u",	rfc5424_loglevel_output);

#ifdef HAVE_JOURNALD
	unsigned int do_journald_output = __rrr_main_check_do_journald_logging(env);
#else
	(void)(env);
	unsigned int do_journald_output = 0;
#endif

	rrr_config_init (
			debuglevel,
			debuglevel_on_exit,
			no_watchdog_timers,
			no_thread_restart,
			rfc5424_loglevel_output,
			do_journald_output
	);

	// DBG-macros must be used after global debuglevel has been set
	RRR_DBG_1("Global configuration: d:%u, doe:%u, nwt:%u, ntr:%u, lt:%u, jo:%u\n",
			debuglevel,
			debuglevel_on_exit,
			no_watchdog_timers,
			no_thread_restart,
			rfc5424_loglevel_output,
			do_journald_output
	);

#ifdef HAVE_JOURNALD
	RRR_DBG_1 ("Check for SystemD environment: %s\n",
		(do_journald_output ? "Found, using native journald logging" : "Not found, using stdout logging")
	);
#else
	(void)(do_journald_output);
#endif

	out:
	rrr_map_clear(&environment_map);
	return ret;
}

int rrr_main_print_help_and_version (
		struct cmd_data *cmd,
		int argc_minimum
) {
	int help_or_version_printed = 0;
	if (cmd_exists(cmd, "version", 0)) {
		RRR_MSG_0(PACKAGE_NAME " version " RRR_CONFIG_VERSION " build timestamp %li\n", RRR_BUILD_TIMESTAMP);
		help_or_version_printed = 1;
	}

	if ((cmd->argc < argc_minimum || strcmp(cmd->command, "help") == 0) || cmd_exists(cmd, "help", 0)) {
		cmd_print_usage(cmd);
		help_or_version_printed = 1;
	}

	if (help_or_version_printed) {
		return 1;
	}

	return 0;
}
