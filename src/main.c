/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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
#include "../config.h"
#include "lib/log.h"
#include "lib/allocator.h"
#include "lib/common.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/instances.h"
#include "lib/instance_config.h"
#include "lib/threads.h"
#include "lib/environment_file.h"
#include "lib/map.h"
#include "lib/rrr_strerror.h"

#define RRR_MAIN_DEFAULT_THREAD_WATCHDOG_TIMER_MS 5000

int rrr_main_create_and_start_threads (
		struct rrr_thread_collection **thread_collection_target,
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_collection *config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
) {
	return rrr_instances_create_and_start_threads (
			thread_collection_target,
			instances,
			config,
			cmd,
			stats,
			message_broker,
			fork_handler
	);
}

void rrr_main_threads_stop_and_destroy (struct rrr_thread_collection *collection) {
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

#define SETENV_STR(name, var)                                  \
    do { if (setenv(name, var, 1) != 0) {                      \
        RRR_MSG_0("Failed to set environment variable %s in rrr_main_parse_cmd_arguments_and_env\n", name); \
        ret = EXIT_FAILURE;                                    \
        goto out;                                              \
    }} while(0)                                                \

#define SETENV(name, type, var)                                \
    do { char buf[128]; sprintf(buf, type, var);               \
        SETENV_STR(name, buf);                                 \
    } while(0)                                                 \

#define GETENV_YESNO(name, target)                             \
    do { char *env; if ((env = getenv(name)) != 0) {           \
        target = (strcasecmp(env, "no") != 0 && strcasecmp(env, "0") != 0) ? 1 : 0; \
    }} while(0)                                                \

#define GETENV_U(name, target)                                 \
    do { char *env; if ((env = getenv(name)) != 0) {           \
        char *endptr; errno = 0; target = strtoul(env, &endptr, 10);   \
        if (*env != '\0' && (errno != 0 || *endptr != '\0')) {         \
            RRR_MSG_0("Invalid value '%s' in environment variable " name ": %s\n", env, rrr_strerror(errno)); \
            ret = EXIT_FAILURE; goto out;                      \
        }                                                      \
    }} while(0)                                                \

#define GETENV_STR(name, target)                               \
    do { char *env; if ((env = getenv(name)) != NULL) {        \
        target = env;                                          \
    }} while(0)                                                \

int rrr_main_parse_cmd_arguments_and_env (struct cmd_data *cmd, const char **env, cmd_conf config) {
	int ret = EXIT_SUCCESS;

	struct rrr_map environment_map = {0};

	unsigned long int debuglevel = 0;
	unsigned long int debuglevel_on_exit = 0;
	unsigned int no_watchdog_timers = 0;
	unsigned int no_thread_restart = 0;
	unsigned int rfc5424_loglevel_output = 0;
	const char *run_directory = NULL;

	const char *tmp;

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
	GETENV_STR(RRR_ENV_RUN_DIRECTORY, run_directory);

	const char *debuglevel_string = cmd_get_value(cmd, "debuglevel", 0);
	if (debuglevel_string != NULL) {
		long int debuglevel_tmp;
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
		debuglevel = (unsigned int) debuglevel_tmp;
	}

	const char *debuglevel_on_exit_string = cmd_get_value(cmd, "debuglevel-on-exit", 0);
	if (debuglevel_on_exit_string != NULL) {
		long int debuglevel_on_exit_tmp;
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
		debuglevel_on_exit = (unsigned int) debuglevel_on_exit_tmp;
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

	if ((tmp = cmd_get_value(cmd, "run-directory", 0)) != NULL) {
		run_directory = tmp;
	}

	if (run_directory == NULL) {
		run_directory = RRR_RUN_DIR;
	}

	if (debuglevel > UINT_MAX) {
		RRR_MSG_0("Invalid value %lu for debuglevel environment variable or argument\n", debuglevel);
		ret = 1;
		goto out;
	}

	if (debuglevel_on_exit > UINT_MAX) {
		RRR_MSG_0("Invalid value %lu for debuglevel on exit environment variable or argument\n", debuglevel_on_exit);
		ret = 1;
		goto out;
	}

	SETENV(RRR_ENV_DEBUGLEVEL,           "%u",    (unsigned int) debuglevel);
	SETENV(RRR_ENV_DEBUGLEVEL_ON_EXIT,   "%u",    (unsigned int) debuglevel_on_exit);
	SETENV(RRR_ENV_NO_WATCHDOG_TIMERS,   "%u",    no_watchdog_timers);
	SETENV(RRR_ENV_NO_THREAD_RESTART,    "%u",    no_thread_restart);
	SETENV(RRR_ENV_LOGLEVEL_TRANSLATION, "%u",    rfc5424_loglevel_output);
	SETENV_STR(RRR_ENV_RUN_DIRECTORY,    run_directory);

#ifdef HAVE_JOURNALD
	unsigned int do_journald_output = __rrr_main_check_do_journald_logging(env) != 0;
#else
	(void)(env);
	unsigned int do_journald_output = 0;
#endif

	rrr_config_init (
			(unsigned int) debuglevel,
			(unsigned int) debuglevel_on_exit,
			no_watchdog_timers,
			no_thread_restart,
			rfc5424_loglevel_output,
			do_journald_output,
			run_directory
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

static const char *rrr_main_banner =
		"======================================\n"
		"  =      RRRRRRRRRRR  RRRR  RRRR\n"
		"  =       RRRRRRRRRRR   RRR   RRR\n"
		"  =       RRR      RRR   RRR   RRR\n"
		"  =       RRR      RRR   RRR   RRR\n"
		"  =       RRRRRRRRRR  RRRR  RRRR\n"
		"  =       RRRRRRRRR  RRRR  RRRR\n"
		"  =       RRR    RRR   RRR   RRR\n"
		"  =       RRR     RRR   RRR   RRR\n"
		"  =       RRR      RRR   RRR   RRR\n"
		"  =      RRRR       RRRR   RRRR  RRRR\n"
		"================================================\n\n";

int rrr_main_print_banner_help_and_version (
		struct cmd_data *cmd,
		unsigned int argc_minimum
) {
	int help_or_version_printed = 0;

	if (cmd_exists(cmd, "banner", 0)) {
		RRR_MSG_PLAIN("%s", rrr_main_banner);
		argc_minimum++;
	}

	if (cmd_exists(cmd, "version", 0)) {
		RRR_MSG_0(PACKAGE_NAME " version " RRR_CONFIG_VERSION " build timestamp %li\n", RRR_BUILD_TIMESTAMP);
		help_or_version_printed = 1;
	}

	if ((cmd->argc < argc_minimum || strcmp(cmd->command, "help") == 0) || cmd_exists(cmd, "help", 0)) {
		cmd_print_usage(cmd);
		help_or_version_printed = 1;
	}

	return help_or_version_printed;
}
