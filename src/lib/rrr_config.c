/*

Read Route Record

Copyright (C) 2018-2022 Atle Solbakken atle@goliathdns.no

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

#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cmdlineparser/cmdline.h"
#include "rrr_config.h"

pthread_mutex_t rrr_config_global_mutex = PTHREAD_MUTEX_INITIALIZER;

struct rrr_global_config rrr_config_global = {
		.debuglevel = 0,
		.debuglevel_on_exit = 0,
		.start_interval = 0,
		.debuglevel_orig = 0,
		.no_watchdog_timers = 0,
		.no_thread_restart = 0,
		.rfc5424_loglevel_output = 0,
		.output_buffer_warn_limit = 0,
		.do_journald_output = 0,
		.log_prefix = "main",
		.run_directory = RRR_RUN_DIR
};

void rrr_config_set_debuglevel_on_exit(void) {
	pthread_mutex_lock(&rrr_config_global_mutex);
	if (rrr_config_global.debuglevel_on_exit > 0) {
		rrr_config_global.debuglevel = rrr_config_global.debuglevel_on_exit;
	}
	pthread_mutex_unlock(&rrr_config_global_mutex);
}

void rrr_config_set_debuglevel_orig(void) {
	pthread_mutex_lock(&rrr_config_global_mutex);
	rrr_config_global.debuglevel = rrr_config_global.debuglevel_orig;
	pthread_mutex_unlock(&rrr_config_global_mutex);
}

void rrr_config_init (
		unsigned int debuglevel,
		unsigned int debuglevel_on_exit,
		unsigned int start_interval,
		unsigned int no_watcdog_timers,
		unsigned int no_thread_restart,
		unsigned int rfc5424_loglevel_output,
		unsigned int output_buffer_warn_limit,
		unsigned int do_journald_output,
		const char *run_directory
) {
	pthread_mutex_lock(&rrr_config_global_mutex);
	rrr_config_global.debuglevel = debuglevel;
	rrr_config_global.debuglevel_orig = debuglevel;
	rrr_config_global.debuglevel_on_exit = debuglevel_on_exit;
	rrr_config_global.start_interval = start_interval;
	rrr_config_global.no_watchdog_timers = no_watcdog_timers;
	rrr_config_global.no_thread_restart = no_thread_restart;
	rrr_config_global.rfc5424_loglevel_output = rfc5424_loglevel_output;
	rrr_config_global.output_buffer_warn_limit = output_buffer_warn_limit;
	rrr_config_global.log_prefix = rrr_default_log_prefix;
	rrr_config_global.do_journald_output = do_journald_output;
	rrr_config_global.run_directory = run_directory;
	pthread_mutex_unlock(&rrr_config_global_mutex);
}

// Usually done per fork
void rrr_config_set_log_prefix (
		const char *log_prefix
) {
	pthread_mutex_lock(&rrr_config_global_mutex);
	rrr_config_global.log_prefix = log_prefix;
	pthread_mutex_unlock(&rrr_config_global_mutex);
}
