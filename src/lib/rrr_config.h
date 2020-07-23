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

#ifndef RRR_CONFIG_H
#define RRR_CONFIG_H

#include <pthread.h>

#define RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX(str) \
	const char *rrr_default_log_prefix = str

// Prefix must be initialized in main c-file using the macro
extern const char *rrr_default_log_prefix;

extern struct rrr_global_config rrr_config_global;

//extern pthread_mutex_t rrr_config_global_mutex;

/* Runtime globals */
struct rrr_global_config {
	unsigned int debuglevel;
	unsigned int debuglevel_on_exit;
	unsigned int debuglevel_orig;
	unsigned int no_watchdog_timers;
	unsigned int no_thread_restart;
	unsigned int rfc5424_loglevel_output;
	const char *log_prefix;
};

void rrr_config_set_debuglevel_orig(void);
void rrr_config_set_debuglevel_on_exit(void);
void rrr_config_init (
		unsigned int debuglevel,
		unsigned int debuglevel_on_exit,
		unsigned int no_watcdog_timers,
		unsigned int no_thread_restart,
		unsigned int rfc5424_loglevel_output
);
void rrr_config_set_log_prefix (
		const char *log_prefix
);

#endif /* RRR_CONFIG_H */
