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

#ifndef RRR_GLOBAL_H
#define RRR_GLOBAL_H

#include <pthread.h>

/* Compile time checks */
#define RRR_ASSERT_DEBUG
#ifdef RRR_ASSERT_DEBUG
#define RRR_ASSERT(predicate,name) \
	do{char _assertion_failed_##name##_[2*!!(predicate)-1];_assertion_failed_##name##_[0]='\0';(void)(_assertion_failed_##name##_);}while(0);
#else
#define RRR_ASSERT(predicate,name)
#endif

#define RRR_FREE_IF_NOT_NULL(arg) do{if(arg != NULL){free(arg);arg=NULL;}}while(0)


#define RRR_GLOBAL_SET_LOG_PREFIX(str) \
	const char *rrr_default_log_prefix = str

// Must be initialized in main c-file using the macro
extern const char *rrr_default_log_prefix;

struct cmd_data;

/* Runtime globals */
struct rrr_global_config {
	unsigned int debuglevel;
	unsigned int debuglevel_on_exit;
	unsigned int debuglevel_orig;
	unsigned int no_watchdog_timers;
	unsigned int no_thread_restart;
	const char *log_prefix;
};

extern struct rrr_global_config rrr_global_config;
extern pthread_mutex_t global_config_mutex;

void rrr_set_debuglevel_orig(void);
void rrr_set_debuglevel_on_exit(void);
void rrr_init_global_config (
		unsigned int debuglevel,
		unsigned int debuglevel_on_exit,
		unsigned int no_watcdog_timers,
		unsigned int no_thread_restart
);
void rrr_global_config_set_log_prefix (
		const char *log_prefix
);
int rrr_print_help_and_version (
		struct cmd_data *cmd,
		int argc_minimum
);

#endif
