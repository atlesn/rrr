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

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#ifndef RRR_GLOBAL_H
#define RRR_GLOBAL_H

/* Compile time checks */
#define RRR_ASSERT_DEBUG
#ifdef RRR_ASSERT_DEBUG
#define RRR_ASSERT(predicate,name) \
	do{char _assertion_failed_##name##_[2*!!(predicate)-1];_assertion_failed_##name##_[0]='\0';(void)(_assertion_failed_##name##_);}while(0);
#else
#define RRR_ASSERT(predicate,name)
#endif

extern pthread_mutex_t global_config_mutex;

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

/* Common structures */
#if UCHAR_MAX == 0xff
typedef unsigned char rrr_u8;
#endif

#if USHRT_MAX == 0xffff
typedef unsigned short rrr_u16;
#endif

#if UINT_MAX == 4294967295UL
typedef unsigned int rrr_u32;
#define RRR_SOCKET_32_IS_UINT 1
#elif ULONG_MAX == 4294967295UL
typedef unsigned long int rrr_u32;
#define RRR_SOCKET_32_IS_LONG 1
#endif

#if ULONG_MAX == 18446744073709551615ULL
typedef unsigned long int rrr_u64;
#define RRR_SOCKET_64_IS_LONG 1
#elif ULLONG_MAX == 18446744073709551615ULL
typedef unsigned long long int rrr_u64;
#define RRR_SOCKET_64_IS_LONG_LONG 1
#endif

#ifdef RRR_SOCKET_32_IS_UINT
    typedef unsigned int rrr_u32;
#elif defined (RRR_SOCKET_32_IS_LONG)
    typedef unsigned long int rrr_u32;
#else
#  error "Could not get size of 32 bit unsigned integer"
#endif

#ifdef RRR_SOCKET_64_IS_LONG
    typedef unsigned long int rrr_u64;
#elif defined (RRR_SOCKET_64_IS_LONG_LONG)
    typedef unsigned long long int rrr_u64;
#else
#  error "Could not get size of 64 bit unsigned integer"
#endif

#define RRR_FREE_IF_NOT_NULL(arg) do{if(arg != NULL){free(arg);arg=NULL;}}while(0)

struct cmd_data;

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
