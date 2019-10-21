/*

Read Route Record

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#ifndef VL_GLOBAL_H
#define VL_GLOBAL_H

#define VL_UNUSED(x) \
	((void)(x))

/* Compile time checks */
#define VL_ASSERT_DEBUG
#ifdef VL_ASSERT_DEBUG
#define VL_ASSERT(predicate,name) \
	do{char _assertion_failed_##name##_[2*!!(predicate)-1];_assertion_failed_##name##_[0]='\0';VL_UNUSED(_assertion_failed_##name##_);}while(0);
#else
#define VL_ASSERT(predicate,name)
#endif

extern pthread_mutex_t global_config_mutex;

/* Runtime globals */
struct rrr_global_config {
	unsigned int debuglevel;
	unsigned int debuglevel_on_exit;
	unsigned int debuglevel_orig;
	unsigned int no_watchdog_timers;
	unsigned int no_thread_restart;
};

extern struct rrr_global_config rrr_global_config;

/*
 * About debug levels, ORed together:
 * 0 - Only errors are printed
 * 1 - Info about loading and closing of modules and threads (low rate)
 * 2 - Runtime information in modules, they tell what they do at (high rate)
 * 3 - Some data debugging is printed (high rate)
 * 4 - Debug locking, thread states and buffers (very high rate)
 * 5 - Alive-messages from some threads to see if they freeze (very high rate)
 * 6 - Debug hex prints (large outputs)
 * 7 - Debug socket closing and opening (high rate at initialization)
 */

#define __VL_DEBUGLEVEL_0	(0)		// 0 - 0
#define __VL_DEBUGLEVEL_1	(1<<0)	// 1 - 1
#define __VL_DEBUGLEVEL_2	(1<<1)	// 2 - 2
#define __VL_DEBUGLEVEL_3	(1<<2)	// 3 - 4
#define __VL_DEBUGLEVEL_4	(1<<3)	// 4 - 8
#define __VL_DEBUGLEVEL_5	(1<<4)	// 5 - 16
#define __VL_DEBUGLEVEL_6	(1<<5)	// 6 - 32
#define __VL_DEBUGLEVEL_7	(1<<6)	// 7 - 64
#define __VL_DEBUGLEVEL_ALL	(__VL_DEBUGLEVEL_1|__VL_DEBUGLEVEL_2|__VL_DEBUGLEVEL_3|__VL_DEBUGLEVEL_4| \
		__VL_DEBUGLEVEL_5|__VL_DEBUGLEVEL_6|__VL_DEBUGLEVEL_7)

#define VL_MSG(...) \
	do {printf (__VA_ARGS__);}while(0)

#define VL_MSG_ERR(...) \
	do {fprintf (stderr, __VA_ARGS__);}while(0)

#define VL_DEBUG_MSG_1(...) \
	do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_1) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG_2(...) \
		do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_2) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG_3(...) \
		do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_3) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG_4(...) \
		do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_4) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG_5(...) \
		do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_5) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG_6(...) \
		do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_6) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG_7(...) \
		do { if ((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_7) != 0) { printf (__VA_ARGS__); }} while(0)

#define VL_DEBUG_MSG(...) \
	do { printf (__VA_ARGS__); } while(0)

#define VL_DEBUGLEVEL_1 \
	((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_1) != 0)

#define VL_DEBUGLEVEL_2 \
		((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_2) != 0)

#define VL_DEBUGLEVEL_3 \
		((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_3) != 0)

#define VL_DEBUGLEVEL_4 \
		((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_4) != 0)

#define VL_DEBUGLEVEL_5 \
		((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_5) != 0)

#define VL_DEBUGLEVEL_6 \
		((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_6) != 0)

#define VL_DEBUGLEVEL_7 \
		((rrr_global_config.debuglevel & __VL_DEBUGLEVEL_7) != 0)

#define VL_DEBUGLEVEL \
		(rrr_global_config.debuglevel)

#define VL_BUG(...) \
	do { VL_MSG_ERR(__VA_ARGS__); abort(); } while (0)

#define RRR_FREE_IF_NOT_NULL(arg) do{if(arg != NULL){free(arg);arg=NULL;}}while(0)


/* Common structures */
#if UCHAR_MAX == 0xff
typedef unsigned char vl_u8;
#endif

#if USHRT_MAX == 0xffff
typedef unsigned short vl_u16;
#endif

#if UINT_MAX == 0xffffffff
typedef unsigned int vl_u32;
#define RRR_SOCKET_32_IS_UINT 1
#elif ULONG_MAX == 0xffffffff
typedef unsigned long int vl_u32;
#define RRR_SOCKET_32_IS_LONG 1
#endif

#if ULONG_MAX == 0xffffffffffffffff
typedef unsigned long int vl_u64;
#define RRR_SOCKET_64_IS_LONG 1
#elif ULLONG_MAX == 0xffffffffffffffff
typedef unsigned long long int vl_u64;
#define RRR_SOCKET_64_IS_LONG_LONG
#endif

struct cmd_data;

void rrr_set_debuglevel_orig(void);
void rrr_set_debuglevel_on_exit(void);
void rrr_init_global_config (
		unsigned int debuglevel,
		unsigned int debuglevel_on_exit,
		unsigned int no_watcdog_timers,
		unsigned int no_thread_restart
);
int rrr_print_help_and_version (
		struct cmd_data *cmd
);

#endif
