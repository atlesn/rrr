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

#ifndef RRR_GLOBAL_H
#define RRR_GLOBAL_H

#define RRR_UNUSED(x) \
	((void)(x))

/* Compile time checks */
#define RRR_ASSERT_DEBUG
#ifdef RRR_ASSERT_DEBUG
#define RRR_ASSERT(predicate,name) \
	do{char _assertion_failed_##name##_[2*!!(predicate)-1];_assertion_failed_##name##_[0]='\0';RRR_UNUSED(_assertion_failed_##name##_);}while(0);
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

#define __RRR_DEBUGLEVEL_0	(0)		// 0 - 0
#define __RRR_DEBUGLEVEL_1	(1<<0)	// 1 - 1
#define __RRR_DEBUGLEVEL_2	(1<<1)	// 2 - 2
#define __RRR_DEBUGLEVEL_3	(1<<2)	// 3 - 4
#define __RRR_DEBUGLEVEL_4	(1<<3)	// 4 - 8
#define __RRR_DEBUGLEVEL_5	(1<<4)	// 5 - 16
#define __RRR_DEBUGLEVEL_6	(1<<5)	// 6 - 32
#define __RRR_DEBUGLEVEL_7	(1<<6)	// 7 - 64
#define __RRR_DEBUGLEVEL_ALL	(__RRR_DEBUGLEVEL_1|__RRR_DEBUGLEVEL_2|__RRR_DEBUGLEVEL_3|__RRR_DEBUGLEVEL_4| \
		__RRR_DEBUGLEVEL_5|__RRR_DEBUGLEVEL_6|__RRR_DEBUGLEVEL_7)

#define RRR_MSG(...) \
	do {printf (__VA_ARGS__);}while(0)

#define RRR_MSG_ERR(...) \
	do {fprintf (stderr, __VA_ARGS__);}while(0)

#define RRR_DBG_1(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_1) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG_2(...) \
		do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_2) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG_3(...) \
		do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_3) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG_4(...) \
		do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_4) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG_5(...) \
		do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_5) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG_6(...) \
		do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_6) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG_7(...) \
		do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_7) != 0) { printf (__VA_ARGS__); }} while(0)

#define RRR_DBG(...) \
	do { printf (__VA_ARGS__); } while(0)

#define RRR_DEBUGLEVEL_1 \
	((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_1) != 0)

#define RRR_DEBUGLEVEL_2 \
		((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_2) != 0)

#define RRR_DEBUGLEVEL_3 \
		((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_3) != 0)

#define RRR_DEBUGLEVEL_4 \
		((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_4) != 0)

#define RRR_DEBUGLEVEL_5 \
		((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_5) != 0)

#define RRR_DEBUGLEVEL_6 \
		((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_6) != 0)

#define RRR_DEBUGLEVEL_7 \
		((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_7) != 0)

#define RRR_DEBUGLEVEL \
		(rrr_global_config.debuglevel)

#define RRR_BUG(...) \
	do { RRR_MSG_ERR(__VA_ARGS__); abort(); } while (0)

#define RRR_FREE_IF_NOT_NULL(arg) do{if(arg != NULL){free(arg);arg=NULL;}}while(0)


/* Common structures */
#if UCHAR_MAX == 0xff
typedef unsigned char vl_u8;
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
