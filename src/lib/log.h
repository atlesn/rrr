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

#ifndef RRR_LOG_H
#define RRR_LOG_H

#include <stdio.h>

#include "../global.h"

/*
 * About debug levels, ORed together:
 * 0 - Only errors are printed. Critical errors to STDERR, other errors to STDOUT.
 * 1 - Info about loading and closing of modules and threads. Detailed errors about incorrect data from outside. (low rate)
 * 2 - Runtime information in modules, they tell what they do. Log messages between modules. (high rate)
 * 3 - Some data debugging is printed (high rate)
 * 4 - Debug locking, thread states and buffers (very high rate)
 * 5 - Alive-messages from some threads to see if they freeze (very high rate)
 * 6 - Debug hex prints (large outputs)
 * 7 - Debug sockets (high rate at initialization)
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

#define __RRR_LOG_PREFIX_0	0
#define __RRR_LOG_PREFIX_1	1
#define __RRR_LOG_PREFIX_2	2
#define __RRR_LOG_PREFIX_3	3
#define __RRR_LOG_PREFIX_4	4
#define __RRR_LOG_PREFIX_5	5
#define __RRR_LOG_PREFIX_6	6
#define __RRR_LOG_PREFIX_7	7

#define RRR_DEBUGLEVEL_OK(x) \
	(x >= __RRR_LOG_PREFIX_0 && x <= __RRR_LOG_PREFIX_7)

// Unchecked operation, should not cause dangerous situations.
// Caller should nevertheless use RRR_DEBUGLEVEL_OK macro first.
#define RRR_DEBUGLEVEL_NUM_TO_FLAG(x) \
	(x == 0 ? 0 : 1 << (x-1))

#define RRR_MSG_PLAIN(...) \
	do {rrr_log_printf_plain (__VA_ARGS__);}while(0)

// Non-critical errors always to be logged
#define RRR_MSG_0(...) \
	do {rrr_log_printf (__RRR_LOG_PREFIX_0, rrr_global_config.log_prefix, __VA_ARGS__);}while(0)

#define RRR_MSG_1(...) \
	do { rrr_log_printf (__RRR_LOG_PREFIX_1, rrr_global_config.log_prefix, __VA_ARGS__); } while(0)

#define RRR_MSG_2(...) \
	do { rrr_log_printf (__RRR_LOG_PREFIX_2, rrr_global_config.log_prefix, __VA_ARGS__); } while(0)

#define RRR_MSG_3(...) \
	do { rrr_log_printf (__RRR_LOG_PREFIX_3, rrr_global_config.log_prefix, __VA_ARGS__); } while(0)

// Critical errors, use only if program, fork or thread exits due to an error
// This should not be used by the library, only by modules and executables
#define RRR_MSG_ERR(...) \
	do {rrr_log_fprintf (stderr, __RRR_LOG_PREFIX_0, rrr_global_config.log_prefix, __VA_ARGS__);}while(0)

// Debug without holding the lock
#define RRR_DBG_SIGNAL(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_1) != 0) { rrr_log_printf_nolock (__RRR_LOG_PREFIX_1, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

// Zero may be passed to X functions
#define RRR_MSG_X(debuglevel_num, ...)													\
	do {																				\
		rrr_log_printf (debuglevel_num, rrr_global_config.log_prefix, __VA_ARGS__);		\
	} while (0)

#define RRR_DBG_X(debuglevel_num, ...)																										\
	do { if ((rrr_global_config.debuglevel & RRR_DEBUGLEVEL_NUM_TO_FLAG(debuglevel_num)) == RRR_DEBUGLEVEL_NUM_TO_FLAG(debuglevel_num)) {	\
		rrr_log_printf (debuglevel_num, rrr_global_config.log_prefix, __VA_ARGS__);															\
	}} while(0)

#define RRR_DBG_1(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_1) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_1, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG_2(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_2) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_2, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG_3(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_3) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_3, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG_4(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_4) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_4, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG_5(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_5) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_5, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG_6(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_6) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_6, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG_7(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_7) != 0) { rrr_log_printf (__RRR_LOG_PREFIX_7, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

#define RRR_DBG(...) \
	do { rrr_log_printf (__RRR_LOG_PREFIX_0, rrr_global_config.log_prefix, __VA_ARGS__); } while(0)

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

#define RRR_RFC5424_LOGLEVEL_EMERGENCY	0
#define RRR_RFC5424_LOGLEVEL_ALERT		1
#define RRR_RFC5424_LOGLEVEL_CRITICAL	2
#define RRR_RFC5424_LOGLEVEL_ERROR		3
#define RRR_RFC5424_LOGLEVEL_WARNING	4
#define RRR_RFC5424_LOGLEVEL_NOTICE		5
#define RRR_RFC5424_LOGLEVEL_INFO		6
#define RRR_RFC5424_LOGLEVEL_DEBUG		7

// While writing code, use this macro to detect for instance invalid arguments to a function
// which caller should have checked as opposed to letting the program crash ungracefully
#define RRR_BUG(...) \
	do { RRR_MSG_ERR(__VA_ARGS__); abort(); } while (0)

#define RRR_LOG_HEADER_FORMAT "<%u> <%s> "

#define RRR_LOG_HOOK_MSG_MAX_SIZE 512

void rrr_log_hook_register (
		int *handle,
		void (*log)(
				unsigned short loglevel_translated,
				const char *prefix,
				const char *message,
				void *private_arg
		),
		void *private_arg
);
void rrr_log_hook_unregister (
		int handle
);

void rrr_log_printf_nolock (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...);
void rrr_log_printf_plain (const char *__restrict __format, ...);
void rrr_log_printf (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...);
void rrr_log_fprintf (FILE *file, unsigned short loglevel, const char *prefix, const char *__restrict __format, ...);

#endif /* RRR_LOG_H */
