/*

Read Route Record

Copyright (C) 2018-2023 Atle Solbakken atle@goliathdns.no

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

#include "rrr_config.h"

#ifdef __cplusplus
#	include <cstdio>
#	include <cstdlib>
#	include <cassert>
#else
#	include <stdio.h>
#	include <stdlib.h>
#	include <assert.h>
#endif

/*
 * About debug levels, ORed together:
 * 0 /   0 - Severe errors
 * 1 /   1 - Loading and closing of modules, threads and forks. Detailed errors about incorrect data from outside
 * 2 /   2 - Messages between modules and requests sent/received by modules and message broker backstop
 * 3 /   4 - Details about message and value processing in modules
 * 4 /   8 - MMAP channel messages as well as buffer searhing/ratelimiting/cleanup
 * 5 /  16 - Cmodule worker fork processing
 * 6 /  32 - Hex dumps of RRR messages when converted to/from host endianess
 * 7 /  64 - Socket open/close/read/write
 * 8 / 128 - Thread handling
 * 9 / 256 - Event queue pass and dispatch (printf only)
 */

#define __RRR_DEBUGLEVEL_0  (0)     // 0
#define __RRR_DEBUGLEVEL_1  (1<<0)  // 1
#define __RRR_DEBUGLEVEL_2  (1<<1)  // 2
#define __RRR_DEBUGLEVEL_3  (1<<2)  // 4
#define __RRR_DEBUGLEVEL_4  (1<<3)  // 8
#define __RRR_DEBUGLEVEL_5  (1<<4)  // 16
#define __RRR_DEBUGLEVEL_6  (1<<5)  // 32
#define __RRR_DEBUGLEVEL_7  (1<<6)  // 64
#define __RRR_DEBUGLEVEL_8  (1<<7)  // 128
#define __RRR_DEBUGLEVEL_9  (1<<8)  // 256

#define __RRR_DEBUGLEVEL_ALL (                                                            \
             __RRR_DEBUGLEVEL_1|__RRR_DEBUGLEVEL_2|__RRR_DEBUGLEVEL_3|__RRR_DEBUGLEVEL_4| \
             __RRR_DEBUGLEVEL_5|__RRR_DEBUGLEVEL_6|__RRR_DEBUGLEVEL_7|__RRR_DEBUGLEVEL_8| \
	     __RRR_DEBUGLEVEL_9)

#define __RRR_LOG_PREFIX_0  0
#define __RRR_LOG_PREFIX_1  1
#define __RRR_LOG_PREFIX_2  2
#define __RRR_LOG_PREFIX_3  3
#define __RRR_LOG_PREFIX_4  4
#define __RRR_LOG_PREFIX_5  5
#define __RRR_LOG_PREFIX_6  6
#define __RRR_LOG_PREFIX_7  7
#define __RRR_LOG_PREFIX_8  8

#define __RRR_LOG_PREFIX_0_Q  "0"
#define __RRR_LOG_PREFIX_9_Q  "9"

#define RRR_DEBUGLEVEL_OK(x) \
	(x >= __RRR_LOG_PREFIX_0 && x <= __RRR_LOG_PREFIX_8)

// Unchecked operation, should not cause dangerous situations.
// Caller should nevertheless use RRR_DEBUGLEVEL_OK macro first.
#define RRR_DEBUGLEVEL_NUM_TO_FLAG(x) \
	(x == 0 ? 0 : 1 << (x-1))

//#define RRR_WITH_SIGNAL_PRINTF

#ifndef RRR_WITH_SIGNAL_PRINTF
#	define RRR_DBG_SIGNAL(...) do { } while(0)
#endif

#ifdef RRR_ENABLE_PRINTF_LOGGING
#	define RRR_MSG_PLAIN(...) printf(__VA_ARGS__)
#	define RRR_MSG_PLAIN_N(a,b) do{ (void)(a); (void)(b); }while(0)
#	define RRR_MSG_0(...) printf(__VA_ARGS__)
#	define RRR_MSG_1(...) printf(__VA_ARGS__)
#	define RRR_MSG_2(...) printf(__VA_ARGS__)
#	define RRR_MSG_3(...) printf(__VA_ARGS__)
#	define RRR_MSG_4(...) printf(__VA_ARGS__)
#	define RRR_MSG_ERR(...) printf(__VA_ARGS__)
#	ifdef RRR_WITH_SIGNAL_PRINTF
#		define RRR_DBG_SIGNAL(...) printf(__VA_ARGS__)
#	endif
#	define RRR_MSG_X(loglevel, ...) printf(__VA_ARGS__)
#	define RRR_DBG_X(loglevel,...) printf(__VA_ARGS__)
#	define RRR_DBG_1(...) printf(__VA_ARGS__)
#	define RRR_DBG_2(...) printf(__VA_ARGS__)
#	define RRR_DBG_3(...) printf(__VA_ARGS__)
#	define RRR_DBG_4(...) printf(__VA_ARGS__)
#	define RRR_DBG_5(...) printf(__VA_ARGS__)
#	define RRR_DBG_6(...) printf(__VA_ARGS__)
#	define RRR_DBG_7(...) printf(__VA_ARGS__)
#	define RRR_DBG_8(...) printf(__VA_ARGS__)
	/* Debuglevel 9 is always printf */
#	define RRR_DBG(...) printf(__VA_ARGS__)
#	ifdef NDEBUG
#		define RRR_BUG(...) do {fprintf(stderr, __VA_ARGS__); abort();}while(0)
#	else
#		define RRR_BUG(...) do {fprintf(stderr, __VA_ARGS__); assert(0);}while(0)
#	endif
#else

#	define RRR_MSG_LOC(...) \
	rrr_log_printf(__FILE__, __LINE__, __VA_ARGS__)

#	define RRR_MSG_PLAIN(...) \
	do {rrr_log_printf_plain (__VA_ARGS__);}while(0)

#	define RRR_MSG_PLAIN_N(value,size) \
	do {rrr_log_printn_plain ((const char *) value, size);}while(0)

	// MSG 0 is for errors
#	define RRR_MSG_0(...) \
	do {RRR_MSG_LOC (__RRR_LOG_PREFIX_0, rrr_config_global.log_prefix, __VA_ARGS__);}while(0)

#	define RRR_MSG_1(...) \
	do { RRR_MSG_LOC (__RRR_LOG_PREFIX_1, rrr_config_global.log_prefix, __VA_ARGS__); } while(0)

#	define RRR_MSG_2(...) \
	do { RRR_MSG_LOC (__RRR_LOG_PREFIX_2, rrr_config_global.log_prefix, __VA_ARGS__); } while(0)

#	define RRR_MSG_3(...) \
	do { RRR_MSG_LOC (__RRR_LOG_PREFIX_3, rrr_config_global.log_prefix, __VA_ARGS__); } while(0)

#	define RRR_MSG_4(...) \
	do { RRR_MSG_LOC (__RRR_LOG_PREFIX_4, rrr_config_global.log_prefix, __VA_ARGS__); } while(0)

	// This should only be used in main()
#	define RRR_MSG_ERR(...) \
	do {rrr_log_fprintf (stderr, __FILE__, __LINE__, __RRR_LOG_PREFIX_0, rrr_config_global.log_prefix, __VA_ARGS__);}while(0)

	// Debug without holding the lock, by default disabled as printf is not async-safe
#	ifdef RRR_WITH_SIGNAL_PRINTF
#		define RRR_DBG_SIGNAL(...) \
		do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_1) != 0) { rrr_log_printf_nolock (__FILE__, __LINE__, __RRR_LOG_PREFIX_1, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)
#	endif

// Zero may be passed to X functions
#    define RRR_MSG_X(debuglevel_num, ...)                                                                                     \
    do {                                                                                                                       \
        rrr_log_printf (__FILE__, __LINE__, debuglevel_num, rrr_config_global.log_prefix, __VA_ARGS__);                        \
    } while (0)                                                                                                                \

#	define RRR_DBG_X(debuglevel_num, ...)																										\
	do { if ((rrr_config_global.debuglevel & RRR_DEBUGLEVEL_NUM_TO_FLAG(debuglevel_num)) == RRR_DEBUGLEVEL_NUM_TO_FLAG(debuglevel_num)) {	\
		RRR_MSG_LOC (debuglevel_num, rrr_config_global.log_prefix, __VA_ARGS__);															\
	}} while(0)

#	define RRR_DBG_1(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_1) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_1, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_2(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_2) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_2, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_3(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_3) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_3, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_4(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_4) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_4, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_5(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_5) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_5, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_6(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_6) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_6, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_7(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_7) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_7, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG_8(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_8) != 0) { RRR_MSG_LOC (__RRR_LOG_PREFIX_8, rrr_config_global.log_prefix, __VA_ARGS__); }} while(0)

#	define RRR_DBG(...) \
	do { RRR_MSG_LOC (__RRR_LOG_PREFIX_0, rrr_config_global.log_prefix, __VA_ARGS__); } while(0)

	// While writing code, use this macro to detect for instance invalid arguments to a function
	// which caller should have checked as opposed to letting the program crash ungracefully
#	ifdef NDEBUG
#	define RRR_BUG(...) do { RRR_MSG_ERR(__VA_ARGS__); abort(); } while (0)
#	else
#	define RRR_BUG(...) do { RRR_MSG_ERR(__VA_ARGS__); assert(0); } while (0)
#	endif
#endif

#define RRR_MSG_0_PRINTF(...) \
	do { printf ("<" __RRR_LOG_PREFIX_0_Q "> <rrr> " __VA_ARGS__); } while(0)

#define RRR_DBG_9_PRINTF(...) \
	do { if ((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_9) != 0) { printf ("<" __RRR_LOG_PREFIX_9_Q "> <rrr> " __VA_ARGS__); }} while(0)

#define RRR_DEBUGLEVEL_1 \
	((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_1) != 0)

#define RRR_DEBUGLEVEL_2 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_2) != 0)

#define RRR_DEBUGLEVEL_3 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_3) != 0)

#define RRR_DEBUGLEVEL_4 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_4) != 0)

#define RRR_DEBUGLEVEL_5 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_5) != 0)

#define RRR_DEBUGLEVEL_6 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_6) != 0)

#define RRR_DEBUGLEVEL_7 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_7) != 0)

#define RRR_DEBUGLEVEL_8 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_8) != 0)

#define RRR_DEBUGLEVEL_9 \
		((rrr_config_global.debuglevel & __RRR_DEBUGLEVEL_9) != 0)

#define RRR_DEBUGLEVEL \
		(rrr_config_global.debuglevel)

#define RRR_RFC5424_LOGLEVEL_EMERGENCY	0
#define RRR_RFC5424_LOGLEVEL_ALERT		1
#define RRR_RFC5424_LOGLEVEL_CRITICAL	2
#define RRR_RFC5424_LOGLEVEL_ERROR		3
#define RRR_RFC5424_LOGLEVEL_WARNING	4
#define RRR_RFC5424_LOGLEVEL_NOTICE		5
#define RRR_RFC5424_LOGLEVEL_INFO		6
#define RRR_RFC5424_LOGLEVEL_DEBUG		7

#define RRR_LOG_HEADER_FORMAT_NO_LEVEL "<%s> "
#define RRR_LOG_HEADER_FORMAT_FULL "<%u> <%s> "

#define RRR_LOG_HOOK_MSG_MAX_SIZE 512

#define RRR_LOG_HOOK_ARGS                                      \
            uint8_t *write_amount,                             \
	    const char *file,                                  \
	    int line,                                          \
            uint8_t loglevel_translated,                       \
            uint8_t loglevel_orig,                             \
            const char *prefix,                                \
            const char *message,                               \
            void *private_arg

struct rrr_event_queue;

// Call from main() before and after /anything/ else
int rrr_log_init(void);
void rrr_log_cleanup(void);
void rrr_log_hook_register (
		int *handle,
		void (*log)(RRR_LOG_HOOK_ARGS),
		void *private_arg,
		struct rrr_event_queue *notify_queue,
		int (*event_pass_retry_callback)(void *arg),
		void *event_pass_retry_callback_arg
);
void rrr_log_hook_unregister_all_after_fork (void);
void rrr_log_hook_unregister (
		int handle
);
void rrr_log_hooks_call_raw (
		const char *file,
		int line,
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
		const char *prefix,
		const char *message
);
void rrr_log_printf_nolock (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
);
void rrr_log_printf_plain (
		const char *__restrict __format,
		...
);
void rrr_log_printn_plain (
		const char *value,
		unsigned long long value_size
);
void rrr_log_printf (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
);
void rrr_log_fprintf (
		FILE *file_target,
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
);

#endif /* RRR_LOG_H */
