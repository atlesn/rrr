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

#define __RRR_LOG_PREFIX_0	0
#define __RRR_LOG_PREFIX_1	1
#define __RRR_LOG_PREFIX_2	2
#define __RRR_LOG_PREFIX_3	3
#define __RRR_LOG_PREFIX_4	4
#define __RRR_LOG_PREFIX_5	5
#define __RRR_LOG_PREFIX_6	6
#define __RRR_LOG_PREFIX_7	7

#define RRR_MSG(...) \
	do {rrr_log_printf (__RRR_LOG_PREFIX_0, rrr_global_config.log_prefix, __VA_ARGS__);}while(0)

#define RRR_MSG_ERR(...) \
	do {rrr_log_fprintf (stderr, __RRR_LOG_PREFIX_0, rrr_global_config.log_prefix, __VA_ARGS__);}while(0)

#define RRR_DBG_SIGNAL(...) \
	do { if ((rrr_global_config.debuglevel & __RRR_DEBUGLEVEL_1) != 0) { rrr_log_printf_nolock (__RRR_LOG_PREFIX_1, rrr_global_config.log_prefix, __VA_ARGS__); }} while(0)

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

#define RRR_BUG(...) \
	do { RRR_MSG_ERR(__VA_ARGS__); abort(); } while (0)

void rrr_log_printf_nolock (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...);
void rrr_log_printf (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...);
void rrr_log_fprintf (FILE *file, unsigned short loglevel, const char *prefix, const char *__restrict __format, ...);

#endif /* RRR_LOG_H */
