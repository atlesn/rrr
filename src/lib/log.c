/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>

#include "log.h"

static pthread_mutex_t rrr_log_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned short __rrr_log_translate_loglevel_rfc5424_stdout (unsigned short loglevel) {
	unsigned short result = 0;

	switch (loglevel) {
		case __RRR_LOG_PREFIX_0:
			result = RRR_RFC5424_LOGLEVEL_ERROR;
			break;
		case __RRR_LOG_PREFIX_1:
		case __RRR_LOG_PREFIX_2:
		case __RRR_LOG_PREFIX_3:
		case __RRR_LOG_PREFIX_4:
		case __RRR_LOG_PREFIX_5:
		case __RRR_LOG_PREFIX_6:
		case __RRR_LOG_PREFIX_7:
		default:
			result = RRR_RFC5424_LOGLEVEL_DEBUG;
			break;
	};

	return result;
}

static unsigned short __rrr_log_translate_loglevel_rfc5424_stderr (unsigned short loglevel) {
	(void)(loglevel);
	return RRR_RFC5424_LOGLEVEL_ERROR;
}

static void __rrr_log_printf_unlock_void (void *arg) {
	(void)(arg);
	pthread_mutex_unlock (&rrr_log_lock);
}

#define LOCK_BEGIN													\
		pthread_mutex_lock (&rrr_log_lock);							\
		pthread_cleanup_push(__rrr_log_printf_unlock_void, NULL)

#define LOCK_END													\
		pthread_cleanup_pop(1)

// TODO : Locking does not work across forks

#define RRR_LOG_TRANSLATE_LOGLEVEL(translate) \
	(rrr_global_config.rfc5424_loglevel_output ? translate(loglevel) : loglevel)

void rrr_log_printf_nolock (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	printf("<%u> <%s> ",
			RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout),
			prefix
	);

	vprintf(__format, args);

	va_end(args);
}

void rrr_log_printf_plain (const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	LOCK_BEGIN;

	vprintf(__format, args);

	LOCK_END;

	va_end(args);
}

void rrr_log_printf (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	LOCK_BEGIN;

	printf("<%u> <%s> ",
			RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout),
			prefix
	);
	vprintf(__format, args);

	LOCK_END;

	va_end(args);
}

void rrr_log_fprintf (FILE *file, unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	LOCK_BEGIN;

	unsigned int loglevel_translated = 0;

	if (file == stderr) {
		loglevel_translated = __rrr_log_translate_loglevel_rfc5424_stderr(loglevel);
	}
	else {
		loglevel_translated = __rrr_log_translate_loglevel_rfc5424_stdout(loglevel);
	}

	fprintf(file, "<%u> <%s> ", loglevel_translated, prefix);
	vfprintf(file, __format, args);

	LOCK_END;

	va_end(args);
}
