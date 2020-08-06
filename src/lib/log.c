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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "log.h"

// Uncomment for debug purposes, logs are only delivered to hooks
//#define RRR_LOG_DISABLE_PRINT

#define RRR_LOG_HOOK_MAX 5

static volatile int rrr_log_is_initialized = 0;

// This locking merely prevents (or attempts to prevent) output from different threads to getting mixed up
static pthread_mutex_t rrr_log_lock;

int rrr_log_init(void) {
	if (rrr_log_is_initialized) {
		// Don't use RRR_BUG, will deadlock
		fprintf(stderr, "%s", "BUG: rrr_log_init() called twice\n");
		abort();
	}

	int ret = 0;

	pthread_mutexattr_t attr;
	if ((pthread_mutexattr_init(&attr)) != 0) {
		fprintf(stderr, "%s", "Could not initialize mutexattr in rrr_log_init()\n");
		ret = 1;
		goto out;
	}

	if ((pthread_mutexattr_setpshared(&attr, 1)) != 0) {
		fprintf(stderr, "%s", "Could not set pshared on mutexattr in rrr_log_init()\n");
		ret = 1;
		goto out_cleanup_mutexattr;
	}

	if ((pthread_mutex_init(&rrr_log_lock, &attr)) != 0) {
		fprintf(stderr, "%s", "Could not initialize lock in rrr_log_init()\n");
		ret = 1;
		goto out_cleanup_mutexattr;
	}

	rrr_log_is_initialized = 1;

	goto out_cleanup_mutexattr;
	out_cleanup_mutexattr:
		pthread_mutexattr_destroy(&attr);
	out:
		return ret;
}

void rrr_log_cleanup(void) {
	if (!rrr_log_is_initialized) {
		return;
	}
	pthread_mutex_destroy(&rrr_log_lock);
}

// TODO : Locking does not work across forks

// This must be separately locked to detect recursion (log functions called from inside hooks)
static pthread_mutex_t rrr_log_hook_lock = PTHREAD_MUTEX_INITIALIZER;

static void __rrr_log_printf_unlock_void (void *arg) {
	(void)(arg);
	pthread_mutex_unlock (&rrr_log_lock);
}

static void __rrr_log_hook_unlock_void (void *arg) {
	(void)(arg);
	pthread_mutex_unlock (&rrr_log_hook_lock);
}

#define LOCK_BEGIN													\
		pthread_mutex_lock (&rrr_log_lock);							\
		pthread_cleanup_push(__rrr_log_printf_unlock_void, NULL)

#define LOCK_END													\
		pthread_cleanup_pop(1)

#define LOCK_HOOK_BEGIN												\
		if (pthread_mutex_trylock (&rrr_log_hook_lock) != 0) {		\
			goto lock_hook_out;										\
		}															\
		pthread_cleanup_push(__rrr_log_hook_unlock_void, NULL)

#define LOCK_HOOK_END												\
		pthread_cleanup_pop(1);										\
		lock_hook_out:

#define LOCK_HOOK_UNCHECKED_BEGIN									\
		pthread_mutex_lock (&rrr_log_hook_lock);					\
		pthread_cleanup_push(__rrr_log_hook_unlock_void, NULL)		\

#define LOCK_HOOK_UNCHECKED_END										\
		pthread_cleanup_pop(1)

struct rrr_log_hook {
	void (*log)(
			unsigned short loglevel_translated,
			const char *prefix,
			const char *message,
			void *private_arg
	);
	void *private_arg;
	int handle;
};

static int rrr_log_hook_handle_pos = 1;
static int rrr_log_hook_count = 0;
static struct rrr_log_hook rrr_log_hooks[RRR_LOG_HOOK_MAX];

void rrr_log_hook_register (
		int *handle,
		void (*log)(
				unsigned short loglevel_translated,
				const char *prefix,
				const char *message,
				void *private_arg
		),
		void *private_arg
) {
	*handle = 0;

	// Check and call outside of lock to prevent recursive locking
	if (rrr_log_hook_count == RRR_LOG_HOOK_MAX) {
		RRR_BUG("BUG: Too many log hooks in rrr_log_hook_register\n");
	}

	LOCK_HOOK_UNCHECKED_BEGIN;

	struct rrr_log_hook hook = {
		 log,
		 private_arg,
		 rrr_log_hook_handle_pos
	};

	rrr_log_hooks[rrr_log_hook_count] = hook;

	rrr_log_hook_handle_pos++;
	rrr_log_hook_count++;

	*handle = hook.handle;

	LOCK_HOOK_UNCHECKED_END;
}

void rrr_log_hook_unregister_all_after_fork (void) {
	LOCK_HOOK_UNCHECKED_BEGIN;
	rrr_log_hook_count = 0;
	LOCK_HOOK_UNCHECKED_END;
}

void rrr_log_hook_unregister (
		int handle
) {
	int shifting_started = 0;

	LOCK_HOOK_UNCHECKED_BEGIN;

	for (int i = 0; i < rrr_log_hook_count; i++) {
		struct rrr_log_hook *hook = &rrr_log_hooks[i];
		if (hook->handle == handle || shifting_started) {
			if (i + 1 < rrr_log_hook_count) {
				struct rrr_log_hook *next = &rrr_log_hooks[i + 1];
				*hook = *next;
			}
			shifting_started = 1;
		}
	}

	rrr_log_hook_count--;

	LOCK_HOOK_UNCHECKED_END;

	// Call outside of lock to prevent recursive locking
	if (shifting_started == 0 || rrr_log_hook_count < 0) {
		RRR_BUG("BUG: Invalid or double unregiser of handle %i in rrr_log_hook_unregister\n", handle);
	}
}

void rrr_log_hooks_call_raw (
		unsigned short loglevel_translated,
		const char *prefix,
		const char *message
) {
	// In case of recursive calls, we will skip the loop
	LOCK_HOOK_BEGIN;

	for (int i = 0; i < rrr_log_hook_count; i++) {
		struct rrr_log_hook *hook = &rrr_log_hooks[i];
		hook->log (
				loglevel_translated,
				prefix,
				message,
				hook->private_arg
		);
	}

	LOCK_HOOK_END;
}

static void __rrr_log_hooks_call (
		unsigned short loglevel_translated,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	const char *prefix_rpos = prefix;

	{
		// In case of a long prefix, only include the last part of it
		size_t prefix_len = strlen(prefix);
		if (prefix_len > RRR_LOG_HOOK_MSG_MAX_SIZE / 4) {
			prefix_rpos = prefix_rpos + prefix_len - (RRR_LOG_HOOK_MSG_MAX_SIZE / 4);
		}
	}

	char tmp[RRR_LOG_HOOK_MSG_MAX_SIZE];
	char *wpos = tmp;
	ssize_t size = snprintf(wpos, RRR_LOG_HOOK_MSG_MAX_SIZE, RRR_LOG_HEADER_FORMAT, loglevel_translated, prefix_rpos);
	if (size <= 0) {
		// NOTE ! Jumping out of function
		return;
	}

	wpos += size;

	// Output may be trimmed
	vsnprintf(wpos, RRR_LOG_HOOK_MSG_MAX_SIZE - size, __format, args);
	tmp[RRR_LOG_HOOK_MSG_MAX_SIZE - 1] = '\0';

	rrr_log_hooks_call_raw(loglevel_translated, prefix, tmp);
}

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

#define RRR_LOG_TRANSLATE_LOGLEVEL(translate) \
	(rrr_config_global.rfc5424_loglevel_output ? translate(loglevel) : loglevel)

void rrr_log_printf_nolock (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	// Don't call the hooks here due to potential lock problems

#ifndef RRR_LOG_DISABLE_PRINT
	printf(RRR_LOG_HEADER_FORMAT,
			RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout),
			prefix
	);
#endif

	vprintf(__format, args);

	va_end(args);
}

void rrr_log_printf_plain (const char *__restrict __format, ...) {
	va_list args;
	va_start(args, __format);

	LOCK_BEGIN;

#ifndef RRR_LOG_DISABLE_PRINT
	vprintf(__format, args);
#endif

	LOCK_END;

	va_end(args);
}

void rrr_log_printn_plain (const char *value, size_t value_size) {
	LOCK_BEGIN;

#ifndef RRR_LOG_DISABLE_PRINT
	printf("%.*s", (int) value_size, value);
#endif


	LOCK_END;
}

void rrr_log_printf (unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_list args_copy;

	va_start(args, __format);
	va_copy(args_copy, args);

	unsigned int loglevel_translated = RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout);

	LOCK_BEGIN;

#ifndef RRR_LOG_DISABLE_PRINT
	printf(RRR_LOG_HEADER_FORMAT,
			loglevel_translated,
			prefix
	);
	vprintf(__format, args);
#endif

	LOCK_END;

	__rrr_log_hooks_call(loglevel_translated, prefix, __format, args_copy);

	va_end(args);
	va_end(args_copy);
}

void rrr_log_fprintf (FILE *file, unsigned short loglevel, const char *prefix, const char *__restrict __format, ...) {
	va_list args;
	va_list args_copy;

	va_start(args, __format);
	va_copy(args_copy, args);

	unsigned int loglevel_translated = 0;

	if (file == stderr) {
		loglevel_translated = __rrr_log_translate_loglevel_rfc5424_stderr(loglevel);
	}
	else {
		loglevel_translated = __rrr_log_translate_loglevel_rfc5424_stdout(loglevel);
	}

	LOCK_BEGIN;

#ifndef RRR_LOG_DISABLE_PRINT
	fprintf(file, RRR_LOG_HEADER_FORMAT, loglevel_translated, prefix);
	vfprintf(file, __format, args);
#endif

	LOCK_END;

	__rrr_log_hooks_call(loglevel_translated, prefix, __format, args_copy);

	va_end(args);
	va_end(args_copy);
}
