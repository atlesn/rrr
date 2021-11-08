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

#ifdef HAVE_JOURNALD
#	define SD_JOURNAL_SUPPRESS_LOCATION
#	include <systemd/sd-journal.h>
#endif

#include "log.h"
#include "allocator.h"
#include "event/event.h"
#include "event/event_functions.h"
#include "util/gnu.h"
#include "util/posix.h"
#include "util/macro_utils.h"
#include "rrr_strerror.h"

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
	if ((rrr_posix_mutex_init(&rrr_log_lock, 0)) != 0) {
		fprintf(stderr, "%s", "Could not initialize lock in rrr_log_init()\n");
		ret = 1;
		goto out;
	}

	rrr_log_is_initialized = 1;

	out:
	return ret;
}

void rrr_log_cleanup(void) {
	if (!rrr_log_is_initialized) {
		return;
	}
	pthread_mutex_destroy(&rrr_log_lock);
}

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

#define LOCK_BEGIN                                                                                                             \
        pthread_mutex_lock (&rrr_log_lock);                                                                                    \
        pthread_cleanup_push(__rrr_log_printf_unlock_void, NULL)

#define LOCK_END                                                                                                               \
        pthread_cleanup_pop(1)

#define LOCK_HOOK_BEGIN                                                                                                        \
        if (pthread_mutex_trylock (&rrr_log_hook_lock) != 0) {                                                                 \
            goto lock_hook_out;                                                                                                \
        }                                                                                                                      \
        pthread_cleanup_push(__rrr_log_hook_unlock_void, NULL)

#define LOCK_HOOK_END                                                                                                          \
        pthread_cleanup_pop(1);                                                                                                \
        lock_hook_out:

#define LOCK_HOOK_UNCHECKED_BEGIN                                                                                              \
        pthread_mutex_lock (&rrr_log_hook_lock);                                                                               \
        pthread_cleanup_push(__rrr_log_hook_unlock_void, NULL)

// Register and unregister functions should spin to keep the thread alive
// thus obtaining the lock faster when there's a lot of messages being generated.
#define LOCK_HOOK_UNCHECKED_BEGIN_SPIN                                                                                         \
        while (pthread_mutex_trylock (&rrr_log_hook_lock) != 0) { }                                                            \
        pthread_cleanup_push(__rrr_log_hook_unlock_void, NULL)

#define LOCK_HOOK_UNCHECKED_END                                                                                                \
        pthread_cleanup_pop(1)

struct rrr_log_hook {
	void (*log)(
			uint8_t *write_amount,
			uint8_t loglevel_translated,
			uint8_t loglevel_orig,
			const char *prefix,
			const char *message,
			void *private_arg
	);
	void *private_arg;
	struct rrr_event_queue *notify_queue;
	int (*event_pass_retry_callback)(void *arg);
	void *event_pass_retry_callback_arg;
	int handle;
};

static int rrr_log_hook_handle_pos = 1;
static int rrr_log_hook_count = 0;
static struct rrr_log_hook rrr_log_hooks[RRR_LOG_HOOK_MAX];

void rrr_log_hook_register (
		int *handle,
		void (*log)(
				uint8_t *write_amount,
				uint8_t loglevel_translated,
				uint8_t loglevel_orig,
				const char *prefix,
				const char *message,
				void *private_arg
		),
		void *private_arg,
		struct rrr_event_queue *notify_queue,
		int (*event_pass_retry_callback)(void *arg),
		void *event_pass_retry_callback_arg
) {
	*handle = 0;

	// Check and call outside of lock to prevent recursive locking
	if (rrr_log_hook_count == RRR_LOG_HOOK_MAX) {
		RRR_BUG("BUG: Too many log hooks in rrr_log_hook_register\n");
	}

	LOCK_HOOK_UNCHECKED_BEGIN_SPIN;

	struct rrr_log_hook hook = {
		 log,
		 private_arg,
		 notify_queue,
		 event_pass_retry_callback,
		 event_pass_retry_callback_arg,
		 rrr_log_hook_handle_pos
	};

	rrr_log_hooks[rrr_log_hook_count] = hook;

	rrr_log_hook_handle_pos++;
	rrr_log_hook_count++;

	*handle = hook.handle;

	LOCK_HOOK_UNCHECKED_END;
}

void rrr_log_hook_unregister_all_after_fork (void) {
	LOCK_HOOK_UNCHECKED_BEGIN_SPIN;
	rrr_log_hook_count = 0;
	LOCK_HOOK_UNCHECKED_END;
}

void rrr_log_hook_unregister (
		int handle
) {
	int shifting_started = 0;

	LOCK_HOOK_UNCHECKED_BEGIN_SPIN;

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
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
		const char *prefix,
		const char *message
) {
	// In case of recursive calls, we will skip the loop
	LOCK_HOOK_BEGIN;

	for (int i = 0; i < rrr_log_hook_count; i++) {
		uint8_t write_amount = 0;
		struct rrr_log_hook *hook = &rrr_log_hooks[i];
		hook->log (
				&write_amount,
				loglevel_translated,
				loglevel_orig,
				prefix,
				message,
				hook->private_arg
		);

		if (hook->notify_queue && write_amount > 0) {
			rrr_event_pass (
					hook->notify_queue,
					RRR_EVENT_FUNCTION_LOG_HOOK_DATA_AVAILABLE,
					write_amount,
					hook->event_pass_retry_callback,
					hook->event_pass_retry_callback_arg
			);
		}
	}

	LOCK_HOOK_END;
}

static void __rrr_log_hooks_call (
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
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
	ssize_t size = snprintf(wpos, RRR_LOG_HOOK_MSG_MAX_SIZE, RRR_LOG_HEADER_FORMAT_FULL, loglevel_translated, prefix_rpos);
	if (size <= 0) {
		// NOTE ! Jumping out of function
		return;
	}

	wpos += size;

	// Output may be trimmed
	vsnprintf(wpos, RRR_LOG_HOOK_MSG_MAX_SIZE - (size_t) size, __format, args);
	tmp[RRR_LOG_HOOK_MSG_MAX_SIZE - 1] = '\0';

	rrr_log_hooks_call_raw (
		loglevel_translated,
		loglevel_orig,
		prefix,
		tmp
	);
}

static uint8_t __rrr_log_translate_loglevel_rfc5424_stdout (
		uint8_t loglevel
) {
	uint8_t result = 0;

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

static uint8_t __rrr_log_translate_loglevel_rfc5424_stderr (
		uint8_t loglevel
) {
	(void)(loglevel);
	return RRR_RFC5424_LOGLEVEL_ERROR;
}

#define RRR_LOG_TRANSLATE_LOGLEVEL(translate) \
	(rrr_config_global.rfc5424_loglevel_output ? translate(loglevel) : loglevel)

#ifdef HAVE_JOURNALD

#define SET_IOVEC(str)	\
		{ str, strlen(str) }

static void __rrr_log_sd_journal_sendv (
		unsigned short loglevel,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	char *buf_priority = NULL;
	char *buf_prefix = NULL;
	char *buf_message = NULL;

	if (rrr_asprintf(&buf_priority, "PRIORITY=%i", loglevel) < 0) {
		goto out;
	}

	if (rrr_asprintf(&buf_prefix, "RRR_CONF=%s", prefix) < 0) {
		goto out;
	}

	{
		char message_format[strlen("MESSAGE=") + strlen(__format) + 1];
		sprintf(message_format, "MESSAGE=%s", __format);
		if (rrr_vasprintf(&buf_message, message_format, args) < 0) {
			goto out;
		}
	}

	struct iovec iovec[3] = {
		SET_IOVEC(buf_priority),
		SET_IOVEC(buf_prefix),
		SET_IOVEC(buf_message)
	};

	int ret_tmp;
	if ((ret_tmp = sd_journal_sendv(iovec, 3)) < 0) {
		fprintf(stderr, "Warning: Syslog call sd_journal_sendv failed with %i\n", ret_tmp);
	}

	out:
	RRR_FREE_IF_NOT_NULL(buf_priority);
	RRR_FREE_IF_NOT_NULL(buf_prefix);
	RRR_FREE_IF_NOT_NULL(buf_message);
}
#endif

void rrr_log_printf_nolock (
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
) {
	va_list args;
	va_start(args, __format);

	// Don't call the hooks here due to potential lock problems

#ifdef HAVE_JOURNALD
	if (rrr_config_global.do_journald_output) {
		__rrr_log_sd_journal_sendv(RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout), prefix, __format, args);
	}
	else {
#endif

#ifndef RRR_LOG_DISABLE_PRINT
		printf(RRR_LOG_HEADER_FORMAT_FULL,
				RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout),
				prefix
		);
		vprintf(__format, args);
#endif

#ifdef HAVE_JOURNALD
	}
#endif

	va_end(args);
}

void rrr_log_printf_plain (
		const char *__restrict __format,
		...
) {
	va_list args;
	va_start(args, __format);


#ifdef HAVE_JOURNALD
	if (rrr_config_global.do_journald_output) {
		int ret = sd_journal_printv(LOG_DEBUG, __format, args);
		if (ret < 0) {
			fprintf(stderr, "Warning: Syslog call sd_journal_printv failed with %i\n", ret);
		}
	}
	else {
#endif

#ifndef RRR_LOG_DISABLE_PRINT
		LOCK_BEGIN;
		vprintf(__format, args);
		LOCK_END;
#endif

#ifdef HAVE_JOURNALD
	}
#endif

	va_end(args);
}

void rrr_log_printn_plain (
		const char *value,
		unsigned long long value_size
) {
	if (value_size > INT_MAX) {
		value_size = INT_MAX;
	}
#ifdef HAVE_JOURNALD
	if (rrr_config_global.do_journald_output) {
		int ret = sd_journal_print(LOG_DEBUG, "%.*s", (int) value_size, value);
		if (ret < 0) {
			fprintf(stderr, "Warning: Syslog call sd_journal_print failed with %i\n", ret);
		}
	}
	else {
#endif

#ifndef RRR_LOG_DISABLE_PRINT
		LOCK_BEGIN;
		printf("%.*s", (int) value_size, value);
		LOCK_END;
#endif

#ifdef HAVE_JOURNALD
	}
#endif
}

void rrr_log_printf (
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
) {
	va_list args;
	va_list args_copy;

	va_start(args, __format);
	va_copy(args_copy, args);

	uint8_t loglevel_translated = RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout);

#ifndef RRR_LOG_DISABLE_PRINT

#ifdef HAVE_JOURNALD
	if (rrr_config_global.do_journald_output) {
		__rrr_log_sd_journal_sendv(RRR_LOG_TRANSLATE_LOGLEVEL(__rrr_log_translate_loglevel_rfc5424_stdout), prefix, __format, args);
	}
	else {
#endif
		LOCK_BEGIN;
		printf(RRR_LOG_HEADER_FORMAT_FULL,
				loglevel_translated,
				prefix
		);
		vprintf(__format, args);
		LOCK_END;
#ifdef HAVE_JOURNALD
	}
#endif

#endif

	__rrr_log_hooks_call (
		loglevel_translated,
		loglevel,
		prefix,
		__format,
		args_copy
);

	va_end(args);
	va_end(args_copy);
}

void rrr_log_fprintf (
		FILE *file,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
) {
	va_list args;
	va_list args_copy;

	va_start(args, __format);
	va_copy(args_copy, args);

	uint8_t loglevel_translated = 0;

	if (rrr_config_global.rfc5424_loglevel_output) {
		if (file == stderr) {
			loglevel_translated = __rrr_log_translate_loglevel_rfc5424_stderr(loglevel);
		}
		else {
			loglevel_translated = __rrr_log_translate_loglevel_rfc5424_stdout(loglevel);
		}
	}

#ifndef RRR_LOG_DISABLE_PRINT
	LOCK_BEGIN;
	fprintf(file, RRR_LOG_HEADER_FORMAT_FULL, loglevel_translated, prefix);
	vfprintf(file, __format, args);
	LOCK_END;
#endif

	__rrr_log_hooks_call (
		loglevel_translated,
		loglevel,
		prefix,
		__format,
		args_copy
	);

	va_end(args);
	va_end(args_copy);
}
