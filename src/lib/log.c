/*

Read Route Record

Copyright (C) 2020-2025 Atle Solbakken atle@goliathdns.no

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
#include <threads.h>
#include <unistd.h>

#include "../../config.h"
#include "helpers/log_helper.h"
#include "messages/msg.h"
#include "messages/msg_head.h"
#include "messages/msg_msg_struct.h"
#include "util/linked_list.h"

#ifdef HAVE_JOURNALD
#	define SD_JOURNAL_SUPPRESS_LOCATION
#	include <systemd/sd-journal.h>
#endif

#include "log.h"
#include "map.h"
#include "allocator.h"
#include "rrr_strerror.h"
#include "event/event.h"
#include "util/gnu.h"
#include "util/posix.h"
#include "util/macro_utils.h"
#include "util/rrr_time.h"
#include "json/json.h"
#include "socket/rrr_socket.h"

// Uncomment for debug purposes, logs are only delivered to hooks
//#define RRR_LOG_DISABLE_PRINT

#define RRR_LOG_HOOK_MAX 5
#define RRR_LOG_SOCKET_PING_INTERVAL_MIN_S 2

static volatile int rrr_log_is_initialized = 0;
static volatile uint64_t rrr_log_boot_timestamp_us = 0;

static _Thread_local int rrr_log_socket_fd = 0;
static _Thread_local void *rrr_log_socket_send_queue = NULL;
static _Thread_local size_t rrr_log_socket_send_queue_size = 0;
static _Thread_local size_t rrr_log_socket_send_queue_pos = 0;
static _Thread_local uint64_t rrr_log_socket_last_send_time = 0;
static const char *rrr_log_socket_file = NULL;

// This locking merely prevents (or attempts to prevent) output from different threads to getting mixed up
static pthread_mutex_t rrr_log_lock;
static pthread_t rrr_log_lock_holder;

// This must be separately locked to detect recursion (log functions called from inside hooks and intercepter)
static pthread_mutex_t rrr_log_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t rrr_log_hook_lock_holder;

// Each thread has its own connection to the log socket, if
// used. Use mutex to detect recursion only.
static _Thread_local pthread_mutex_t rrr_log_socket_lock = PTHREAD_MUTEX_INITIALIZER;


static void (*rrr_log_printf_intercept_callback)(RRR_LOG_HOOK_ARGS) = NULL;
static void *rrr_log_printf_intercept_callback_arg = NULL;

static void __rrr_log_free_dbl_ptr(void *arg) {
	void **dbl_ptr = (void **) arg;
	RRR_FREE_IF_NOT_NULL(*dbl_ptr);
}

static void __rrr_log_socket_send_queue_free(void) {
	RRR_FREE_IF_NOT_NULL(rrr_log_socket_send_queue);
	rrr_log_socket_send_queue_pos = 0;
	rrr_log_socket_send_queue_size = 0;
}

static void __rrr_log_socket_send_queue_reset(void) {
	rrr_log_socket_send_queue_pos = 0;
}

static void __rrr_log_printf_intercept_set (
		void (*log)(RRR_LOG_HOOK_ARGS),
		void *private_arg
) {
	rrr_log_printf_intercept_callback = log;
	rrr_log_printf_intercept_callback_arg = private_arg;
}

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

	rrr_log_boot_timestamp_us = rrr_time_get_64();
	rrr_log_is_initialized = 1;

	out:
	return ret;
}

static void __rrr_log_printf_unlock_void (void *arg) {
	(void)(arg);
	pthread_mutex_unlock (&rrr_log_lock);
}

static void __rrr_log_hook_unlock_void (void *arg) {
	(void)(arg);
	pthread_mutex_unlock (&rrr_log_hook_lock);
}

static void __rrr_log_socket_unlock_void (void *arg) {
	(void)(arg);
	pthread_mutex_unlock (&rrr_log_socket_lock);
}

#define LOCK_BEGIN                                                                                                             \
        if (pthread_mutex_trylock (&rrr_log_lock) != 0) {                                                                      \
	    if (rrr_log_lock_holder == pthread_self())                                                                         \
		goto lock_out; /* Re-entry */                                                                                  \
	    pthread_mutex_lock(&rrr_log_lock);                                                                                 \
	}                                                                                                                      \
        rrr_log_lock_holder = pthread_self();                                                                                  \
        pthread_cleanup_push(__rrr_log_printf_unlock_void, NULL)

#define LOCK_END                                                                                                               \
        pthread_cleanup_pop(1);                                                                                                \
	lock_out:

#define LOCK_HOOK_BEGIN                                                                                                        \
        if (pthread_mutex_trylock (&rrr_log_hook_lock) != 0) {                                                                 \
            if (rrr_log_hook_lock_holder == pthread_self())                                                                    \
	        goto lock_hook_out;                                                                                            \
            pthread_mutex_lock(&rrr_log_hook_lock);                                                                            \
        }                                                                                                                      \
        rrr_log_hook_lock_holder = pthread_self();                                                                             \
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

static void __rrr_log_make_timestamp(char buf[32]) {
#ifdef RRR_ENABLE_LOG_TIMESTAMPS
	uint64_t ts = rrr_time_get_64() - rrr_log_boot_timestamp_us;
	uint64_t seconds = ts / 1000 / 1000;
	uint64_t micros = ts - seconds * 1000 * 1000;
	sprintf(buf, "%010" PRIu64 ".%06" PRIu64, seconds, micros);
#else
	*buf = '\0';
#endif
}

struct rrr_log_hook {
	void (*log)(RRR_LOG_HOOK_ARGS);
	void *private_arg;
	struct rrr_event_queue *notify_queue;
	int handle;
};

static int rrr_log_hook_handle_pos = 1;
static int rrr_log_hook_count = 0;
static struct rrr_log_hook rrr_log_hooks[RRR_LOG_HOOK_MAX];

void rrr_log_hook_register (
		int *handle,
		void (*log)(RRR_LOG_HOOK_ARGS),
		void *private_arg,
		struct rrr_event_queue *notify_queue
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
		const char *file,
		int line,
		uint8_t loglevel_translated,
		uint8_t loglevel_orig,
		uint32_t flags,
		const char *prefix,
		const char *message
) {
	// In case of recursive calls, we will skip the loop
	LOCK_HOOK_BEGIN;

	for (int i = 0; i < rrr_log_hook_count; i++) {
		struct rrr_log_hook *hook = &rrr_log_hooks[i];
		hook->log (
				file,
				line,
				loglevel_translated,
				loglevel_orig,
				flags,
				prefix,
				message,
				hook->private_arg
		);
	}

	LOCK_HOOK_END;
}

static void __rrr_log_hooks_call (
		const char *file,
		int line,
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
	ssize_t size = snprintf(wpos, RRR_LOG_HOOK_MSG_MAX_SIZE, RRR_LOG_HEADER_FORMAT_NO_TS, loglevel_translated, prefix_rpos);
	if (size <= 0) {
		// NOTE ! Jumping out of function
		return;
	}

	wpos += size;

	// Output may be trimmed
	vsnprintf(wpos, RRR_LOG_HOOK_MSG_MAX_SIZE - (size_t) size, __format, args);
	tmp[RRR_LOG_HOOK_MSG_MAX_SIZE - 1] = '\0';

	rrr_log_hooks_call_raw (
			file,
			line,
			loglevel_translated,
			loglevel_orig,
			0,
			prefix,
			tmp
	);
}

#define RRR_LOG_TRANSLATE_LOGLEVEL(translate) \
	(rrr_config_global.rfc5424_loglevel_output ? translate(loglevel) : loglevel)

static void __rrr_log_printf_json (
		const struct rrr_map *fields
) {
	char *buf;
	rrr_json_from_map_nolog(&buf, fields);
	printf("%s\n", buf);
	rrr_free(buf);
}

#ifdef HAVE_JOURNALD

#define SET_IOVEC(str)	\
		{ str, strlen(str) }

static void __rrr_log_sd_journal_send_iovec (
		const char *file,
		int line,
		unsigned short loglevel,
		const char *prefix,
		struct rrr_map *fields
) {
	struct iovec *iovec;

	rrr_map_item_replace_new_f_nolog(fields, "CODE_FILE", "CODE_FILE=%s", file);
	rrr_map_item_replace_new_f_nolog(fields, "CODE_LINE", "CODE_LINE=%i", line);
	rrr_map_item_replace_new_f_nolog(fields, "PRIORITY", "PRIORITY=%u", loglevel);
	rrr_map_item_replace_new_f_nolog(fields, "RRR_CONF", "RRR_CONF=%s", prefix);

	if ((iovec = rrr_allocate(sizeof(*iovec) * RRR_LL_COUNT(fields))) == NULL)
		RRR_ABORT("Failed to allocate iovec in %s\n", __func__);

	int i = 0;
	RRR_MAP_ITERATE_BEGIN(fields);
		iovec[i].iov_base = (void *) node_value;
		iovec[i].iov_len = strlen(node_value);
		i++;
	RRR_MAP_ITERATE_END();

	int ret_tmp;
	if ((ret_tmp = sd_journal_sendv(iovec, i)) < 0) {
		fprintf(stderr, "Warning: Syslog call sd_journal_sendv failed with %i\n", ret_tmp);
	}

	rrr_free(iovec);
}

static void __rrr_log_sd_journal_send_va (
		const char *file,
		int line,
		unsigned short loglevel,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	char *buf_message = NULL;
	struct rrr_map fields = {0};

	assert (rrr_config_global.do_json_output == 0 && "Cannot use JSON format with SystemD output");

	{
		char message_format[strlen("MESSAGE=") + strlen(__format) + 1];
		sprintf(message_format, "MESSAGE=%s", __format);
		if (rrr_vasprintf(&buf_message, message_format, args) < 0) {
			goto out;
		}
		rrr_map_item_replace_new_nolog(&fields, "MESSAGE", buf_message);
	}

	__rrr_log_sd_journal_send_iovec(file, line, loglevel, prefix, &fields);

	out:
	RRR_FREE_IF_NOT_NULL(buf_message);
}
#endif

static void __rrr_log_vprintf_intercept (
		const char *file,
		int line,
		unsigned short loglevel_translated,
		unsigned short loglevel,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	char *message = NULL;

	if (rrr_vasprintf(&message, __format, args) < 0) {
		fprintf(stderr, "Warning: Failed to format log message in %s\n", __func__);
		goto out;
	}

	rrr_log_printf_intercept_callback (
			file,
			line,
			loglevel_translated,
			loglevel,
			0,
			prefix,
			message,
			rrr_log_printf_intercept_callback_arg
	);

	out:
	RRR_FREE_IF_NOT_NULL(message);
}

static void __rrr_log_printf_nolock_va (
		const char *file,
		int line,
		uint8_t loglevel,
		int is_translated,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	char ts[32];
	uint8_t loglevel_translated;
	struct rrr_map fields = {0};

	__rrr_log_make_timestamp(ts);

	loglevel_translated = is_translated
		? loglevel
		: RRR_LOG_TRANSLATE_LOGLEVEL(rrr_log_translate_loglevel_rfc5424_stdout);

	// Don't call the hooks here due to potential lock problems

#ifdef HAVE_JOURNALD
	if (rrr_config_global.do_journald_output) {
		__rrr_log_sd_journal_send_va (
				file,
				line,
				loglevel_translated,
				prefix,
				__format,
				args
		);
	}
	else {
#else
	(void)(file);
	(void)(line);
#endif

#ifndef RRR_LOG_DISABLE_PRINT
		if (rrr_config_global.do_json_output) {
			rrr_map_item_replace_new_va_nolog(&fields, "log_message", __format, args);
			__rrr_log_printf_json(&fields);
		}
		else {
			printf(RRR_LOG_HEADER_FORMAT_WITH_TS,
				RRR_LOG_HEADER_ARGS(
					ts,
					loglevel_translated,
					prefix
				)
			);
			vprintf(__format, args);
		}
#endif

#ifdef HAVE_JOURNALD
	}
#endif

	rrr_map_clear(&fields);
}

void rrr_log_printf_nolock (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
) {
	va_list(args);
	va_start(args, __format);

	__rrr_log_printf_nolock_va (
			file,
			line,
			loglevel,
			0, /* Is not translated */
			prefix,
			__format,
			args
	);

	va_end(args);
}

void rrr_log_printf_nolock_loglevel_translated (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
) {
	va_list(args);
	va_start(args, __format);

	__rrr_log_printf_nolock_va (
			file,
			line,
			loglevel,
			1, /* Is already translated */
			prefix,
			__format,
			args
	);

	va_end(args);
}

void rrr_log_printf_plain (
		const char *__restrict __format,
		...
) {
	va_list args;
	va_start(args, __format);
	struct rrr_map fields = {0};

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
		if (rrr_config_global.do_json_output) {
			rrr_map_item_replace_new_va_nolog(&fields, "log_message", __format, args);
			__rrr_log_printf_json(&fields);
		}
		else {
			vprintf(__format, args);
		}
		LOCK_END;
#endif
#ifdef HAVE_JOURNALD
	}
#endif

	rrr_map_clear(&fields);
	va_end(args);
}

void rrr_log_printn_plain (
		const char *value,
		unsigned long long value_size
) {
	struct rrr_map fields = {0};

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
		if (rrr_config_global.do_json_output) {
			rrr_map_item_replace_new_n_nolog(&fields, "log_message", value, value_size);
			__rrr_log_printf_json(&fields);
		}
		else {
			printf("%.*s", (int) value_size, value);
		}
		LOCK_END;
#endif
#ifdef HAVE_JOURNALD
	}
#endif

	rrr_map_clear(&fields);
}

static void __rrr_log_json_make_va (
		struct rrr_map *target,
		const char *file,
		int line,
		unsigned short loglevel_translated,
		unsigned short loglevel,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	(void)(loglevel);

	char ts[32];
	__rrr_log_make_timestamp(ts);

	rrr_map_item_replace_new_nolog(target, "log_timestamp", ts);
	rrr_map_item_replace_new_nolog(target, "log_file", file);
	rrr_map_item_replace_new_f_nolog(target, "log_line", "%i", line);
	rrr_map_item_replace_new_f_nolog(target, "log_level_translated", "%u", loglevel_translated);
	rrr_map_item_replace_new(target, "log_prefix", prefix);
	rrr_map_item_replace_new_va_nolog(target, "log_message", __format, args);
}

static void __rrr_log_printf_va (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		va_list args
) {
	va_list args_copy;

	va_copy(args_copy, args);

	uint8_t loglevel_translated = RRR_LOG_TRANSLATE_LOGLEVEL(rrr_log_translate_loglevel_rfc5424_stdout);
	struct rrr_map fields = {0};

#ifndef RRR_LOG_DISABLE_PRINT

#ifdef HAVE_JOURNALD
	if (rrr_config_global.do_journald_output) {
		__rrr_log_sd_journal_send_va(file, line, RRR_LOG_TRANSLATE_LOGLEVEL(rrr_log_translate_loglevel_rfc5424_stdout), prefix, __format, args);
	}
	else {
#endif

	if (rrr_log_printf_intercept_callback != NULL) {
		__rrr_log_vprintf_intercept (
				file,
				line,
				loglevel_translated,
				loglevel,
				prefix,
				__format,
				args
		);
	}
	else {
#ifndef RRR_LOG_DISABLE_PRINT
		LOCK_BEGIN;
		if (rrr_config_global.do_json_output) {
			__rrr_log_json_make_va (
					&fields,
					file,
					line,
					loglevel_translated,
					loglevel,
					prefix,
					__format,
					args
			);
			__rrr_log_printf_json(&fields);
		}
		else {
			char ts[32];
			__rrr_log_make_timestamp(ts);
			printf(RRR_LOG_HEADER_FORMAT_WITH_TS,
				RRR_LOG_HEADER_ARGS(
					ts,
					loglevel_translated,
					prefix
				)
			);
			vprintf(__format, args);
		}
		LOCK_END;
#endif
	}

#ifdef HAVE_JOURNALD
	}
#endif

#endif

	__rrr_log_hooks_call (
		file,
		line,
		loglevel_translated,
		loglevel,
		prefix,
		__format,
		args_copy
	);

	rrr_map_clear(&fields);
	va_end(args_copy);
}

void rrr_log_printf (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		...
) {
	va_list args;

	va_start(args, __format);

	__rrr_log_printf_va (
			file,
			line,
			loglevel,
			prefix,
			__format,
			args
	);

	va_end(args);
}

void rrr_log_vprintf (
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *__restrict __format,
		va_list ap
) {
	__rrr_log_printf_va (
			file,
			line,
			loglevel,
			prefix,
			__format,
			ap
	);
}

void rrr_log_fprintf (
		FILE *file_target,
		const char *file,
		int line,
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

	assert(file_target != stdout && "Use rrr_log_printf for stdout, otherwise interception does not work");

	if (rrr_config_global.rfc5424_loglevel_output) {
		if (file_target == stderr) {
			loglevel_translated = rrr_log_translate_loglevel_rfc5424_stderr(loglevel);
		}
		else {
			loglevel_translated = rrr_log_translate_loglevel_rfc5424_stdout(loglevel);
		}
	}

#ifndef RRR_LOG_DISABLE_PRINT
	char ts[32];

	__rrr_log_make_timestamp(ts);

	LOCK_BEGIN;
	fprintf(
		file_target,
		RRR_LOG_HEADER_FORMAT_WITH_TS,
		RRR_LOG_HEADER_ARGS(
			ts,
			loglevel_translated,
			prefix
		)
	);
	vfprintf(file_target, __format, args);
	LOCK_END;
#endif

	__rrr_log_hooks_call (
		file,
		line,
		loglevel_translated,
		loglevel,
		prefix,
		__format,
		args_copy
	);

	va_end(args);
	va_end(args_copy);
}

void rrr_log_print_json (
		FILE *file_target,
		const char *file,
		int line,
		uint8_t loglevel,
		const char *prefix,
		const char *json
) {
	RRR_ABORT("NOT IMPLEMENTED");
}

static void __rrr_log_socket_send (
		const void *to_send,
		size_t to_send_size
) {
	// Don't use socket framework, might cause deadlocks
	ssize_t sent_bytes = write(rrr_log_socket_fd, to_send, to_send_size);
	if (sent_bytes < 0 || (size_t) sent_bytes != to_send_size) {
		fprintf(stderr, "Error while sending log message in %s: %s\n",
			__func__, rrr_strerror(errno));
		abort();
	}

	rrr_log_socket_last_send_time = rrr_time_get_64();
}

static void __rrr_log_socket_send_from_queue (void) {
	__rrr_log_socket_send (
		rrr_log_socket_send_queue,
		rrr_log_socket_send_queue_pos
	);

	rrr_log_socket_send_queue_pos = 0;
}

static void __rrr_log_socket_printf_intercept_callback (RRR_LOG_HOOK_ARGS) {
	(void)(private_arg);

	struct rrr_msg_log *msg_log = NULL;
	rrr_length msg_size;

	assert(rrr_log_is_initialized);

	if (rrr_log_helper_log_msg_make (
			&msg_log,
			&msg_size,
			file,
			line,
			loglevel_translated,
			loglevel_orig,
			flags,
			prefix,
			message
	) != 0) {
		fprintf(stderr, "Failed to make log message in %s, cannot continue.\n", __func__);
		abort();
	}

	const int try_lock_result = pthread_mutex_trylock(&rrr_log_socket_lock);

	// Must always append to send queue if:
	// - Lock is not obtained, re-entry situation
	// - Send queue is already populated, ensure ordering
	// - Re-entry in socket framework
	// - Log socket not yet ready (after a thread or fork has started)

	if (try_lock_result != 0 ||
	    rrr_log_socket_send_queue_pos > 0 ||
	    rrr_socket_is_locked() ||
	    rrr_log_socket_fd == 0
	) {
		size_t new_size = rrr_log_socket_send_queue_pos + msg_size;
		assert(new_size >= msg_size);
		if (new_size > rrr_log_socket_send_queue_size) {
			void *new_buf = rrr_reallocate(rrr_log_socket_send_queue, new_size);
			if (new_buf == NULL) {
				fprintf(stderr, "Failed to allocate %llu bytes in %s\n",
					(unsigned long long) new_size, __func__);
				abort();
			}

			rrr_log_socket_send_queue = new_buf;
			rrr_log_socket_send_queue_size = new_size;
		}

		memcpy(rrr_log_socket_send_queue + rrr_log_socket_send_queue_pos, msg_log, msg_size);
		rrr_log_socket_send_queue_pos += msg_size;
		assert(rrr_log_socket_send_queue_pos >= msg_size);

		if (try_lock_result == 0)
			goto send;

		// Possible re-entry from socket framework, flush on
		// next call which is not re-entry.

		rrr_free(msg_log);

		pthread_mutex_unlock(&rrr_log_socket_lock);

		return;
	}

	send:
	pthread_cleanup_push(__rrr_log_socket_unlock_void, NULL);
	pthread_cleanup_push(__rrr_log_free_dbl_ptr, &msg_log);

	if (rrr_log_socket_fd == 0) {
		goto cleanup;
	}

	if (rrr_log_socket_send_queue_pos > 0) {
		__rrr_log_socket_send_from_queue();
	}
	else {
		__rrr_log_socket_send(msg_log, msg_size);
	}

	cleanup:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
}

int rrr_log_socket_connect (
		const char *log_socket
) {
	int ret = 0;

	assert(rrr_log_socket_fd == 0);

	if (log_socket == NULL) {
		assert(rrr_log_socket_file != NULL);
		log_socket = rrr_log_socket_file;
	}
	else {
		assert(rrr_log_socket_file == NULL);
		rrr_log_socket_file = log_socket;
		__rrr_log_printf_intercept_set (__rrr_log_socket_printf_intercept_callback, NULL);
	}

	if (rrr_socket_unix_connect(&rrr_log_socket_fd, "log", log_socket, 0 /* Not nonblock */) != 0) {
		// Make sure error messages are printed
		__rrr_log_printf_intercept_set (NULL, NULL);

		RRR_MSG_0("Failed to connect to log socket '%s'\n", log_socket);

		ret = 1;
		goto out;
	}

	goto out;
	out:
		return ret;
}

int rrr_log_socket_fd_get (void) {
	return rrr_log_socket_fd;
}

static void __rrr_log_socket_reconnect (void) {
	assert(rrr_log_socket_fd == 0);

	if (rrr_log_socket_connect(NULL) != 0) {
		fprintf(stderr, "Reconnection to log socket failed in %s\n",
			__func__);
		abort();
	}
}

void rrr_log_socket_flush_and_close (void) {
	if (rrr_log_socket_fd > 0) {
		if (rrr_log_socket_send_queue_pos > 0) {
			__rrr_log_socket_send_from_queue();
		}
		rrr_socket_close(rrr_log_socket_fd);
		rrr_log_socket_fd = 0;
	}

	__rrr_log_socket_send_queue_free();

}

void rrr_log_socket_after_thread (void) {
	if (rrr_log_socket_file == NULL)
		return;

	// No need to reset send queue as pthread will
	// do that prior to any messages being delivered.
	// If any messages are there, they were added 
	// after the thread started.

	__rrr_log_socket_reconnect();
}

void rrr_log_socket_after_fork (void) {
	if (rrr_log_socket_file == NULL)
		return;

	// Thread local variables should be preserved
	// across the fork
	assert(rrr_log_socket_fd > 0);

	// Queue may have remnants from parent
	// process, make sure it is cleared.
	__rrr_log_socket_send_queue_reset();

	rrr_socket_close(rrr_log_socket_fd);
	rrr_log_socket_fd = 0;

	__rrr_log_socket_reconnect();
}

void rrr_log_socket_ping_or_flush (void) {
	struct rrr_msg msg;
	size_t msg_size;
	ssize_t bytes_sent;
	uint64_t now = rrr_time_get_64();

	if (rrr_log_socket_fd == 0)
		return;

	if (rrr_log_socket_send_queue_pos > 0) {
		__rrr_log_socket_send_from_queue();
		return;
	}

	if (now - rrr_log_socket_last_send_time <
	    RRR_LOG_SOCKET_PING_INTERVAL_MIN_S * 1000 * 1000)
		return;

	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PING, 0);
	msg_size = MSG_TOTAL_SIZE(&msg);

	rrr_msg_checksum_and_to_network_endian(&msg);

	bytes_sent = write(rrr_log_socket_fd, &msg, sizeof(msg));
	if (bytes_sent < 0 || (size_t) bytes_sent != msg_size) {
		fprintf(stderr, "Failed to send ping in %s: %s\n",
			__func__,
			rrr_strerror(errno)
		);
		abort();
	}

	rrr_log_socket_last_send_time = now;
}

void rrr_log_cleanup(void) {
	rrr_log_socket_flush_and_close();

	if (rrr_log_is_initialized) {
		pthread_mutex_destroy(&rrr_log_lock);
		rrr_log_is_initialized = 0;
	}
}
