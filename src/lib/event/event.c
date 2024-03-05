/*

Read Route Record

Copyright (C) 2021-2024 Atle Solbakken atle@goliathdns.no

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
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

#include "../log.h"
#include "../allocator.h"
#include "event.h"
#include "event_struct.h"
#include "event_functions.h"
#include "../rrr_strerror.h"
#include "../rrr_config.h"
#include "../rrr_path_max.h"
#include "../helpers/string_builder.h"
#include "../socket/rrr_socket.h"
#include "../socket/rrr_socket_eventfd.h"
#include "../util/gnu.h"
#include "../util/rrr_time.h"

// Uncomment to debug event processing
//#define RRR_WITH_LIBEVENT_DEBUG

#define SET_RECEIVER()                                                    \
    assert(receiver_h < queue->receiver_count);                           \
    struct rrr_event_receiver *receiver = queue->receivers + receiver_h

#define SET_ENVELOPE()                                                    \
    struct rrr_event_queue *queue = envelope->queue;                      \
    rrr_event_receiver_handle receiver_h = envelope->receiver_h

struct rrr_event_hook_config rrr_event_hooking = {0};

void rrr_event_hook_set (
		void (*hook)(RRR_EVENT_HOOK_ARGS),
		void *arg
) {
	if (!rrr_event_hooking.enabled)
		return;

	// Unsafe to change this function. Also, only set hook
	// prior to making any threads as the struct update is
	// not atomic. After forking however, this function may
	// be called again.
	assert (rrr_event_hooking.pid != getpid() && "Double call to event hook set from same pid");

	rrr_event_hooking.pid = getpid();
	rrr_event_hooking.hook = hook;
	rrr_event_hooking.arg = arg;
}

void rrr_event_hook_enable (
		void
) {
	rrr_event_hooking.enabled = 1;
}

ssize_t rrr_event_hook_string_format (
		char *buf,
		size_t buf_size,
		const char *source_func,
		evutil_socket_t fd,
		int flags,
		const char *extra
) {
	return snprintf (buf, buf_size, "pid: % 8lli tid: % 8lli func: %-50s fd: % 4i time: %" PRIu64 " flags: %i read: %i write: %i timeout: %i%s",
		(long long int) getpid(),
		(long long int) rrr_gettid(),
		source_func,
		fd,
		rrr_time_get_64(),
		flags,
		(flags & EV_READ) != 0,
		(flags & EV_WRITE) != 0,
		(flags & EV_TIMEOUT) != 0,
		extra
	);
}

int rrr_event_queue_reinit (
		struct rrr_event_queue *queue
) {
	return event_reinit(queue->event_base) != 0;
}

void rrr_event_queue_fds_get (
		int fds[RRR_EVENT_QUEUE_FD_MAX],
		size_t *fds_count,
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h
) {
	size_t wpos = 0;

	SET_RECEIVER();
	for (size_t i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
		fds[wpos++] = RRR_SOCKET_EVENTFD_READ_FD(&receiver->functions[i].eventfd);
		fds[wpos++] = RRR_SOCKET_EVENTFD_WRITE_FD(&receiver->functions[i].eventfd);
	}
	*fds_count = wpos;
}

int rrr_event_function_count (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h
) {
	SET_RECEIVER();

	int count = 0;

	for (int i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
		if (receiver->functions[i].function != NULL) {
			count++;
		}
	}

	if (receiver->callback_periodic) {
		count++;
	}

	return count;
}

void rrr_event_function_set (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS),
		const char *description
) {
	SET_RECEIVER();

	if (function == NULL) {
		RRR_BUG("BUG: Function was NULL in %s\n", __func__);
	}

	RRR_DBG_9_PRINTF("EQ SETF %p[%u] %s %u->%p (%s)\n",
		queue, receiver_h, receiver->name, code, function, description);

	receiver->functions[code].function = function;
}

void rrr_event_function_set_with_arg (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS),
		void *arg,
		const char *description
) {
	SET_RECEIVER();

	if (function == NULL) {
		RRR_BUG("BUG: Function was NULL in %s\n", __func__);
	}

	RRR_DBG_9_PRINTF("EQ SETF %p[%u] %s %u->%p(%p) (%s)\n",
		queue, receiver_h, receiver->name, code, function, arg, description);

	receiver->functions[code].function = function;
	receiver->functions[code].function_arg = arg;
}

int rrr_event_function_priority_set (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		uint8_t code,
		enum rrr_event_priority priority
) {
	SET_RECEIVER();

	if (event_priority_set(receiver->functions[code].signal_event, (int) priority) != 0) {
		RRR_MSG_0("Failed to set priority %s\n", __func__);
		return 1;
	}

	return 0;
}

static void __rrr_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_event_receiver_envelope *envelope = arg;
	SET_ENVELOPE();
	SET_RECEIVER();

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s periodic fd %i pid %llu tid %llu\n",
		queue, receiver_h, receiver->name, (int) fd, (unsigned long long) getpid(), (unsigned long long) rrr_gettid());

	if ( receiver->callback_periodic != NULL &&
	    (queue->callback_ret = receiver->callback_periodic(receiver->callback_arg)) != 0
	) {
		event_base_loopbreak(queue->event_base);
	}
}

static void __rrr_event_unpause (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_event_receiver_envelope *envelope = arg;
	SET_ENVELOPE();
	SET_RECEIVER();

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s unpause fd %i pid %llu tid %llu\n",
		queue, receiver_h, receiver->name, (int) fd, (unsigned long long) getpid(), (unsigned long long) rrr_gettid());

	for (uint8_t i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
		if (receiver->functions[i].is_paused) {
			event_add(receiver->functions[i].signal_event, NULL);
		}
	}
}

static void __rrr_event_signal_event (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
 	struct rrr_event_function *function = arg;
	struct rrr_event_receiver_envelope *envelope = &function->receiver_e;
	SET_ENVELOPE();
	SET_RECEIVER();

	(void)(fd);
	(void)(flags);

 	int ret = 0;
	uint64_t count = 0;
	unsigned short is_paused_new = function->is_paused;

	RRR_EVENT_HOOK();

	RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s function %u fd %i pid %llu tid %llu\n",
		queue, receiver_h, receiver->name, function->index, (int) fd, (unsigned long long) getpid(), (unsigned long long) rrr_gettid());

	if (function->callback_pause) {
		function->callback_pause(&is_paused_new, function->is_paused, function->callback_pause_arg);
	}

	if (!is_paused_new && function->is_paused) {
		RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s function %u unpaused\n",
			queue, receiver_h, receiver->name, function->index);
		function->is_paused = 0;
	}
	else if (is_paused_new) {
		if (!function->is_paused) {
			RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s function %u paused\n",
				queue, receiver_h, receiver->name, function->index);
			function->is_paused = 1;
		}

		event_del(function->signal_event);

		if (!event_pending(receiver->unpause_event, EV_TIMEOUT, NULL)) {
			struct timeval tv = { 0, 50 }; // 50 us
			event_add(receiver->unpause_event, &tv);
		}

		goto out;
	}

	if (receiver->deferred_amount[function->index] > 0) {
		count = receiver->deferred_amount[function->index];
		receiver->deferred_amount[function->index] = 0;
	}
	else {
		if ((ret = rrr_socket_eventfd_read(&count, &function->eventfd)) != 0) {
			if (ret == RRR_SOCKET_NOT_READY) {
				RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s fd %i not ready\n",
					queue, receiver_h, receiver->name, (int) fd);
				// OK, nothing to do
			}
			else {
				RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s error from eventfd read, ending loop\n",
					queue, receiver_h, receiver->name);
				event_base_loopbreak(queue->event_base);
			}
		}
	}

	if (function->function == NULL) {
		RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s function not registered\n",
			queue, receiver_h, receiver->name);
		goto out;
	}

	RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s count %" PRIu64 " function %p\n",
		queue, receiver_h, receiver->name, count, function->function);

	int retries = 5;
	while (count > 0 && retries--) {
		uint16_t amount = (count > 0xffff ? 0xffff : (uint16_t) count);
		count -= amount;

		const uint16_t amount_orig = amount;

		if ((ret = function->function (
				&amount,
				function->function_arg != NULL
					? function->function_arg
					: receiver->callback_arg
		)) != 0) {
			if (ret == RRR_EVENT_EXIT) {
				RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s exit command from callback, ending loop\n",
					queue, receiver_h, receiver->name);
			}
			else {
				RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s error %i from callback, ending loop\n",
					queue, receiver_h, receiver->name, ret);
			}

			queue->callback_ret = ret;

			event_base_loopbreak(queue->event_base);

			goto out;
		}

		if (amount_orig == amount) {
			// This can happen if the sender incorrectly PASSes prior to data being written to the buffer
			// in question. In case of bad performance, also verify that the reader is able to handle all
			// received messages or that it activates the pausing if it's not able to.
			sched_yield();
		}

		if (amount > 0) {
			count += amount;
		}

		RRR_DBG_9_PRINTF("EQ DISP %p[%u] %s => count %" PRIu64 " (remaining)\n",
			queue, receiver_h, receiver->name, count);
	}

	if (count > 0) {
		RRR_DBG_9_PRINTF("EQ PASS %p[%u] %s => count %" PRIu64 " (deferred)\n",
			queue, receiver_h, receiver->name, count);

		receiver->deferred_amount[function->index] = count;

		event_active(function->signal_event, 0, 0);
	}

	out:
	return;
}

void rrr_event_callback_pause_set (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		uint8_t code,
		void (*callback)(RRR_EVENT_FUNCTION_PAUSE_ARGS),
		void *callback_arg
) {
	SET_RECEIVER();

	receiver->functions[code].callback_pause = callback;
	receiver->functions[code].callback_pause_arg = callback_arg;
}

int rrr_event_dispatch_once (
		struct rrr_event_queue *queue
) {
	return (event_base_loop(queue->event_base, EVLOOP_ONCE) < 0);
}

static void __rrr_event_function_periodic_clear (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h
) {
	SET_RECEIVER();

	if (receiver->callback_periodic == NULL)
		return;

	event_del(receiver->periodic_event);

	receiver->callback_periodic = NULL;
}

int rrr_event_function_periodic_set (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		unsigned int periodic_interval_us,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS)
) {
	int ret = 0;

	struct timeval tv_interval = {0};
	SET_RECEIVER();

	__rrr_event_function_periodic_clear(queue, receiver_h);

	tv_interval.tv_usec = (int) (periodic_interval_us % 1000000);
	tv_interval.tv_sec = (long int) ((periodic_interval_us - (long unsigned int) tv_interval.tv_usec) / 1000000);

	if (event_add(receiver->periodic_event, &tv_interval)) {
		RRR_MSG_0("Failed to add periodic event in %s\n", __func__);
		ret = 1;
		goto out;
	}

	receiver->callback_periodic = function_periodic;

	out:
	return ret;
}

int rrr_event_dispatch (
		struct rrr_event_queue *queue
) {
	int ret = 0;

	queue->callback_ret = 0;

	if ((ret = event_base_dispatch(queue->event_base)) != 0) {
		RRR_MSG_0("Error from event_base_dispatch in %s: %i\n", __func__, ret);
		ret = 1;
		goto out;
	}

	if (queue->callback_ret != 0) {
		ret = queue->callback_ret & ~(RRR_EVENT_EXIT);
	}
	else if (event_base_got_break(queue->event_base)) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_event_function_periodic_set_and_dispatch (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		unsigned int periodic_interval_us,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS)
) {
	int ret = 0;

	if ((ret = rrr_event_function_periodic_set (
			queue,
			receiver_h,
			periodic_interval_us,
			function_periodic
	)) != 0) {
		goto out;
	}

	ret = rrr_event_dispatch(queue);

	out:
	return ret;
}

void rrr_event_dispatch_break (
		struct rrr_event_queue *queue
) {
	event_base_loopbreak(queue->event_base);
}

void rrr_event_dispatch_exit (
		struct rrr_event_queue *queue
) {
	queue->callback_ret = RRR_EVENT_EXIT;
	event_base_loopbreak(queue->event_base);
}

void rrr_event_dispatch_restart (
		struct rrr_event_queue *queue
) {
	event_base_loopcontinue(queue->event_base);
}

int rrr_event_pass (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		uint8_t function,
		uint8_t amount,
		int (*retry_callback)(void *arg),
		void *retry_callback_arg
) {
	int ret = 0;

	SET_RECEIVER();

	if (function > RRR_EVENT_FUNCTION_MAX) {
		RRR_BUG("BUG: Function out of range in %s\n", __func__);
	}

	RRR_DBG_9_PRINTF("EQ PASS %p[%u] %s function %u amount %u\n",
		queue, receiver_h, receiver->name, function, amount);

	retry:
	if ((ret = rrr_socket_eventfd_write(&receiver->functions[function].eventfd, amount)) != 0) {
		if (ret == RRR_SOCKET_NOT_READY) {
			if (retry_callback != NULL && ((ret = retry_callback(retry_callback_arg)) != 0)) {
				goto out;
			}
			goto retry;
		}
		RRR_MSG_0("Failed to pass event in %s, return was %i\n", __func__, ret);
		ret = RRR_EVENT_ERR;
		goto out;
	}

	out:
	return ret;
}

void rrr_event_count (
		int64_t *eventfd_count,
		uint64_t *deferred_count,
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		uint8_t function
) {
	SET_RECEIVER();

#ifdef RRR_SOCKET_EVENTFD_DEBUG
	rrr_socket_eventfd_count(eventfd_count, &receiver->functions[function].eventfd);
#else
	*eventfd_count = 0;
#endif

	// Note : No locking, race conditions may occur. Usually only the
	//        reader updates the deferred counter.
	*deferred_count = receiver->deferred_amount[function];
}

static void __rrr_event_receiver_envelope_init (
		struct rrr_event_receiver_envelope *envelope,
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h
) {
	memset(envelope, '\0', sizeof(*envelope));

	envelope->queue = queue;
	envelope->receiver_h = receiver_h;
}

static int __rrr_event_receiver_init (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		const char *name,
		void *callback_arg
) {
	int ret = 0;

	SET_RECEIVER();

	RRR_DBG_9_PRINTF("EQ INIT %p[%u] %s thread ID %llu\n",
		queue, receiver_h, name, (long long unsigned) rrr_gettid());

	memset(receiver, '\0', sizeof(*receiver));

	strncpy(receiver->name, name, sizeof(receiver->name));
	receiver->name[sizeof(receiver->name) - 1] = '\0';
	receiver->callback_arg = callback_arg;

	if ((receiver->periodic_event = event_new (
			queue->event_base,
			-1,
			EV_TIMEOUT|EV_PERSIST,
			__rrr_event_periodic,
			queue->receiver_envelopes + receiver_h
	)) == NULL) {
		RRR_MSG_0("Failed to create periodic event in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((receiver->unpause_event = event_new (
			queue->event_base,
			-1,
			EV_TIMEOUT,
			__rrr_event_unpause,
			queue->receiver_envelopes + receiver_h
	)) == NULL) {
		RRR_MSG_0("Failed to create unpause event in %s\n", __func__);
		ret = 1;
		goto out_destroy_periodic_event;
	}

	__rrr_event_receiver_envelope_init (queue->receiver_envelopes + receiver_h, queue, receiver_h);

	for (unsigned short i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
		RRR_ASSERT(sizeof(i)<=sizeof(receiver->functions[0].index), sizeof_loop_counter_exceeds_size_in_function_struct);

		__rrr_event_receiver_envelope_init(&receiver->functions[i].receiver_e, queue, receiver_h);

		if ((ret = rrr_socket_eventfd_init(&receiver->functions[i].eventfd)) != 0) {
			break;
		}

		if ((receiver->functions[i].signal_event = event_new (
				queue->event_base,
				RRR_SOCKET_EVENTFD_READ_FD(&receiver->functions[i].eventfd),
				EV_READ | EV_PERSIST,
				__rrr_event_signal_event,
				&receiver->functions[i]
		)) == NULL) {
			RRR_MSG_0("Failed to create signal event in %s\n", __func__);
			ret = 1;
			break;
		}

		if (event_add (receiver->functions[i].signal_event, NULL) != 0) {
			RRR_MSG_0("Failed to add signal event in %s\n", __func__);
			ret = 1;
			break;
		}

		receiver->functions[i].index = i;

		RRR_DBG_9_PRINTF(" -      function %llu fds %i<-%i\n",
				(long long unsigned int) i,
				RRR_SOCKET_EVENTFD_READ_FD(&receiver->functions[i].eventfd),
				RRR_SOCKET_EVENTFD_WRITE_FD(&receiver->functions[i].eventfd)
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Failed to initialize event FDs in %s\n", __func__);
		ret = 1;
		goto out_cleanup_eventfd;
	}

	goto out;
	out_cleanup_eventfd:
		for (size_t i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
			rrr_socket_eventfd_cleanup(&receiver->functions[i].eventfd);
			if (receiver->functions[i].signal_event != NULL) {
				event_free(receiver->functions[i].signal_event);
			}
		}
		event_free(receiver->unpause_event);
	out_destroy_periodic_event:
		event_free(receiver->periodic_event);
	out:
		return ret;
}

int rrr_event_receiver_new (
		rrr_event_receiver_handle *result,
		struct rrr_event_queue *queue,
		const char *name,
		void *callback_arg
) {
	int ret = 0;

	if (queue->receiver_count == queue->receiver_max) {
		RRR_BUG("BUG: Max receivers breached in %s (%u)\n",
			__func__, queue->receiver_max);
	}

	rrr_event_receiver_handle receiver_h = queue->receiver_count++;

	if ((ret = __rrr_event_receiver_init (queue, receiver_h, name, callback_arg)) != 0) {
		goto out_error;
	}

	*result = receiver_h;

	goto out;
	out_error:
		queue->receiver_count--;
	out:
		return ret;
}

void rrr_event_receiver_callback_arg_set (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h,
		void *callback_arg
) {
	SET_RECEIVER();
	receiver->callback_arg = callback_arg;
}

void rrr_event_receiver_reset (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h
) {
	SET_RECEIVER();

	for (size_t i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
		struct rrr_event_function *function = &receiver->functions[i];

		if (function->signal_event != NULL) {
			event_del(function->signal_event);
		}

		function->function = NULL;
		function->function_arg = NULL;
		function->callback_pause = NULL;
		function->callback_pause_arg = NULL;
		function->is_paused = 0;
	}

	event_del(receiver->periodic_event);
	receiver->callback_periodic = NULL;

	event_del(receiver->unpause_event);
}

static void __rrr_event_receiver_cleanup (
		struct rrr_event_queue *queue,
		rrr_event_receiver_handle receiver_h
) {
	SET_RECEIVER();

	for (size_t i = 0; i <= RRR_EVENT_FUNCTION_MAX; i++) {
		rrr_socket_eventfd_cleanup(&receiver->functions[i].eventfd);
		if (receiver->functions[i].signal_event != NULL) {
			event_free(receiver->functions[i].signal_event);
		}
	}

	if (receiver->periodic_event != NULL) {
		event_free(receiver->periodic_event);
	}

	if (receiver->unpause_event != NULL) {
		event_free(receiver->unpause_event);
	}

	memset(receiver, '\0', sizeof(*receiver));
}

void rrr_event_queue_destroy (
		struct rrr_event_queue *queue
) {
	RRR_DBG_9_PRINTF("EQ DSTY %p\n", queue);

	if (queue->receiver_max > 0) {
		for (rrr_event_receiver_handle i = 0; i < queue->receiver_count; i++) {
			__rrr_event_receiver_cleanup(queue, i);
		}
		rrr_free(queue->receivers);
		rrr_free(queue->receiver_envelopes);
	}

	event_base_free(queue->event_base);
	rrr_free(queue);
}

void rrr_event_queue_destroy_void (
		void *queue
) {
	rrr_event_queue_destroy(queue);
}

#ifdef RRR_WITH_LIBEVENT_DEBUG
static int debug_active = 0;
#endif

int rrr_event_queue_new (
		struct rrr_event_queue **target,
		rrr_event_receiver_handle receiver_max
) {
	int ret = 0;


#ifdef RRR_WITH_LIBEVENT_DEBUG
	if (!debug_active) {
		event_enable_debug_mode();
		event_enable_debug_logging(EVENT_DBG_ALL);
		debug_active = 1;
	}
#endif
	struct event_config *cfg = NULL;

	*target = NULL;

	struct rrr_event_queue *queue = NULL;

	if ((cfg = event_config_new()) == NULL) {
		RRR_MSG_0("Could not create event config in %s\n", __func__);
		ret = 1;
		goto out;
	}

	// epoll does not work with UNIX files, use poll instead
	if (event_config_avoid_method(cfg, "epoll") != 0) {
		RRR_MSG_0("event_config_avoid_method() failed in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((queue = rrr_allocate_zero(sizeof(*queue))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((queue->event_base = event_base_new_with_config(cfg)) == NULL) {
		RRR_MSG_0("Could not create event base in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	if (event_base_priority_init (queue->event_base, RRR_EVENT_PRIORITY_COUNT) != 0) {
		RRR_MSG_0("Failed to initialize priority queues in %s\n", __func__);
		ret = 1;
		goto out_destroy_event_base;
	}

	if (receiver_max > 0) {
		if ((queue->receivers = rrr_allocate_zero(sizeof(*queue->receivers) * receiver_max)) == NULL) {
			RRR_MSG_0("Could not allocate receivers in %s\n", __func__);
			ret = 1;
			goto out_destroy_event_base;
		}

		if ((queue->receiver_envelopes = rrr_allocate_zero(sizeof(*queue->receiver_envelopes) * receiver_max)) == NULL) {
			RRR_MSG_0("Could not allocate envelopes in %s\n", __func__);
			ret = 1;
			goto out_destroy_receivers;
		}

		queue->receiver_max = receiver_max;
	}

	*target = queue;

	goto out;
//	out_destroy_envelopes:
//		rrr_free(queue->receiver_envelopes);
	out_destroy_receivers:
		rrr_free(queue->receivers);
	out_destroy_event_base:
		event_base_free(queue->event_base);
	out_free:
		rrr_free(queue);
	out:
		if (cfg != NULL) {
		        event_config_free(cfg);
		}
		return ret;
}
