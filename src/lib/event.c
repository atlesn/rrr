/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <event2/event.h>
#include <event2/thread.h>

#include "log.h"
#include "event.h"
#include "threads.h"
#include "rrr_strerror.h"
#include "util/posix.h"
#include "util/rrr_time.h"

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int rrr_event_libevent_initialized = 0;

struct rrr_event {
	uint8_t function;
	uint8_t flags;
	uint16_t amount;
};

struct rrr_event_queue {
	uint8_t queue_rpos;
	uint8_t queue_wpos;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct event_base *event_base;
	struct rrr_event queue[0xff];
	int (*functions[0xff])(RRR_EVENT_FUNCTION_ARGS);
};

void rrr_event_queue_destroy (
		struct rrr_event_queue *queue
) {
	pthread_mutex_destroy(&queue->lock);
	pthread_cond_destroy(&queue->cond);
	munmap(queue, sizeof(*queue));
	event_base_free(queue->event_base);
}

int rrr_event_queue_new (
		struct rrr_event_queue **target
) {
	int ret = 0;

	pthread_mutex_lock(&init_lock);
	if (rrr_event_libevent_initialized++ == 0) {
		ret = evthread_use_pthreads();
	}
	pthread_mutex_unlock(&init_lock);

	if (ret != 0) {
		RRR_MSG_0("evthread_use_pthreads() failed in rrr_event_queue_new\n");
		ret = 1;
		goto out;
	}

	*target = NULL;

	struct rrr_event_queue *queue = NULL;

	if ((queue = rrr_posix_mmap(sizeof(*queue))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in rrr_event_queue_new\n");
		ret = 1;
		goto out;
	}

	if ((rrr_posix_mutex_init(&queue->lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
		RRR_MSG_0("Could not initialize mutex B in rrr_event_queue_init\n");
		ret = 1;
		goto out_munmap;
	}

	if ((rrr_posix_cond_init(&queue->cond, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
		RRR_MSG_0("Could not initialize cond in rrr_event_queue_init\n");
		ret = 1;
		goto out_destroy_lock;
	}

	if ((queue->event_base = event_base_new()) == NULL) {
		RRR_MSG_0("Could not create event base in rrr_event_queue_init\n");
		ret = 1;
		goto out_destroy_cond;
	}

	*target = queue;

	goto out;
//	out_destroy_event_base:
//		event_base_free(queue->event_base);
	out_destroy_cond:
		pthread_cond_destroy(&queue->cond);
	out_destroy_lock:
		pthread_mutex_destroy(&queue->lock);
	out_munmap:
		munmap(queue, sizeof(*queue));
	out:
		return ret;
}

void rrr_event_function_set (
		struct rrr_event_queue *handle,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS)
) {
	handle->functions[code] = function;
}

int rrr_event_dispatch (
		struct rrr_event_queue *queue,
		unsigned int periodic_interval_us,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS),
		void *arg
) {
	int ret = 0;

	uint64_t time_periodic_call = 0;

	while (ret == 0) {
		uint8_t function = 0;
		uint8_t flags = 0;
		uint16_t amount = 0;

		{
			pthread_mutex_lock(&queue->lock);

			unsigned int sleep_time = 100 * 1000; // 100 ms
			if (sleep_time > periodic_interval_us) {
				sleep_time = periodic_interval_us;
			}

			if (queue->queue[queue->queue_rpos].amount == 0) {
				struct timespec wakeup_time;
				rrr_time_gettimeofday_timespec(&wakeup_time, sleep_time);
				ret = pthread_cond_timedwait(&queue->cond, &queue->lock, &wakeup_time);
			}

			struct rrr_event event  = queue->queue[queue->queue_rpos];

			if (event.amount > 0) {
				memset (&queue->queue[queue->queue_rpos], '\0', sizeof(queue->queue[0]));
				queue->queue_rpos++
;
				function = event.function;
				flags = event.flags;
				amount = event.amount;
			}

			pthread_mutex_unlock(&queue->lock);
		}

		if (ret != 0 && ret != ETIMEDOUT) {
			RRR_MSG_0("pthread_cond_wait failed in rrr_event_dispatch_loop: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		ret = 0;

		uint64_t time_now;

		periodic_check:
		time_now = rrr_time_get_64();

		if (time_now - time_periodic_call >= periodic_interval_us) {
			if ((ret = function_periodic(arg)) != 0) {
				goto out;
			}
			time_periodic_call = time_now;
		}

		if (amount > 0) {
			if (queue->functions[function] == NULL) {
				RRR_MSG_0("Function %u was not registered in rrr_event_dispatch_loop\n", function);
				abort();
				ret = 1;
				goto out;
			}

			int tick = 0;
			while (amount > 0) {
				if ((++tick) % 65535 == 0) {
					goto periodic_check;
				}
				uint16_t amount_new = amount;
				if ((ret = queue->functions[function](&amount_new, flags, arg)) != 0) {
					goto out;
				}
				if (amount_new > amount) {
					RRR_BUG("BUG: Amount increased after event function, possible underflow\n");
				}
				amount = amount_new;
			}
		}
	}

	out:
	return ret & ~(RRR_EVENT_EXIT);
}

static void __rrr_event_pass_add_maximum_amount (
		uint16_t *amount,
		struct rrr_event *event
) {
	const uint16_t available = 0xffff - event->amount;
	if (*amount > available) {
		event->amount += available;
		*amount -= available;
	} else {
		event->amount += *amount;
		*amount = 0;
	}
}

void rrr_event_pass (
		struct rrr_event_queue *queue,
		uint8_t function,
		uint8_t flags,
		uint16_t amount
) {
	pthread_mutex_lock(&queue->lock);

	for (;;) {
		// Sneak peak at previous write, maybe it's the same function
		uint8_t wpos = queue->queue_wpos;

		const uint8_t wpos_prev = wpos - 1;	
		struct rrr_event *event = &queue->queue[wpos_prev];
		if (event->function == function && event->flags == flags && event->amount > 0 && event->amount < 0xffff) {
			__rrr_event_pass_add_maximum_amount(&amount, event);
		}

		if (amount == 0) {
			goto out;
		}

		// If wpos is full, go backwards in the ring to find already
		// stored events with the same function and flags
		do {
			event = &queue->queue[wpos];

			if (event->amount == 0) {
				// Write to free location
				event->function = function;
				event->flags = flags;
				event->amount = amount;
				queue->queue_wpos++;
				pthread_cond_broadcast(&queue->cond);
				amount = 0;
			}
			else if (wpos == queue->queue_rpos) {
				// Don't add to oldest entry
			}
			else if (event->function == function && event->flags == flags && event->amount < 0xffff) {
				__rrr_event_pass_add_maximum_amount(&amount, event);
			}

			if (amount == 0) {
				goto out;
			}
		} while(--wpos != queue->queue_wpos);

		// Event queue was full :-(
		pthread_mutex_unlock(&queue->lock);
		rrr_posix_usleep(5000); // 5 ms
		pthread_mutex_lock(&queue->lock);
	}

	out:
	pthread_mutex_unlock(&queue->lock);
}
