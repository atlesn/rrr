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

#include "log.h"
#include "event.h"
#include "threads.h"
#include "rrr_strerror.h"
#include "util/posix.h"
#include "util/rrr_time.h"

void rrr_event_function_set (
		struct rrr_event_queue *handle,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS)
) {
	handle->functions[code] = function;
}

#define PERIODIC_EXPIRED() \
	(time_now - time_periodic_call >= 1 * 1000 * 1000)

int rrr_event_dispatch (
		struct rrr_event_queue *queue,
		pthread_mutex_t *mutex,
		pthread_cond_t *cond,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS),
		void *arg
) {
	int ret = 0;

	uint64_t time_periodic_call = 0;

	while (ret == 0) {

		struct rrr_event event;
		{
			pthread_mutex_lock(mutex);

			if (queue->queue[queue->queue_rpos].amount == 0) {
				struct timespec wakeup_time;
				rrr_time_gettimeofday_timespec(&wakeup_time, 100 * 1000); // 100 ms
				ret = pthread_cond_timedwait(cond, mutex, &wakeup_time);
			}

			event = queue->queue[queue->queue_rpos];

			if (event.amount > 0) {
				memset (&queue->queue[queue->queue_rpos], '\0', sizeof(queue->queue[0]));
				queue->queue_rpos++;
			}

			pthread_mutex_unlock(mutex);
		}

		if (ret != 0 && ret != ETIMEDOUT) {
			RRR_MSG_0("pthread_cond_wait failed in rrr_event_dispatch_loop: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		if (event.amount == 0) {
			continue;
		}

		if (queue->functions[event.function] == NULL) {
			RRR_MSG_0("Function %u was not registered in rrr_event_dispatch_loop\n", event.function);
			ret = 1;
			goto out;
		}

		uint64_t time_now;

		periodic_check:
		time_now = rrr_time_get_64();

		if (PERIODIC_EXPIRED()) {
			if ((ret = function_periodic(arg)) != 0) {
				goto out;
			}
			time_periodic_call = time_now;
		}

		int tick = 0;
		while (event.amount > 0) {
			if ((++tick) % 65535 == 0) {
				goto periodic_check;
			}
			if ((ret = queue->functions[event.function](&event.amount, event.flags, arg)) != 0) {
				goto out;
			}
		}
	}

	out:
	return ret;
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
		pthread_mutex_t *mutex,
		pthread_cond_t *cond,
		uint8_t function,
		uint8_t flags,
		uint16_t amount
) {
	pthread_mutex_lock(mutex);
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
				pthread_cond_broadcast(cond);
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
		pthread_mutex_unlock(mutex);
		rrr_posix_usleep(5000); // 5 ms
		pthread_mutex_lock(mutex);
	}

	out:
	pthread_mutex_unlock(mutex);
}
