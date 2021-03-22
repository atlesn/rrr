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

#ifndef RRR_EVENT_H
#define RRR_EVENT_H

#include <stdint.h>
#include <pthread.h>

#include "read_constants.h"

#define RRR_EVENT_FUNCTION_ARGS \
	uint16_t *amount, void *arg

#define RRR_EVENT_FUNCTION_PERIODIC_ARGS \
	void *arg

#define RRR_EVENT_QUEUE_FD_MAX \
	(0x100 * 2)

#define RRR_EVENT_OK     RRR_READ_OK
#define RRR_EVENT_ERR    RRR_READ_HARD_ERROR
#define RRR_EVENT_EXIT   RRR_READ_EOF

enum rrr_event_priority {
	RRR_EVENT_PRIORITY_HIGH,
	RRR_EVENT_PRIORITY_MID,
	RRR_EVENT_PRIORITY_LOW
};

// Default priority for events is MID (3 / 2 == 1), integer division

#define RRR_EVENT_PRIORITY_COUNT (RRR_EVENT_PRIORITY_LOW + 1)

struct rrr_event;
struct rrr_event_queue;

void rrr_event_queue_destroy (
		struct rrr_event_queue *queue
);
int rrr_event_queue_new (
		struct rrr_event_queue **target
);
int rrr_event_queue_reinit (
		struct rrr_event_queue *queue
);
struct event_base *rrr_event_queue_base_get (
		struct rrr_event_queue *queue
);
void rrr_event_queue_fds_get (
		int fds[RRR_EVENT_QUEUE_FD_MAX],
		size_t *fds_count,
		struct rrr_event_queue *queue
);
void rrr_event_function_set (
		struct rrr_event_queue *handle,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS)
);
void rrr_event_function_set_with_arg (
		struct rrr_event_queue *handle,
		uint8_t code,
		int (*function)(RRR_EVENT_FUNCTION_ARGS),
		void *arg
);
void rrr_event_callback_pause_set (
		struct rrr_event_queue *queue,
		void (*callback)(int *do_pause, void *callback_arg),
		void *callback_arg
);
int rrr_event_dispatch (
		struct rrr_event_queue *queue,
		unsigned int periodic_interval_us,
		int (*function_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS),
		void *arg
);
int rrr_event_pass (
		struct rrr_event_queue *queue,
		uint8_t function,
		uint16_t amount
);

#endif /* RRR_EVENT_H */
