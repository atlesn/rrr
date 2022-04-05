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

#ifndef RRR_EVENT_STRUCT_H
#define RRR_EVENT_STRUCT_H

#include <pthread.h>

#include "event.h"
#include "event_functions.h"
#include "../socket/rrr_socket_eventfd.h"

struct rrr_event_queue;

struct rrr_event_function {
	int (*function)(RRR_EVENT_FUNCTION_ARGS);
	void *function_arg;
	void (*callback_pause)(RRR_EVENT_FUNCTION_PAUSE_ARGS);
	void *callback_pause_arg;
	struct rrr_socket_eventfd eventfd;
	struct event *signal_event;
	struct rrr_event_queue *queue;
	unsigned short index;
	unsigned short is_paused;
};

struct rrr_event_queue {
	struct event_base *event_base;

	struct rrr_event_function functions[RRR_EVENT_FUNCTION_MAX + 1];
	uint64_t deferred_amount[RRR_EVENT_FUNCTION_MAX + 1];

	struct event *periodic_event;
	struct event *unpause_event;

	int (*callback_periodic)(RRR_EVENT_FUNCTION_PERIODIC_ARGS);
	void *callback_arg;
	int callback_ret;
};

#endif /* RRR_EVENT_STRUCT_H */
