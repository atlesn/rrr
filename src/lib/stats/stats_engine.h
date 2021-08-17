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

#ifndef RRR_STATS_ENGINE_H
#define RRR_STATS_ENGINE_H

#include <pthread.h>
#include <inttypes.h>
#include <sys/socket.h>

#include "../socket/rrr_socket_client.h"
#include "../util/linked_list.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "stats_message.h"

#define RRR_STATS_ENGINE_STICKY_SEND_INTERVAL_MS 1000

struct event;

struct rrr_stats_named_message_list {
	RRR_LL_NODE(struct rrr_stats_named_message_list);
	RRR_LL_HEAD(struct rrr_msg_stats);
	unsigned int owner_handle;
	uint64_t last_seen;
};

struct rrr_stats_named_message_list_collection {
	RRR_LL_HEAD(struct rrr_stats_named_message_list);
};

struct rrr_stats_log_journal {
	RRR_LL_HEAD(struct rrr_msg_stats);
};

struct rrr_stats_engine {
	int initialized;
	int socket;
	int log_hook_handle;
	pthread_mutex_t main_lock;

	// Errors occuring while logging. The log functions have no
	// return values, we must store the return value and check
	// in our periodic function.
	int exit_now_ret;

	// Access through macro only to update usercount
	pthread_mutex_t journal_lock;
	int journal_lock_usercount;

	struct rrr_event_queue *queue;
	struct rrr_event_collection events;
	rrr_event_handle event_periodic;

	struct rrr_stats_named_message_list_collection named_message_list;
	struct rrr_socket_client_collection *client_collection;

	struct rrr_stats_log_journal log_journal_input;
};

int rrr_stats_engine_init (
		struct rrr_stats_engine *stats,
		struct rrr_event_queue *queue
);
void rrr_stats_engine_cleanup (struct rrr_stats_engine *stats);
int rrr_stats_engine_tick (struct rrr_stats_engine *stats);

int rrr_stats_engine_handle_obtain (
		unsigned int *handle,
		struct rrr_stats_engine *stats
);
void rrr_stats_engine_handle_unregister (
		struct rrr_stats_engine *stats,
		unsigned int handle
);
int rrr_stats_engine_post_message (
		struct rrr_stats_engine *stats,
		unsigned int handle,
		const char *path_prefix,
		const struct rrr_msg_stats *message
);

#endif /* RRR_STATS_ENGINE_H */
