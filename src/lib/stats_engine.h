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

#include "linked_list.h"
#include "rrr_socket_client.h"

#define RRR_STATS_ENGINE_STICKY_SEND_INTERVAL_MS 1000

struct rrr_stats_message;

struct rrr_stats_named_message_list {
	RRR_LL_NODE(struct rrr_stats_named_message_list);
	RRR_LL_HEAD(struct rrr_stats_message);
	unsigned int owner_handle;
	uint64_t last_seen;
};

struct rrr_stats_named_message_list_collection {
	RRR_LL_HEAD(struct rrr_stats_named_message_list);
};

struct rrr_stats_engine {
	int initialized;
	int socket;
	pthread_mutex_t main_lock;
	struct rrr_stats_named_message_list_collection named_message_list;
	struct rrr_socket_client_collection client_collection;
};

int rrr_stats_engine_init (struct rrr_stats_engine *stats);
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
		const struct rrr_stats_message *message
);

#endif /* RRR_STATS_ENGINE_H */
