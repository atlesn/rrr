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

#include "linked_list.h"

struct rrr_stats_handle_list_entry {
	RRR_LL_NODE(struct rrr_stats_handle_list_entry);
	unsigned int stats_handle;
};

struct rrr_stats_handle_list {
	RRR_LL_HEAD(struct rrr_stats_handle_list_entry);
};

struct rrr_stats_engine {
	int initialized;
	int socket;
	pthread_mutex_t main_lock;
	struct rrr_stats_handle_list handle_list;
};

int rrr_stats_engine_init (struct rrr_stats_engine *stats);
void rrr_stats_engine_cleanup (struct rrr_stats_engine *stats);


#endif /* RRR_STATS_ENGINE_H */
