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

#ifndef RRR_STATS_INSTANCE_H
#define RRR_STATS_INSTANCE_H

#include <pthread.h>

struct rrr_stats_engine;

struct rrr_stats_instance {
	char *name;
	pthread_mutex_t lock;
	int stats_handle;
	struct rrr_stats_engine *engine;
};

int rrr_stats_instance_new (struct rrr_stats_instance **result, struct rrr_stats_engine *engine, const char *name);
void rrr_stats_instance_destroy (struct rrr_stats_instance *instance);
void rrr_stats_instance_destroy_void (void *instance);

#endif /* RRR_STATS_INSTANCE_H */
