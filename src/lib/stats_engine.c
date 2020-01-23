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

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stddef.h>

#include "../global.h"
#include "gnu.h"
#include "stats_engine.h"
#include "rrr_socket.h"
#include "linked_list.h"
#include "vl_time.h"
#include "random.h"

int rrr_stats_engine_init (struct rrr_stats_engine *stats) {
	int ret = 0;
	char *filename = NULL;

	memset (stats, '\0', sizeof(*stats));

	if (pthread_mutex_init(&stats->main_lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize mutex in rrr_stats_engine_init\n");
		ret = 1;
		goto out;
	}

	pid_t pid = getpid();
	if (rrr_asprintf(&filename, "/tmp/rrr_stats.%i\n", pid) <= 0) {
		VL_MSG_ERR("Could not generate filename for statistics socket\n");
		ret = 1;
		goto out_destroy_mutex;
	}

	unlink(filename); // OK to ignore errors

	if (rrr_socket_unix_create_bind_and_listen(&stats->socket, "rrr_stats_engine", filename, 2, 1) != 0) {
		VL_MSG_ERR("Could not create socket for statistics engine with filename '%s'\n", filename);
		ret = 1;
		goto out_destroy_mutex;
	}

	VL_DEBUG_MSG_1("Statistics engine started, listening at %s\n", filename);

	stats->initialized = 1;
	goto out;

	out_destroy_mutex:
	pthread_mutex_destroy(&stats->main_lock);

	out:
	RRR_FREE_IF_NOT_NULL(filename);
	return ret;
}

void rrr_stats_engine_cleanup (struct rrr_stats_engine *stats) {
	if (stats->initialized == 0) {
		return;
	}

	// Not waterproof, cleanup should not be called before threads have exited. This
	// is not possible, of course, if some thread is hanged up in which we take a
	// certain risk by destroying the mutex at program exit.
	pthread_mutex_lock(&stats->main_lock);
	RRR_LL_DESTROY(&stats->handle_list, struct rrr_stats_handle_list_entry, free(node));
	stats->initialized = 0;
	pthread_mutex_unlock(&stats->main_lock);

	rrr_socket_close_ignore_unregistered(stats->socket);
	stats->socket = 0;
	pthread_mutex_destroy(&stats->main_lock);
}

static int __rrr_stats_engine_handle_exists_nolock (struct rrr_stats_engine *stats, unsigned int stats_handle) {
	RRR_LL_ITERATE_BEGIN(&stats->handle_list, struct rrr_stats_handle_list_entry);
		if (node->stats_handle == stats_handle) {
			return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

static int __rrr_stats_engine_register_handle_nolock (struct rrr_stats_engine *stats, unsigned int stats_handle) {
	int ret = 0;

	struct rrr_stats_handle_list_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		VL_MSG_ERR("Could not allocate memory in _rrr_stats_engine_register_handle_nolock\n");
		ret = 1;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));

	entry->stats_handle = stats_handle;

	RRR_LL_APPEND(&stats->handle_list, entry);

	out:
	return ret;
}

int rrr_stats_engine_obtain_handle (unsigned int *handle, struct rrr_stats_engine *stats) {
	int ret = 0;

	*handle = 0;

	if (stats->initialized == 0) {
		VL_MSG_ERR("Could not create handle in rrr_stats_engine_obtain_handle, not initialized\n");
		ret = 1;
		goto out;
	}

	pthread_mutex_lock(&stats->main_lock);

	unsigned int new_handle = 0;
	int iterations = 0;

	do {
		new_handle = rrr_rand();
		if (++iterations % 100000 == 0) {
			VL_DEBUG_MSG("Warning: Huge number of handles in statistics engine\n");
		}
	} while (__rrr_stats_engine_handle_exists_nolock(stats, new_handle));

	if (__rrr_stats_engine_register_handle_nolock(stats, new_handle) != 0) {
		VL_MSG_ERR("Could not register handle in rrr_stats_engine_obtain_handle\n");
		ret = 1;
		goto out_unlock;
	}

	*handle = new_handle;

	out_unlock:
		pthread_mutex_unlock(&stats->main_lock);
	out:
		return ret;
}
