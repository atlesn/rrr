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
	stats->initialized = 0;
	pthread_mutex_unlock(&stats->main_lock);

	rrr_socket_close_ignore_unregistered(stats->socket);
	stats->socket = 0;
	pthread_mutex_destroy(&stats->main_lock);
}


int rrr_stats_instance_new (struct rrr_stats_instance **result, struct rrr_stats_engine *engine, const char *name) {
	int ret = 0;
	*result = NULL;

	struct rrr_stats_instance *instance = malloc(sizeof(*instance));
	if (instance == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_stats_instance_new\n");
		ret = 1;
		goto out;
	}

	if (pthread_mutex_init(&instance->lock, 0) != 0) {
		VL_MSG_ERR("Could not initialize mutex in  rrr_stats_instance_new\n");
		ret = 1;
		goto out_free;
	}

	if ((instance->name = strdup(name)) == NULL) {
		VL_MSG_ERR("Could not save instance name in rrr_stats_instance_new\n");
		ret = 1;
		goto out_destroy_mutex;
	}

	instance->engine = engine;

	*result = instance;
	goto out;

	out_destroy_mutex:
		pthread_mutex_destroy(&instance->lock);
	out_free:
		RRR_FREE_IF_NOT_NULL(instance);

	out:
	return ret;
}

void rrr_stats_instance_destroy (struct rrr_stats_instance *instance) {
	RRR_FREE_IF_NOT_NULL(instance->name);
	pthread_mutex_destroy(&instance->lock);
	free(instance);
}

void rrr_stats_instance_destroy_void (void *instance) {
	rrr_stats_instance_destroy(instance);
}
