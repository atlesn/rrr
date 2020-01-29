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

#include <stddef.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "stats_engine.h"
#include "stats_instance.h"
#include "stats_message.h"
#include "../global.h"

int rrr_stats_instance_new (
		struct rrr_stats_instance **result,
		struct rrr_stats_engine *engine,
		const char *name
) {
	int ret = 0;
	*result = NULL;

	struct rrr_stats_instance *instance = malloc(sizeof(*instance));
	if (instance == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_stats_instance_new\n");
		ret = 1;
		goto out;
	}

	memset(instance, '\0', sizeof(*instance));

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

	// NOTE : We won't trap memory or other errors here very well as program continues to run upon any error
	if ((ret = rrr_stats_engine_handle_obtain(&instance->stats_handle, engine)) != 0) {
		VL_DEBUG_MSG_1("Could not obtain stats handle in rrr_stats_instance_new, statistics will be disabled. Return was %i.\n", ret);
		ret = 0;
	}

	instance->engine = engine;

	*result = instance;
	goto out;

//	out_free_name:
//		RRR_FREE_IF_NOT_NULL(instance->name);
	out_destroy_mutex:
		pthread_mutex_destroy(&instance->lock);
	out_free:
		RRR_FREE_IF_NOT_NULL(instance);

	out:
	return ret;
}

void rrr_stats_instance_destroy (
		struct rrr_stats_instance *instance
) {
	if (instance->stats_handle != 0) {
		rrr_stats_engine_handle_unregister(instance->engine, instance->stats_handle);
	}
	RRR_FREE_IF_NOT_NULL(instance->name);
	pthread_mutex_destroy(&instance->lock);
	free(instance);
}

void rrr_stats_instance_destroy_void (
		void *instance
) {
	rrr_stats_instance_destroy(instance);
}

int rrr_stats_instance_post_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		const char *text
) {
	int ret = 0;
	struct rrr_stats_message message;

	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		goto out;
	}

	if (rrr_stats_message_init (
			&message,
			RRR_STATS_MESSAGE_TYPE_TEXT,
			(sticky != 0 ? RRR_STATS_MESSAGE_FLAGS_STICKY : 0),
			path_postfix,
			text,
			strlen(text) + 1
	) != 0) {
		VL_MSG_ERR("Could not initialize statistics message in rrr_stats_message_post_text\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_stats_engine_post_message (
			instance->engine,
			instance->stats_handle,
			RRR_STATS_INSTANCE_PATH_PREFIX,
			&message
	)) != 0) {
		VL_MSG_ERR("Error returned from post function in rrr_stats_message_post_text\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_stats_instance_post_base10_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		long long int value
) {
	char text[128];

	VL_ASSERT(sizeof(long long int) <= 64, long_long_is_lteq_64);

	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		return 0;
	}

	sprintf(text, "%lli", value);

	return rrr_stats_instance_post_text(instance, path_postfix, sticky, text);
}

int rrr_stats_instance_post_default_stickies (
		struct rrr_stats_instance *instance
) {
	int ret = 0;

	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		goto out;
	}

	if ((ret = rrr_stats_instance_post_text(instance, RRR_STATS_MESSAGE_PATH_INSTANCE_NAME, 1, instance->name)) != 0) {
		goto out;
	}

	out:
	return ret;
}
