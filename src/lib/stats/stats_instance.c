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
#include <stdint.h>

#include "../log.h"

#include "stats_engine.h"
#include "stats_instance.h"
#include "stats_message.h"

#include "../rrr_time.h"
#include "../linked_list.h"
#include "../macro_utils.h"

static int __rrr_stats_instance_rate_counter_new (
		struct rrr_stats_instance_rate_counter **target,
		unsigned int id,
		const char *name
) {
	int ret = 0;

	*target = NULL;

	struct rrr_stats_instance_rate_counter *result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_stats_instance_rate_counter_new A\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((result->name = strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_stats_instance_rate_counter_new B\n");
		ret = 1;
		goto out_free;
	}

	result->id = id;
	result->prev_time = rrr_time_get_64();

	*target = result;

	goto out;

	out_free:
		free(result);
	out:
		return ret;
}

static int __rrr_stats_instance_rate_counter_destroy (
		struct rrr_stats_instance_rate_counter *counter
) {
	RRR_FREE_IF_NOT_NULL(counter->name);
	free(counter);
	return 0;
}

static struct rrr_stats_instance_rate_counter *__rrr_stats_instance_rate_counter_find (
		struct rrr_stats_instance *instance,
		unsigned int id
) {
	RRR_LL_ITERATE_BEGIN(&instance->rate_counters, struct rrr_stats_instance_rate_counter);
		if (node->id == id) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

int rrr_stats_instance_new (
		struct rrr_stats_instance **result,
		struct rrr_stats_engine *engine,
		const char *name
) {
	int ret = 0;
	*result = NULL;

	struct rrr_stats_instance *instance = malloc(sizeof(*instance));
	if (instance == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_stats_instance_new\n");
		ret = 1;
		goto out;
	}

	memset(instance, '\0', sizeof(*instance));

	if (pthread_mutex_init(&instance->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize mutex in  rrr_stats_instance_new\n");
		ret = 1;
		goto out_free;
	}

	if ((instance->name = strdup(name)) == NULL) {
		RRR_MSG_0("Could not save instance name in rrr_stats_instance_new\n");
		ret = 1;
		goto out_destroy_mutex;
	}

	// NOTE : We won't trap memory or other errors here very well as program continues to run upon any error
	if ((ret = rrr_stats_engine_handle_obtain(&instance->stats_handle, engine)) != 0) {
		RRR_DBG_1("Could not obtain stats handle in rrr_stats_instance_new, statistics will be disabled. Return was %i.\n", ret);
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
	if (instance == NULL) {
		return;
	}
	if (instance->stats_handle != 0) {
		rrr_stats_engine_handle_unregister(instance->engine, instance->stats_handle);
	}
	RRR_LL_DESTROY(&instance->rate_counters, struct rrr_stats_instance_rate_counter, __rrr_stats_instance_rate_counter_destroy(node));
	RRR_FREE_IF_NOT_NULL(instance->name);
	pthread_mutex_destroy(&instance->lock);
	free(instance);
}

void rrr_stats_instance_destroy_void (
		void *instance
) {
	rrr_stats_instance_destroy(instance);
}

static int __rrr_stats_instance_post_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		uint8_t type,
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
			type,
			(sticky != 0 ? RRR_STATS_MESSAGE_FLAGS_STICKY : 0),
			path_postfix,
			text,
			strlen(text) + 1
	) != 0) {
		RRR_MSG_0("Could not initialize statistics message in rrr_stats_message_post_text\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_stats_engine_post_message (
			instance->engine,
			instance->stats_handle,
			RRR_STATS_INSTANCE_PATH_PREFIX,
			&message
	)) != 0) {
		RRR_MSG_0("Error returned from post function in rrr_stats_message_post_text\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_stats_instance_post_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		const char *text
) {
	return __rrr_stats_instance_post_text(instance, path_postfix, sticky, RRR_STATS_MESSAGE_TYPE_TEXT, text);
}

int rrr_stats_instance_post_base10_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		long long int value
) {
	char text[128];

	RRR_ASSERT(sizeof(long long int) <= 64, long_long_is_lteq_64);

	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		return 0;
	}

	sprintf(text, "%lli", value);

	return __rrr_stats_instance_post_text(instance, path_postfix, sticky, RRR_STATS_MESSAGE_TYPE_BASE10_TEXT, text);
}

int rrr_stats_instance_post_unsigned_base10_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		long long unsigned int value
) {
	char text[128];

	RRR_ASSERT(sizeof(long long unsigned int) <= 64, long_long_is_lteq_64);

	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		return 0;
	}

	sprintf(text, "%llu", value);

	return __rrr_stats_instance_post_text(instance, path_postfix, sticky, RRR_STATS_MESSAGE_TYPE_BASE10_TEXT, text);
}

int rrr_stats_instance_post_double_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		double value
) {
	char text[128];

	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		return 0;
	}

	sprintf(text, "%f", value);

	return __rrr_stats_instance_post_text(instance, path_postfix, sticky, RRR_STATS_MESSAGE_TYPE_DOUBLE_TEXT, text);
}

int rrr_stats_instance_update_rate (
		struct rrr_stats_instance *instance,
		unsigned int id,
		const char *name,
		unsigned int count
) {
	if (instance->stats_handle == 0) {
		// Not registered with statistics engine
		return 0;
	}

	struct rrr_stats_instance_rate_counter *counter = __rrr_stats_instance_rate_counter_find(instance, id);
	if (counter == NULL) {
		if (__rrr_stats_instance_rate_counter_new(&counter, id, name) != 0) {
			RRR_MSG_0("Could not create rate counter in rrr_stats_instance_update_rate\n");
			return 1;
		}
		RRR_LL_APPEND(&instance->rate_counters, counter);
	}

	counter->accumulator += count;
	counter->accumulator_total += count;

	uint64_t time_now = rrr_time_get_64();
	if (time_now - counter->prev_time > RRR_STATS_INSTANCE_RATE_POST_INTERVAL_MS * 1000) {
		double second = 1 * 1000 * 1000;
		double period = time_now - counter->prev_time;
		double per_period = ((double) counter->accumulator * 1000.0 * 1000.0) / period;

		double factor = ((double) second) / ((double) period);
		double per_second = factor * per_period;

		counter->accumulator = 0;
		counter->prev_time = time_now;

		int ret = 0;

		char path_buf[128];
		if (strlen(name) > 64) {
			RRR_BUG("name too long in rrr_stats_instance_update_rate\n");
		}

		sprintf (path_buf, "%s/per_second", name);
		ret |= rrr_stats_instance_post_double_text(instance, path_buf, 0, per_second);
		sprintf (path_buf, "%s/total", name);
		ret |= rrr_stats_instance_post_base10_text(instance, path_buf, 0, counter->accumulator_total);
		sprintf (path_buf, "%s/class", name);
		ret |= rrr_stats_instance_post_text(instance, path_buf, 0, "ratecounter");

		return ret;
	}

	return 0;
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
