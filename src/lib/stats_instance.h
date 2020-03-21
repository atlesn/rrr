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

#define RRR_STATS_INSTANCE_RATE_POST_INTERVAL_MS 500

#include <pthread.h>

#include "linked_list.h"

// Should be done together with other pthread_cleanup_push at top of thread entry function
#define RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH						\
	struct rrr_stats_instance *stats = NULL;									\
	if (rrr_stats_instance_new (												\
		&stats,																	\
		INSTANCE_D_STATS(thread_data),											\
		INSTANCE_D_NAME(thread_data)											\
	) != 0) {																	\
		RRR_MSG_ERR("Could not initialize stats engine for instance %s\n",		\
				INSTANCE_D_NAME(thread_data)									\
		);																		\
		pthread_exit(0);														\
	}																			\
	pthread_cleanup_push(rrr_stats_instance_destroy_void, stats)

// Should be done before running main loop in thread entry function
#define RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES								\
	do {if (rrr_stats_instance_post_default_stickies(stats) != 0) {				\
		RRR_MSG_ERR("Error while posting default sticky statistics instance %s\n", \
				INSTANCE_D_NAME(thread_data)									\
		);																		\
		pthread_exit(0);														\
	}} while(0)

// Should be done at bottom of thread entry function together with other pthread_cleanup_pop
#define RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP						\
	pthread_cleanup_pop(1); stats = NULL

#define RRR_STATS_INSTANCE_PATH_PREFIX "instances"

#define RRR_INSTANCE_POST_ARGUMENTS									\
	struct rrr_stats_instance *instance,							\
	const char *path_postfix,										\
	int sticky

struct rrr_stats_engine;

struct rrr_stats_instance_rate_counter {
	RRR_LL_NODE(struct rrr_stats_instance_rate_counter);
	unsigned int id;
	char *name;
	unsigned int accumulator;
	unsigned int accumulator_total;
	uint64_t prev_time;
};

struct rrr_stats_instance_rate_counter_collection {
	RRR_LL_HEAD(struct rrr_stats_instance_rate_counter);
};

struct rrr_stats_instance {
	char *name;
	pthread_mutex_t lock;
	unsigned int stats_handle;
	struct rrr_stats_engine *engine;
	struct rrr_stats_instance_rate_counter_collection rate_counters;
};

int rrr_stats_instance_new (
		struct rrr_stats_instance **result,
		struct rrr_stats_engine *engine,
		const char *name
);
void rrr_stats_instance_destroy (
		struct rrr_stats_instance *instance
);
void rrr_stats_instance_destroy_void (
		void *instance
);
int rrr_stats_instance_post_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		const char *text
);
int rrr_stats_instance_post_base10_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		long long int value
);
int rrr_stats_instance_post_unsigned_base10_text (
		RRR_INSTANCE_POST_ARGUMENTS,
		long long unsigned int value
);
int rrr_stats_instance_post_default_stickies (
		struct rrr_stats_instance *instance
);
int rrr_stats_instance_update_rate (
		struct rrr_stats_instance *instance,
		unsigned int id,
		const char *name,
		unsigned int count
);

#endif /* RRR_STATS_INSTANCE_H */
