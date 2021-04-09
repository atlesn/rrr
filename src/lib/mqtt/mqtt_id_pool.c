/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "../log.h"

#include "mqtt_id_pool.h"

#include "../util/macro_utils.h"
#include "../util/posix.h"

int rrr_mqtt_id_pool_init (struct rrr_mqtt_id_pool *pool) {
	memset (pool, '\0', sizeof(*pool));

	return 0;
}

void rrr_mqtt_id_pool_clear (struct rrr_mqtt_id_pool *pool) {
	free(pool->pool);
	pool->pool = NULL;
	pool->allocated_majors = 0;
	pool->last_allocated_id = 0;
}

void rrr_mqtt_id_pool_destroy (struct rrr_mqtt_id_pool *pool) {
	RRR_FREE_IF_NOT_NULL(pool->pool);
}

static inline int __rrr_mqtt_id_pool_realloc(struct rrr_mqtt_id_pool *pool, ssize_t steps) {
	ssize_t new_majors = pool->allocated_majors + steps;
	if (new_majors > (ssize_t) RRR_MQTT_ID_POOL_SIZE_IN_32) {
		return 1;
	}

//	ssize_t old_size = pool->allocated_majors * sizeof(*(pool->pool));
	ssize_t new_size = new_majors * sizeof(*(pool->pool));

	uint32_t *new_pool = realloc(pool->pool, new_size);
	if (new_pool == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mqtt_id_pool_realloc\n");
		return 1;
	}

	for (ssize_t i = pool->allocated_majors; i < new_majors; i++) {
		new_pool[i] = 0;
	}

	pool->pool = new_pool;
	pool->allocated_majors = new_majors;

	return 0;
}

static inline uint16_t __rrr_mqtt_id_pool_get_id_32 (uint32_t *source) {
	if (*source == 0xffffffff) {
		return 0;
	}

	uint32_t tmp = *source;
	for (uint16_t i = 0; i < 32; i++) {
		if ((tmp & 1) == 0) {
			*source |= 1 << i;
			return i + 1;
		}
		tmp >>= 1;
	}

	RRR_BUG("Did not find the free bit in __rrr_mqtt_id_pool_get_id_32\n");

	return 0;
}

#define MIN_MAJ_MASK(id)						\
		uint32_t min = (id - 1) % 32;			\
		ssize_t maj = (id - 1 - min) / 32;		\
		uint32_t mask = (1 << min)

uint16_t rrr_mqtt_id_pool_get_id (struct rrr_mqtt_id_pool *pool) {
	uint16_t ret = 0; // = no id available

	ret = ++(pool->last_allocated_id);
	if (ret == 0) {
		ret++;
	}
	MIN_MAJ_MASK(ret);

	RRR_DBG_3("Get ID, min %" PRIu32 ", maj %li, mask %" PRIu32 ", size %li, pool block %" PRIu32 "\n",
			min,
			maj,
			mask,
			pool->allocated_majors,
			(maj < pool->allocated_majors ? pool->pool[maj] : 0)
	);

	if (maj < pool->allocated_majors && (pool->pool[maj] & mask) == 0) {
		pool->pool[maj] |= mask;
		RRR_DBG_3("Fast-allocated ID %u, pool block %" PRIu32 "\n", ret, pool->pool[maj]);
		goto out;
	}

	ret = 0;

	retry:
	for (int i = 0; i < pool->allocated_majors; i++) {
		uint16_t ret_tmp = __rrr_mqtt_id_pool_get_id_32 (&(pool->pool[i]));
		if (ret_tmp > 0) {
			ret = ret_tmp + 32 * i;
			RRR_DBG_3("Allocated ID %u, pool block %" PRIu32 "\n", ret, pool->pool[i]);
			goto out;
		}
	}

	if (__rrr_mqtt_id_pool_realloc(pool, RRR_MQTT_ID_POOL_STEP_SIZE_IN_32) == 0) {
		goto retry;
	}
	else {
// Noisy message
//		RRR_DBG_1("No more room in ID pool\n");
	}

	out:
	pool->last_allocated_id = ret;
	return ret;
}

void rrr_mqtt_id_pool_release_id (struct rrr_mqtt_id_pool *pool, uint16_t id) {
	MIN_MAJ_MASK(id);

	RRR_DBG_3("Release ID %u, min %" PRIu32 ", maj %li, mask %" PRIu32 ", size %li, pool block %" PRIu32 "\n",
			id, min, maj, mask, pool->allocated_majors, pool->pool[maj]);

	if (maj >= pool->allocated_majors) {
		RRR_BUG("Tried to release ID which was not yet allocated in rrr_mqtt_id_pool_release_id\n");
	}

	if ((pool->pool[maj] & mask) == 0) {
		RRR_BUG("Tried to release unused ID in rrr_mqtt_id_pool_release_id\n");
	}

	pool->pool[maj] &= ~mask;
}
