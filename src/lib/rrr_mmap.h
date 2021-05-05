/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MMAP_H
#define RRR_MMAP_H

#include <pthread.h>
#include <inttypes.h>

#include "util/linked_list.h"

#define RRR_MMAP_COLLECTION_MAX 128
#define RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES 10
#define RRR_MMAP_COLLECTION_ALLOCATION_MAX 32768
#define RRR_MMAP_TO_FREE_LIST_MAX 16

// Flag set after a certain number of allocations to prevent more
// usage. This allows new memory to be allocated in series in new
// and clean mmaps.
#define RRR_MMAP_COLLECTION_FLAG_BAD (1<<0)

struct rrr_mmap_stats;

struct rrr_mmap {
	void *heap;
	int maintenance_cleanup_strikes;
	uint64_t allocation_count;
	uint8_t flags;
	pthread_mutex_t lock;
	uint64_t heap_size;
	uint64_t prev_allocation_failure_req_size;
	uint64_t prev_allocation_index_pos;
	size_t to_free_list_count;
	uintptr_t to_free_list[RRR_MMAP_TO_FREE_LIST_MAX];
	int is_shared;
};

struct rrr_mmap_heap_index {
	uintptr_t heap_min;
	uintptr_t heap_max;
	size_t mmap_idx;
};

struct rrr_mmap_collection {
	size_t mmap_count;
	struct rrr_mmap mmaps[RRR_MMAP_COLLECTION_MAX];
	struct rrr_mmap_heap_index minmax[RRR_MMAP_COLLECTION_MAX];
};

void rrr_mmap_free (
		struct rrr_mmap *mmap,
		void *ptr
);
void rrr_mmap_dump_indexes (
		struct rrr_mmap *mmap
);
void *rrr_mmap_allocate (
		struct rrr_mmap *mmap,
		uint64_t req_size
);
int rrr_mmap_heap_reallocate (
		struct rrr_mmap *mmap,
		uint64_t heap_size
);
int rrr_mmap_new (
		struct rrr_mmap **target,
		uint64_t heap_size,
		int is_shared
);
void rrr_mmap_destroy (
		struct rrr_mmap *mmap
);
void rrr_mmap_collections_maintenance (
		struct rrr_mmap_stats *stats,
		struct rrr_mmap_collection *collections,
		size_t collection_count,
		pthread_rwlock_t *index_lock
);
void rrr_mmap_collections_clear (
		struct rrr_mmap_collection *collections,
		size_t collection_count,
		pthread_rwlock_t *index_lock
);
void *rrr_mmap_collection_allocate (
		struct rrr_mmap_collection *collection,
		uint64_t bytes,
		uint64_t min_mmap_size,
		pthread_rwlock_t *index_lock,
		int is_shared
);
int rrr_mmap_collections_free (
		struct rrr_mmap_collection *collections,
		size_t collection_count,
		pthread_rwlock_t *index_lock,
		void *ptr
);

#endif /* RRR_MMAP_H */
