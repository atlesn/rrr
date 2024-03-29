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
#include "rrr_shm.h"
#include "rrr_types.h"

// Maximum number of memory maps in a collection
#define RRR_MMAP_COLLECTION_MAX 128

// Number of cleanup strikes before an empty map is freed
#define RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES 10

// After a certain number of allocations, a memory map is
// marked as BAD and will not be used for new allocations.

// The current average allocation count for all maps in a
// collection is set to be the allocation limit. These two
// values define the upper and lower bounds of this limit.

// Marking maps as BAD after some number of allocations is
// important to reduce fragmentation. Applications with
// different sized messages are very prone to fragmentation
// which could cause high memory usage and cause soft program
// restart due to all maps being full.
#define RRR_MMAP_COLLECTION_ALLOCATION_LIMIT_MAX 8192
#define RRR_MMAP_COLLECTION_ALLOCATION_LIMIT_MIN 128

// As an optimization, free() commands are not processed
// one by one, but more frees are collected and then freed.
#define RRR_MMAP_TO_FREE_LIST_MAX 16

// Flag set after a certain number of allocations to prevent more
// usage. This allows new memory to be allocated in series in new
// and clean mmaps.
#define RRR_MMAP_COLLECTION_FLAG_BAD (1<<0)

typedef rrr_biglength rrr_mmap_handle;

struct rrr_mmap_stats;
struct rrr_mmap_collection;

struct rrr_mmap_heap_index {
	uintptr_t heap_min;
	uintptr_t heap_max;
	size_t mmap_idx;
};

struct rrr_mmap_collection_private_data {
	struct rrr_mmap_collection *collection;
	unsigned int version;
	struct rrr_mmap_heap_index minmax[RRR_MMAP_COLLECTION_MAX];
};

void *rrr_mmap_collection_resolve (
		struct rrr_mmap_collection *collection,
		rrr_shm_handle shm_handle,
		rrr_mmap_handle mmap_handle
);
void rrr_mmap_collection_fork_unregister (
		struct rrr_mmap_collection *collection
);
void rrr_mmap_collections_maintenance (
		struct rrr_mmap_stats *stats,
		struct rrr_mmap_collection *collections,
		size_t collection_count
);
void rrr_mmap_collections_destroy (
		struct rrr_mmap_collection *collections,
		size_t collection_count
);
int rrr_mmap_collections_new (
		struct rrr_mmap_collection **result,
		size_t collection_count,
		int is_pshared,
		const char *creator
);
void rrr_mmap_collection_private_datas_init (
		struct rrr_mmap_collection_private_data *private_datas,
		struct rrr_mmap_collection *collections,
		size_t collection_count
);
void *rrr_mmap_collection_allocate (
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
);
void *rrr_mmap_collections_allocate (
		struct rrr_mmap_collection *collections,
		size_t index,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
);
void *rrr_mmap_collection_allocate_with_handles (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
);
int rrr_mmap_collections_free (
		struct rrr_mmap_collection_private_data *private_datas,
		size_t collection_count,
		void *ptr
);

static inline int rrr_mmap_collection_new (
		struct rrr_mmap_collection **result,
		int is_pshared,
		const char *creator
) {
	return rrr_mmap_collections_new(result, 1, is_pshared, creator);
}

static inline void rrr_mmap_collection_maintenance (
		struct rrr_mmap_stats *stats,
		struct rrr_mmap_collection *collection
) {
	rrr_mmap_collections_maintenance(stats, collection, 1);
}

static inline void rrr_mmap_collection_destroy (
		struct rrr_mmap_collection *collection
) {
	rrr_mmap_collections_destroy(collection, 1);
}

static inline void rrr_mmap_collection_private_data_init (
		struct rrr_mmap_collection_private_data *private_data,
		struct rrr_mmap_collection *collection
) {
	rrr_mmap_collection_private_datas_init (private_data, collection, 1);
}

static inline int rrr_mmap_collection_free (
		struct rrr_mmap_collection_private_data *private_data,
		void *ptr
) {
	return rrr_mmap_collections_free(private_data, 1, ptr);
}

#endif /* RRR_MMAP_H */
