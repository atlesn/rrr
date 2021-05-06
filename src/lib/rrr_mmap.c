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

#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "rrr_mmap.h"
#include "rrr_mmap_stats.h"
#include "rrr_strerror.h"
#include "util/linked_list.h"
#include "util/rrr_time.h"
#include "util/posix.h"

/*
 * Description of allocator:
 *
 * The heap starts with a block index. A block index holds size and used flags for up to 64 blocks.
 *
 * The first allocated chunk gets the first data position which starts right after the index. The
 * index will then be updated setting the used bit for the chunk and by writing the size of the new
 * chunk at the first position in the size array.
 *
 * The next block will use the second element of the block size array and set the next used bit, and it's data
 * will be placed directly after the first block's data.
 *
 * After all 64 positions in the heap index is taken, a new index is created right after the last data block.
 *
 * A chunk is never completely freed, its space will always remain in the heap and index. It may however be re-used
 * if there is a new allocation with a size smaller than or equal to it's size.
 *
 * In the future, housekeeping functions may be made available to deal with holes in the heap.
 *
 */

#define RRR_MMAP_HEAP_CHUNK_MIN_SIZE 16

#define RRR_MMAP_SENTINEL_DEBUG

#ifdef RRR_MMAP_SENTINEL_DEBUG
static const uint64_t rrr_mmap_sentinel_template = 0xa0a0a0a00a0a0a0a;
#endif

struct rrr_mmap_heap_block_index {
	uint64_t block_used_map;
	uint64_t block_sizes[64];
};

void *rrr_mmap_resolve (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave,
		rrr_mmap_handle handle
) {
	return rrr_shm_resolve(shm_slave, mmap->shm_handle) + handle;
}

void *rrr_mmap_resolve_raw (
		struct rrr_shm_collection_slave *shm_slave,
		rrr_shm_handle shm_handle,
		rrr_mmap_handle mmap_handle
) {
	void *ret = rrr_shm_resolve(shm_slave, shm_handle);
	return (ret == NULL ? NULL : ret + mmap_handle);
}

#define DEFINE_HEAP() \
	void *heap = rrr_mmap_resolve(mmap, shm_slave, 0)

static void __rrr_mmap_free (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	int blocks = 0;
	int iterations = 0;

	DEFINE_HEAP();

	if (mmap->to_free_list_count == 0) {
		return;
	}

	size_t to_free_list_sorted_count = 0;
	uintptr_t last_value = 0;
	rrr_mmap_handle to_free_list_sorted[RRR_MMAP_TO_FREE_LIST_MAX];
	for (size_t i = 0; i < mmap->to_free_list_count; i++) {
		uintptr_t min_value = 0;
		for (size_t i = 0; i < mmap->to_free_list_count; i++) {
			if (mmap->to_free_list[i] > last_value && (min_value == 0 || mmap->to_free_list[i] < min_value)) {
				min_value = mmap->to_free_list[i];
			}
		}
		last_value = min_value;
		to_free_list_sorted[i] = min_value;
		to_free_list_sorted_count++;
	}

	if (to_free_list_sorted_count != mmap->to_free_list_count) {
		RRR_BUG("BUG: Pointer sorting error in __rrr_mmap_free, possibly duplicate pointers in free list\n");
	}

	size_t to_free_list_sorted_pos = 0;
	rrr_mmap_handle block_pos = 0;

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);
		if (block_pos > mmap->heap_size) {
			break;
		}

		blocks++;

		for (uint64_t j = 0; j < 64; j++) {
			uint64_t used_mask = (uint64_t) 1 << j;

			iterations++;

			if (index->block_sizes[j] == 0 && (index->block_used_map & used_mask) == used_mask) {
				// Unusable merged chunk
				continue;
			}

			if (to_free_list_sorted[to_free_list_sorted_pos] == block_pos) {
				if ((index->block_used_map & used_mask) == 0) {
					RRR_BUG("BUG: Double free of pos %" PRIu64 " ptr %p in __rrr_mmap_free\n", block_pos, heap + block_pos);
				}

				index->block_used_map &= ~(used_mask);

				if (++to_free_list_sorted_pos == to_free_list_sorted_count) {
					goto out;
				}
			}

			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in rrr_mmap_free\n");
			}
		}
	}

	out:

	if (to_free_list_sorted_pos != to_free_list_sorted_count) {
		RRR_BUG("BUG: Invalid free of in rrr_mmap_free, one or more positions not found %lu<>%lu (%lu not found)\n",
				to_free_list_sorted_pos, to_free_list_sorted_count, to_free_list_sorted[to_free_list_sorted_pos]);
	}

	mmap->prev_allocation_failure_req_size = 0;
	mmap->to_free_list_count = 0;
}

void rrr_mmap_free (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave,
		rrr_mmap_handle handle
) {
	pthread_mutex_lock(&mmap->lock);

	mmap->to_free_list[mmap->to_free_list_count++] = handle;

// TODO : Re-anble 
//	if (mmap->to_free_list_count == RRR_MMAP_TO_FREE_LIST_MAX) {
		__rrr_mmap_free(mmap, shm_slave);
//	}

	pthread_mutex_unlock(&mmap->lock);

	mmap->prev_allocation_failure_req_size = 0;
}

static void __rrr_mmap_dump_indexes (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	rrr_mmap_handle block_pos = 0;
	uint64_t total_free_bytes = 0;

	DEFINE_HEAP();

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);

		uint64_t free_bytes_in_block = 0;

		for (uint64_t j = 0; j < 64; j++) {
			uint64_t used_mask = (uint64_t) 1 << j;

			if (index->block_used_map & used_mask) {
				if (index->block_sizes[j] == 0) {
					// Unusable chunk due to merging
					printf("/");
				}
				else {
					printf("X");
				}
			}
			else {
				printf ("-");
				free_bytes_in_block += index->block_sizes[j];
			}

			if (index->block_sizes[j] == 0 && (index->block_used_map & used_mask) == 0) {
				// Last block
				block_pos = mmap->heap_size;
			}

			block_pos += index->block_sizes[j];
			total_free_bytes += free_bytes_in_block;
		}

		printf (" - %" PRIu64 " free\n", free_bytes_in_block);
	}
	printf ("Total free: %" PRIu64 "\n", total_free_bytes);
}

void rrr_mmap_dump_indexes (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	pthread_mutex_lock(&mmap->lock);
	__rrr_mmap_dump_indexes(mmap, shm_slave);
	pthread_mutex_unlock(&mmap->lock);
}

void __dump_bin (uint64_t n) {
	for (int i = 0; i < 64; i++) {
		printf ("%i", ((n & 1) == 1) ? 1 : 0);
		n >>= 1;
	}
	printf ("\n");
}

static void *__rrr_mmap_allocate_with_handles (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave,
		uint64_t req_size
) {
	if (req_size == 0) {
		RRR_BUG("request size was 0 in rrr_mmap_allocate\n");
	}
#ifdef RRR_MMAP_SENTINEL_DEBUG
	req_size += sizeof(rrr_mmap_sentinel_template);
#endif

	uint64_t req_size_padded = req_size - (req_size % RRR_MMAP_HEAP_CHUNK_MIN_SIZE) +
			RRR_MMAP_HEAP_CHUNK_MIN_SIZE;

	void *result = NULL;

	pthread_mutex_lock(&mmap->lock);

	DEFINE_HEAP();

	if (mmap->prev_allocation_failure_req_size != 0 && mmap->prev_allocation_failure_req_size <= req_size) {
		goto out_unlock;
	}

	int retry_count = 0;
	rrr_mmap_handle block_pos = mmap->prev_allocation_index_pos;

	if (block_pos > 0) {
		retry_count = 1;
	}

	retry:

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (heap + block_pos);

		mmap->prev_allocation_index_pos = block_pos;

		block_pos += sizeof(struct rrr_mmap_heap_block_index);

		if (block_pos > mmap->heap_size) {
			// Out of memory, not room for another index.
			result = NULL;
			goto out_unlock;
		}

		uint64_t merge_j = 0;
		uint64_t merge_block_pos = 0;
		uint64_t consecutive_unused_count = 0;
		uint64_t consecutive_unused_size = 0;

		for (uint64_t j = 0; j < 64; j++) {
			uint64_t used_mask = (uint64_t) 1 << j;

			if (index->block_sizes[j] == 0) {
				if ((index->block_used_map & used_mask) == used_mask) {
					// Unusable merged chunk
					continue;
				}

				// Allocate new block
				if ((block_pos + req_size_padded) > mmap->heap_size) {
					// Out of memory, allocation would overrun end
					result = NULL;
					goto out_unlock;
				}
				index->block_sizes[j] = req_size_padded;
				index->block_used_map |= used_mask;
				result = heap + block_pos;
#ifdef RRR_MMAP_SENTINEL_DEBUG
				*((uint64_t*)(heap + block_pos + req_size_padded - sizeof(rrr_mmap_sentinel_template))) = rrr_mmap_sentinel_template;
#endif
				goto out_unlock;
			}
			else {
#ifdef RRR_MMAP_SENTINEL_DEBUG
				if (*((uint64_t*)(heap + block_pos + index->block_sizes[j] - sizeof(rrr_mmap_sentinel_template))) != rrr_mmap_sentinel_template) {
					RRR_BUG("Sentinel overwritten at end of block at position %" PRIu64 "\n", block_pos);
				}
#endif

				if ((index->block_used_map & used_mask) != used_mask) {
					if (consecutive_unused_count == 0) {
						merge_block_pos = block_pos;
						merge_j = j;
					}
					consecutive_unused_count++;
					consecutive_unused_size += index->block_sizes[j];

					if (index->block_sizes[j] >= req_size_padded) {
						// Re-use previously allocated and freed block
						index->block_used_map |= used_mask;
						result = heap + block_pos;
						goto out_unlock;
					}
					else if (consecutive_unused_size >= req_size_padded) {
						// Merge blocks if multiple after each other are free
						for (uint64_t k = merge_j; k <= j; k++) {
							index->block_used_map |= (uint64_t) 1 << k;
							index->block_sizes[k] = 0;
						}
						index->block_sizes[merge_j] = consecutive_unused_size;
						result = heap + merge_block_pos;

						goto out_unlock;
					}
				}
				else {
					consecutive_unused_count = 0;
					consecutive_unused_size = 0;
				}
			}

			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in rrr_mmap_alloc\n");
			}
		}
	}

	if (retry_count--) {
		block_pos = 0;
		goto retry;
	}

	out_unlock:

	if (result == NULL) {
		mmap->prev_allocation_failure_req_size = req_size;
	}
	else {
		mmap->allocation_count++;

		*shm_handle = mmap->shm_handle;
		*mmap_handle = (uintptr_t) result - (uintptr_t) heap;
	}

	pthread_mutex_unlock(&mmap->lock);

	return result;
}

void *rrr_mmap_allocate (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave,
		uint64_t req_size
) {
	rrr_shm_handle shm_handle_dummy;
	rrr_mmap_handle mmap_handle_dummy;

	return __rrr_mmap_allocate_with_handles(&shm_handle_dummy, &mmap_handle_dummy, mmap, shm_slave, req_size);
}

static int __rrr_mmap_is_empty (
		uint64_t *allocation_count,
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	int ret = 1;

	pthread_mutex_lock(&mmap->lock);

	DEFINE_HEAP();

	*allocation_count = mmap->allocation_count;

	rrr_mmap_handle block_pos = 0;
	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);

		if (block_pos > mmap->heap_size) {
			break;
		}

		if (index->block_used_map != 0) {
			for (uint64_t j = 0; j < 64; j++) {
				uint64_t used_mask = (uint64_t) 1 << j;
				if ((index->block_used_map & used_mask) && index->block_sizes[j] != 0) {
					ret = 0;
					goto out_unlock;
				}
			}
		}

		for (uint64_t j = 0; j < 64; j++) {
			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in __rrr_mmap_is_empty block size %lu\n", index->block_sizes[j]);
			}
		}
	}

	out_unlock:

	pthread_mutex_unlock(&mmap->lock);

	return ret;
}

static int __rrr_mmap_init (
		struct rrr_mmap *result,
		struct rrr_shm_collection_master *shm_master,
		uint64_t heap_size
) {
	int ret = 0;

	memset(result, '\0', sizeof(*result));

	heap_size += sizeof(struct rrr_mmap_heap_block_index);
#ifdef RRR_MMAP_SENTINEL_DEBUG
	heap_size += sizeof(rrr_mmap_sentinel_template);
#endif

	uint64_t heap_size_padded = heap_size + (4096 - (heap_size % 4096));

	if ((ret = rrr_shm_collection_master_allocate (&result->shm_handle, shm_master, heap_size_padded)) != 0) {
		RRR_MSG_0("Could not allocate memory in __rrr_mmap_init\n");
		goto out;
	}

	if ((ret = rrr_posix_mutex_init(&result->lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
		RRR_MSG_0("Could not initialize mutex in __rrr_mmap_init (%i)\n", ret);
		ret = 1;
		goto out_free_heap;
	}

	result->shm_master = shm_master;
	result->heap_size = heap_size_padded;

	goto out;

	out_free_heap:
		rrr_shm_collection_master_free(shm_master, result->shm_handle);
	out:
		return ret;
}

int rrr_mmap_new (
		struct rrr_mmap **target,
		struct rrr_shm_collection_master *shm_master,
		struct rrr_shm_collection_slave *shm_slave,
		uint64_t heap_size
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mmap *result = NULL;

	rrr_shm_handle handle_tmp;
	if ((ret = rrr_shm_collection_master_allocate (&handle_tmp, shm_master, sizeof(*result))) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_mmap_new\n");
		goto out;
	}

	if ((result = rrr_shm_resolve (shm_slave, handle_tmp)) == NULL) {
		RRR_MSG_0("SHM resolve failed in rrr_mmap_new\n");
		ret = 1;
		goto out_free_main;
	}

	if ((ret = __rrr_mmap_init (result, shm_master, heap_size)) != 0) {
		goto out_free_main;
	}

	*target = result;
	result = NULL;

	goto out;

	out_free_main:
		rrr_shm_collection_master_free(shm_master, handle_tmp);
	out:
		return ret;
}

void __rrr_mmap_cleanup (
		struct rrr_mmap *mmap
) {
	pthread_mutex_destroy(&mmap->lock);
	rrr_shm_collection_master_free(mmap->shm_master, mmap->shm_handle);
	memset(mmap, '\0', sizeof(*mmap));
}

void rrr_mmap_destroy (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	pthread_mutex_destroy(&mmap->lock);

	rrr_shm_collection_master_free(mmap->shm_master, mmap->shm_handle);

	rrr_shm_handle handle;
	if (rrr_shm_resolve_reverse (&handle, shm_slave, mmap) != 0) {
		RRR_BUG("BUG: Reverse resolve of SHM handle failed in rrr_mmap_destroy\n");
	}
	rrr_shm_collection_master_free(mmap->shm_master, handle);
}

#define RRR_MMAP_ITERATE_BEGIN() \
	do { for (size_t i = 0; i < RRR_MMAP_COLLECTION_MAX; i++) { \
		struct rrr_mmap *mmap = &collection->mmaps[i] \

#define RRR_MMAP_ITERATE_END() \
	}} while(0)

static void __rrr_mmap_collection_minmax_update_if_needed (
		struct rrr_mmap_collection *collection,
		struct rrr_mmap_collection_minmax *minmax,
		struct rrr_shm_collection_slave *shm_slave,
		pthread_rwlock_t *index_lock_held
) {
	if (minmax->version == collection->version) {
		goto out;
	}

	// Change to write lock
	pthread_rwlock_unlock(index_lock_held);
	pthread_rwlock_wrlock(index_lock_held);

	// Check again after obtaining write lock
	if (minmax->version == collection->version) {
		goto out;
	}

	minmax->version = collection->version;

	size_t wpos = 0;
	RRR_MMAP_ITERATE_BEGIN();
		if (mmap->heap_size != 0) {
			DEFINE_HEAP();
			minmax->minmax[wpos].heap_min = (uintptr_t) heap;
			minmax->minmax[wpos].heap_max = (uintptr_t) heap + mmap->heap_size;
			minmax->minmax[wpos].mmap_idx = i;
			printf("Make minmax %lu %p minmax pos %lu - %p<=x<%p shm %lu\n",
				i, mmap, wpos, heap, heap + mmap->heap_size, mmap->shm_handle);
			wpos++;
		}
		if (wpos == collection->mmap_count) {
			break;
		}
	RRR_MMAP_ITERATE_END();

	// Keep write lockj

	out:
		return;
}

static int __rrr_mmap_collection_minmax_search (
		size_t *pos,
		struct rrr_mmap_collection *collection,
		struct rrr_mmap_collection_minmax *minmax,
		struct rrr_shm_collection_slave *shm_slave,
		pthread_rwlock_t *index_lock_held,
		uintptr_t ptr
) {
	__rrr_mmap_collection_minmax_update_if_needed(collection, minmax, shm_slave, index_lock_held);

	for (size_t j = 0; j < collection->mmap_count; j++) {
		if (ptr >= minmax->minmax[j].heap_min && ptr < minmax->minmax[j].heap_max) {
			*pos = minmax->minmax[j].mmap_idx;
			return 1;
		}
	}
	return 0;
}

void rrr_mmap_collections_maintenance (
		struct rrr_mmap_stats *stats,
		struct rrr_mmap_collection *collections,
		size_t collection_count,
		struct rrr_shm_collection_slave *shm_slave,
		pthread_rwlock_t *index_lock
) {
	memset(stats, '\0', sizeof(*stats));

	pthread_rwlock_rdlock(index_lock);
	for (size_t i = 0; i < collection_count; i++) {
		struct rrr_mmap_collection *collection = &collections[i];
		RRR_MMAP_ITERATE_BEGIN();
			if (mmap->heap_size != 0) {
				pthread_mutex_lock(&mmap->lock);
				__rrr_mmap_free(mmap, shm_slave);
				pthread_mutex_unlock(&mmap->lock);
			}
		RRR_MMAP_ITERATE_END();
	}
	pthread_rwlock_unlock(index_lock);

	pthread_rwlock_wrlock(index_lock);
	for (size_t i = 0; i < collection_count; i++) {
		struct rrr_mmap_collection *collection = &collections[i];

		if (collection->mmap_count == 0) {
			continue;
		}

		RRR_MMAP_ITERATE_BEGIN();
			if (mmap->heap_size == 0) {
				continue;
			}

			stats->mmap_total_heap_size += mmap->heap_size;
			stats->mmap_total_count++;

			uint64_t allocation_count;
			if (__rrr_mmap_is_empty(&allocation_count, mmap, shm_slave)) {
				printf("Cleanup %p strike %i\n", mmap, mmap->maintenance_cleanup_strikes);
				rrr_mmap_dump_indexes(mmap, shm_slave);
				if (++mmap->maintenance_cleanup_strikes >= RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES) {
					 __rrr_mmap_cleanup (mmap);
					collection->mmap_count--;
					collection->version++;
					continue;
				}
				stats->mmap_total_empty_count++;
			}
			else {
				if (allocation_count > RRR_MMAP_COLLECTION_ALLOCATION_MAX) {
					printf("Bad %p\n", mmap);
					rrr_mmap_dump_indexes(mmap, shm_slave);
					stats->mmap_total_bad_count++;
					mmap->flags |= RRR_MMAP_COLLECTION_FLAG_BAD;
					mmap->maintenance_cleanup_strikes = RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES;
				}
				else {
					mmap->maintenance_cleanup_strikes = 0;
				}
			}
		RRR_MMAP_ITERATE_END();
	}
	pthread_rwlock_unlock(index_lock);
}

void rrr_mmap_collections_clear (
		struct rrr_mmap_collection *collections,
		struct rrr_shm_collection_slave *shm_slave,
		size_t collection_count,
		pthread_rwlock_t *index_lock
) {
	int count = 0;

	struct rrr_mmap_stats stats_dummy;
	rrr_mmap_collections_maintenance(&stats_dummy, collections, collection_count, shm_slave, index_lock);

	pthread_rwlock_wrlock(index_lock);
	for (size_t i = 0; i < collection_count; i++) {
		struct rrr_mmap_collection *collection = &collections[i];
		RRR_MMAP_ITERATE_BEGIN();
			if (mmap->heap_size != 0) {
				__rrr_mmap_cleanup (mmap);
				collection->mmap_count--;
				count++;
			}
		RRR_MMAP_ITERATE_END();
	}
	pthread_rwlock_unlock(index_lock);

//	printf("MMAPs left upon cleanup: %i\n", count);
}

void *rrr_mmap_collection_allocate_with_handles (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap_collection *collection,
		struct rrr_shm_collection_master *shm_master,
		struct rrr_shm_collection_slave *shm_slave,
		uint64_t bytes,
		uint64_t min_mmap_size,
		pthread_rwlock_t *index_lock
) {
	void *result = NULL;

	pthread_rwlock_rdlock(index_lock);
	if (collection->mmap_count > 0) {
		RRR_MMAP_ITERATE_BEGIN();
			if (  mmap->heap_size != 0 &&
			     (mmap->flags & RRR_MMAP_COLLECTION_FLAG_BAD) == 0 &&
			     (result = __rrr_mmap_allocate_with_handles(shm_handle, mmap_handle, mmap, shm_slave, bytes)) != NULL
			) {
				printf("Allocate %lu %p = %p shm %lu\n", i, mmap, result, mmap->shm_handle);
				break;
			}
		RRR_MMAP_ITERATE_END();
	}
	pthread_rwlock_unlock(index_lock);

	if (result) {
		goto out;
	}

	pthread_rwlock_wrlock(index_lock);
	RRR_MMAP_ITERATE_BEGIN();
		printf("Init try %p\n", mmap);
		if (mmap->heap_size == 0) {
			if (__rrr_mmap_init (mmap, shm_master, bytes > min_mmap_size ? bytes : min_mmap_size) != 0) {
				break;
			}
			printf("- OK shm %lu\n", mmap->shm_handle);
			collection->mmap_count++;
			collection->version++;
			result = __rrr_mmap_allocate_with_handles(shm_handle, mmap_handle, mmap, shm_slave, bytes);
			printf("Allocate %lu %p = %p shm %lu\n", i, mmap, result, mmap->shm_handle);
			break;
		}
	RRR_MMAP_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	out:
	return result;
}

void *rrr_mmap_collection_allocate (
		struct rrr_mmap_collection *collection,
		struct rrr_shm_collection_master *shm_master,
		struct rrr_shm_collection_slave *shm_slave,
		uint64_t bytes,
		uint64_t min_mmap_size,
		pthread_rwlock_t *index_lock
) {
	rrr_shm_handle shm_handle_dummy;
	rrr_mmap_handle mmap_handle_dummy;

	return rrr_mmap_collection_allocate_with_handles (
			&shm_handle_dummy,
			&mmap_handle_dummy,
			collection,
			shm_master,
			shm_slave,
			bytes,
			min_mmap_size,
			index_lock
	);
}

int rrr_mmap_collections_free (
		struct rrr_mmap_collection *collections,
		struct rrr_mmap_collection_minmax *minmaxes,
		size_t collection_count,
		struct rrr_shm_collection_slave *shm_slave,
		pthread_rwlock_t *index_lock,
		void *ptr
) {
	int ret = 1; // Error

	pthread_rwlock_rdlock(index_lock);

	for (size_t j = 0; j < collection_count; j++) {
		if (collections[j].mmap_count == 0) {
			continue;
		}

		size_t pos = 0;
		if (__rrr_mmap_collection_minmax_search (
				&pos,
				&collections[j],
				&minmaxes[j],
				shm_slave,
				index_lock,
				(uintptr_t) ptr
		) == 1) {
			struct rrr_mmap *mmap = &collections[j].mmaps[pos];

			DEFINE_HEAP();

			printf("Free %lu %p = %p shm %lu\n", pos, mmap, ptr, mmap->shm_handle);

			rrr_mmap_free(mmap, shm_slave, (uintptr_t) ptr - (uintptr_t) heap);
	
			ret = 0;

			break;
		}
	}

	pthread_rwlock_unlock(index_lock);

	return ret;

}
