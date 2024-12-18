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

// Enable printf debugging (very verbose)
// #define RRR_MMAP_ALLOCATION_DEBUG 1

// Dump mmaps upon allocation failure (should be enabled)
#define RRR_MMAP_ALLOCATION_FAILURE_DEBUG

#define RRR_MMAP_SENTINEL_DEBUG

#ifdef RRR_MMAP_SENTINEL_DEBUG
static const rrr_biglength rrr_mmap_sentinel_template = 0xa0a0a0a00a0a0a0a;
#endif

struct rrr_mmap {
	struct rrr_mmap_collection *collection;

	rrr_shm_handle shm_heap;
	void *mmap_heap;

	int maintenance_cleanup_strikes;
	rrr_biglength allocation_count;
	uint8_t flags;
	rrr_mmap_handle heap_size;
	rrr_mmap_handle prev_allocation_failure_req_size;
	rrr_mmap_handle  prev_allocation_index_pos;
};

struct rrr_mmap_collection {
	size_t mmap_count;
	unsigned int version;

	pthread_mutex_t index_lock;

	rrr_biglength allocation_limit;

	struct rrr_shm_collection_master *shm_master;
	struct rrr_shm_collection_slave *shm_slave;
	struct rrr_mmap mmaps[RRR_MMAP_COLLECTION_MAX];
};

struct rrr_mmap_heap_block_index {
	rrr_biglength block_used_map;
	rrr_biglength block_sizes[64];
};

#define LOCK(collection) \
	do {int ret_tmp = rrr_posix_mutex_robust_lock(&collection->index_lock); if (ret_tmp != 0) RRR_BUG("Unhandled lock error %s in %s, cannot continue.\n", rrr_strerror(ret_tmp), __func__);
#define UNLOCK(collection) \
	{ int ret_tmp = pthread_mutex_unlock(&collection->index_lock); if (ret_tmp != 0) RRR_BUG("Unhandled unlock error %s in %s, cannot continue\n", rrr_strerror(ret_tmp), __func__); }} while(0)
#define INIT(collection, is_pshared) \
	rrr_posix_mutex_init(&collection->index_lock, (is_pshared ? RRR_POSIX_MUTEX_IS_PSHARED|RRR_POSIX_MUTEX_IS_ROBUST : 0))
#define DESTROY(collection) \
	rrr_posix_mutex_robust_destroy(&collection->index_lock)

void *__rrr_mmap_resolve (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave,
		size_t pos
) {
	return (shm_slave != NULL
		? rrr_shm_resolve(shm_slave, mmap->shm_heap) + pos
		: mmap->mmap_heap + pos
	);
}

#define DEFINE_HEAP() \
	void *heap = __rrr_mmap_resolve(mmap, shm_slave, 0)

static void __rrr_mmap_free (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave,
		rrr_mmap_handle handle
) {
	DEFINE_HEAP();

	rrr_mmap_handle block_pos = 0;

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);
		if (block_pos > mmap->heap_size) {
			break;
		}

		for (rrr_biglength j = 0; j < 64; j++) {
			rrr_biglength used_mask = (rrr_biglength) 1 << j;

			if (index->block_sizes[j] == 0 && (index->block_used_map & used_mask) == used_mask) {
				// Unusable merged chunk
				continue;
			}

			if (handle == block_pos) {
				if ((index->block_used_map & used_mask) == 0) {
					RRR_BUG("BUG: Double free of pos %" PRIrrrbl " ptr %p in %s\n", block_pos, heap + block_pos, __func__);
				}

				index->block_used_map &= ~(used_mask);
				goto out;
			}

			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in %s\n", __func__);
			}
		}
	}

	RRR_BUG("BUG: Invalid free in %s, %llu not found\n", __func__, (long long unsigned int) handle);

	out:

	mmap->prev_allocation_failure_req_size = 0;
}

// Use to debug, but is not an exposed function
void rrr_mmap_dump_indexes (
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	rrr_mmap_handle block_pos = 0;
	rrr_biglength total_free_bytes = 0;

	DEFINE_HEAP();

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);

		rrr_biglength free_bytes_in_block = 0;

		for (rrr_biglength j = 0; j < 64; j++) {
			rrr_biglength used_mask = (rrr_biglength) 1 << j;

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

		printf (" - %" PRIrrrbl " free\n", free_bytes_in_block);
	}
	printf ("Total free: %" PRIrrrbl "\n", total_free_bytes);
}

void __dump_bin (rrr_biglength n) {
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
		rrr_biglength req_size
) {
	if (req_size == 0) {
		RRR_BUG("request size was 0 in %s\n", __func__);
	}
#ifdef RRR_MMAP_SENTINEL_DEBUG
	req_size += sizeof(rrr_mmap_sentinel_template);
#endif

	rrr_biglength req_size_padded = req_size - (req_size % RRR_MMAP_HEAP_CHUNK_MIN_SIZE) +
			RRR_MMAP_HEAP_CHUNK_MIN_SIZE;

	void *result = NULL;

	struct rrr_shm_collection_slave *shm_slave = mmap->collection->shm_slave;
	DEFINE_HEAP();

	if (mmap->prev_allocation_failure_req_size != 0 && mmap->prev_allocation_failure_req_size <= req_size) {
		goto out_unlock;
	}

	if (req_size > mmap->heap_size - sizeof(struct rrr_mmap_heap_block_index)) {
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

		rrr_biglength merge_j = 0;
		rrr_biglength merge_block_pos = 0;
		rrr_biglength consecutive_unused_count = 0;
		rrr_biglength consecutive_unused_size = 0;

		for (rrr_biglength j = 0; j < 64; j++) {
			rrr_biglength used_mask = (rrr_biglength) 1 << j;

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
				*((rrr_biglength*)(heap + block_pos + req_size_padded - sizeof(rrr_mmap_sentinel_template))) = rrr_mmap_sentinel_template;
#endif
				goto out_unlock;
			}
			else {
#ifdef RRR_MMAP_SENTINEL_DEBUG
				if (*((rrr_biglength*)(heap + block_pos + index->block_sizes[j] - sizeof(rrr_mmap_sentinel_template))) != rrr_mmap_sentinel_template) {
					RRR_BUG("BUG: Sentinel overwritten at end of block at position %" PRIrrrbl "in %s\n", block_pos, __func__);
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
						for (rrr_biglength k = merge_j; k <= j; k++) {
							index->block_used_map |= (rrr_biglength) 1 << k;
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
				RRR_BUG("BUG: Heap index corruption in %s\n", __func__);
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

		*shm_handle = mmap->shm_heap;
		*mmap_handle = (uintptr_t) result - (uintptr_t) heap;
	}

	return result;
}

static int __rrr_mmap_is_empty (
		rrr_biglength *allocation_count,
		struct rrr_mmap *mmap,
		struct rrr_shm_collection_slave *shm_slave
) {
	int ret = 1;

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
			for (rrr_biglength j = 0; j < 64; j++) {
				rrr_biglength used_mask = (rrr_biglength) 1 << j;
				if ((index->block_used_map & used_mask) && index->block_sizes[j] != 0) {
					ret = 0;
					goto out_unlock;
				}
			}
		}

		for (rrr_biglength j = 0; j < 64; j++) {
			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in %s block size %" PRIrrrbl "\n", __func__, index->block_sizes[j]);
			}
		}
	}

	out_unlock:

	return ret;
}

static int __rrr_mmap_init (
		struct rrr_mmap *result,
		struct rrr_mmap_collection *collection,
		rrr_biglength heap_size
) {
	int ret = 0;

	memset(result, '\0', sizeof(*result));

	heap_size += sizeof(struct rrr_mmap_heap_block_index);
#ifdef RRR_MMAP_SENTINEL_DEBUG
	heap_size += sizeof(rrr_mmap_sentinel_template);
#endif

	rrr_biglength heap_size_padded = heap_size + (4096 - (heap_size % 4096));

#if UINT64_MAX > SIZE_MAX
	if (heap_size_padded > SIZE_MAX) {
		RRR_MSG_0("Heap size overflow while initializing mmap\n");
		ret = 1;
		goto out;
	}
#endif

	if (collection->shm_master) {
		if ((ret = rrr_shm_collection_master_allocate (
				&result->shm_heap,
				collection->shm_master,
				rrr_size_from_biglength_bug_const(heap_size_padded)
		)) != 0) {
			RRR_MSG_0("Could not allocate SHM memory in %s\n", __func__);
			goto out;
		}
#ifdef RRR_MMAP_ALLOCATION_DEBUG
		printf("Init %p shm %lu\n", result, result->shm_heap);
#endif
	}
	else {
		if ((result->mmap_heap = rrr_posix_mmap (
				rrr_size_from_biglength_bug_const(heap_size_padded),
				0 /* not pshared */
		)) == NULL) {
			RRR_MSG_0("Could not allocate MMAP memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
#ifdef RRR_MMAP_ALLOCATION_DEBUG
		printf("Init %p mmap %p\n", result, result->mmap_heap);
#endif
	}

	result->heap_size = heap_size_padded;
	result->collection = collection;

	goto out;

//	out_free_heap:
//	if (result->shm_heap) {
//			rrr_shm_collection_master_free(collection->shm_master, result->shm_heap);
//		}
//		else {
//			munmap(result->mmap_heap, heap_size_padded);
//		}
	out:
		return ret;
}

static void __rrr_mmap_cleanup (
		struct rrr_mmap *mmap
) {
	if (mmap->shm_heap) {
		rrr_shm_collection_master_free(mmap->collection->shm_master, mmap->shm_heap);
	}
	else {
		munmap(mmap->mmap_heap, (size_t) mmap->heap_size);
	}
	memset(mmap, '\0', sizeof(*mmap));
}

static void __rrr_mmap_collection_mmap_cleanup (
		struct rrr_mmap_collection *collection,
		struct rrr_mmap *mmap
) {
	__rrr_mmap_cleanup (mmap);
	collection->mmap_count--;
	collection->version++;
}

#define RRR_MMAP_ITERATE_BEGIN() \
	do { for (size_t i = 0; i < RRR_MMAP_COLLECTION_MAX; i++) { \
		struct rrr_mmap *mmap = &collection->mmaps[i] \

#define RRR_MMAP_ITERATE_END() \
	}} while(0)

void *rrr_mmap_collection_resolve (
		struct rrr_mmap_collection *collection,
		rrr_shm_handle shm_handle,
		rrr_mmap_handle mmap_handle
) {
	void *ret;

	if (collection->shm_master == NULL) {
		RRR_BUG("BUG: %s called on non-pshared mmap collection\n", __func__);
	}

	LOCK(collection);
	ret = rrr_shm_resolve (
			collection->shm_slave,
			shm_handle
	);
	UNLOCK(collection);

	if (ret == NULL) {
		RRR_BUG("BUG: Unknown handle %llu in %s\n",
				(long long unsigned int) shm_handle, __func__);
	}

	return ret + mmap_handle;
}

static void __rrr_mmap_collection_minmax_update_if_needed (
		struct rrr_mmap_collection_private_data *private_data
) {
	struct rrr_mmap_collection *collection = private_data->collection;
	if (private_data->version == collection->version) {
		goto out;
	}

	// Check version again
	if (private_data->version == collection->version) {
		goto out;
	}

	private_data->version = collection->version;

	size_t wpos = 0;
	RRR_MMAP_ITERATE_BEGIN();
		if (mmap->heap_size != 0) {
			struct rrr_shm_collection_slave *shm_slave = collection->shm_slave;
			DEFINE_HEAP();
			private_data->minmax[wpos].heap_min = (uintptr_t) heap;
			private_data->minmax[wpos].heap_max = (uintptr_t) (heap + mmap->heap_size);
			private_data->minmax[wpos].mmap_idx = i;
#ifdef RRR_MMAP_ALLOCATION_DEBUG
			printf("Make minmax %lu %p minmax pos %lu - %p<=x<%p shm %lu heap %p\n",
				i, mmap, wpos, heap, heap + mmap->heap_size, mmap->shm_heap, heap);
#endif
			wpos++;
		}
		if (wpos == collection->mmap_count) {
			break;
		}
	RRR_MMAP_ITERATE_END();

	// Keep wrlock

	out:
		return;
}

static int __rrr_mmap_collection_minmax_search (
		size_t *pos,
		struct rrr_mmap_collection_private_data *private_data,
		uintptr_t ptr
) {
	__rrr_mmap_collection_minmax_update_if_needed(private_data);

	for (size_t j = 0; j < private_data->collection->mmap_count; j++) {
		if (ptr >= private_data->minmax[j].heap_min && ptr < private_data->minmax[j].heap_max) {
			*pos = private_data->minmax[j].mmap_idx;
			return 1;
		}
	}
	return 0;
}

void rrr_mmap_collection_fork_unregister (
		struct rrr_mmap_collection *collection
) {
	LOCK(collection);
	rrr_shm_collection_master_fork_unregister(collection->shm_master);
	UNLOCK(collection);
}

void rrr_mmap_collections_maintenance (
		struct rrr_mmap_stats *stats,
		struct rrr_mmap_collection *collections,
		size_t collection_count
) {
	memset(stats, '\0', sizeof(*stats));

	for (size_t i = 0; i < collection_count; i++) {
		struct rrr_mmap_collection *collection = &collections[i];

		LOCK(collection);

		if (collection->mmap_count == 0) {
			goto next;
		}

		rrr_biglength allocation_count_total = 0;
		unsigned int allocation_count_total_entries = 0;

		RRR_MMAP_ITERATE_BEGIN();
			if (mmap->heap_size == 0) {
				continue;
			}

			stats->mmap_total_heap_size += mmap->heap_size;
			stats->mmap_total_count++;

			rrr_biglength allocation_count;
			if (__rrr_mmap_is_empty(&allocation_count, mmap, collection->shm_slave)) {
#ifdef RRR_MMAP_ALLOCATION_DEBUG
				printf("Cleanup %p strike %i shm %lu\n", mmap, mmap->maintenance_cleanup_strikes, mmap->shm_heap);
				rrr_mmap_dump_indexes(mmap, collection->shm_slave);
#endif
				if (++mmap->maintenance_cleanup_strikes >= RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES) {
					__rrr_mmap_collection_mmap_cleanup(collection, mmap);
					continue;
				}
				stats->mmap_total_empty_count++;
			}
			else {
				if (allocation_count > collection->allocation_limit) {
#ifdef RRR_MMAP_ALLOCATION_DEBUG
					printf("Bad %p\n", mmap);
					rrr_mmap_dump_indexes(mmap, collection->shm_slave);
#endif
					stats->mmap_total_bad_count++;
					mmap->flags |= RRR_MMAP_COLLECTION_FLAG_BAD;
					mmap->maintenance_cleanup_strikes = RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES;
				}
				else {
					mmap->maintenance_cleanup_strikes = 0;
				}
			}

			allocation_count_total += allocation_count;
			allocation_count_total_entries++;
		RRR_MMAP_ITERATE_END();

		if (allocation_count_total_entries > 0) {
			// New limit will be used next round
			collection->allocation_limit = allocation_count_total / allocation_count_total_entries;

			if (collection->allocation_limit < RRR_MMAP_COLLECTION_ALLOCATION_LIMIT_MIN) {
				collection->allocation_limit = RRR_MMAP_COLLECTION_ALLOCATION_LIMIT_MIN;
			}
			if (collection->allocation_limit > RRR_MMAP_COLLECTION_ALLOCATION_LIMIT_MAX) {
				collection->allocation_limit = RRR_MMAP_COLLECTION_ALLOCATION_LIMIT_MAX;
			}
		}

		next:
		UNLOCK(collection);
	}
}

void __rrr_mmap_collection_cleanup (
		struct rrr_mmap_collection *collection
) {
#ifdef RRR_MMAP_ALLOCATION_DEBUG
	int count = 0;
#endif

	LOCK(collection);
	RRR_MMAP_ITERATE_BEGIN();
		if (mmap->heap_size != 0) {
			__rrr_mmap_collection_mmap_cleanup(collection, mmap);
#ifdef RRR_MMAP_ALLOCATION_DEBUG
			count++;
#endif
		}
	RRR_MMAP_ITERATE_END();

	if (collection->shm_slave) {
		rrr_shm_collection_slave_destroy(collection->shm_slave);
	}

	if (collection->shm_master) {
		rrr_shm_collection_master_destroy(collection->shm_master);
	}

	UNLOCK(collection);

	DESTROY(collection);

#ifdef RRR_MMAP_ALLOCATION_DEBUG
	printf("MMAPs left upon cleanup: %i\n", count);
#endif
}

void rrr_mmap_collections_destroy (
		struct rrr_mmap_collection *collections,
		size_t collection_count
) {
	struct rrr_mmap_stats stats_dummy;
	rrr_mmap_collections_maintenance(&stats_dummy, collections, collection_count);

	for (size_t i = 0; i < collection_count; i++) {
		struct rrr_mmap_collection *collection = &collections[i];
		__rrr_mmap_collection_cleanup(collection);
	}

	munmap (collections, sizeof(*collections) * collection_count);
}

static int __rrr_mmap_collection_init (
		struct rrr_mmap_collection *target,
		int is_pshared,
		const char *creator
) {
	int ret = 0;

	memset(target, '\0', sizeof(*target));
	if (INIT(target, is_pshared) != 0) {
		RRR_MSG_0("Could not initialize lock in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (is_pshared) {
		// Note : Allocated using shared memory. After fork(), all processes
		//        still use the same shm master.
		if ((ret = rrr_shm_collection_master_new(&target->shm_master, creator)) != 0) {
			RRR_MSG_0("Could create SHM master in %s\n", __func__);
			goto out_destroy_lock;
		}

		// Note : The slave is never pshared. Upon fork(), new children
		//        will have their own copy.
		if ((ret = rrr_shm_collection_slave_new(&target->shm_slave, target->shm_master)) != 0) {
			RRR_MSG_0("Could create SHM slave in %s\n", __func__);
			goto out_destroy_shm_master;
		}
	}

	goto out;
	out_destroy_shm_master:
		rrr_shm_collection_master_destroy(target->shm_master);
	out_destroy_lock:
		DESTROY(target);
	out:
	return ret;
}

int rrr_mmap_collections_new (
		struct rrr_mmap_collection **result,
		size_t collection_count,
		int is_pshared,
		const char *creator
) {
	int ret = 0;

	struct rrr_mmap_collection *collections = NULL;

	collections = rrr_posix_mmap (sizeof(*collections) * collection_count, is_pshared);

	if (collections == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	size_t i_cleanup_max = 0;

	for (size_t i = 0; i < collection_count; i++) {
		if ((ret = __rrr_mmap_collection_init(&collections[i], is_pshared, creator)) != 0) {
			goto out_free;
		}
		i_cleanup_max = i;
	}

	*result = collections;

	goto out;
	out_free:
		for (size_t i = 0; i < i_cleanup_max; i++) {
			__rrr_mmap_collection_cleanup(&collections[i]);
		}
		munmap (collections, sizeof(*collections) * collection_count);
	out:
		return ret;
}

void rrr_mmap_collection_private_datas_init (
		struct rrr_mmap_collection_private_data *private_datas,
		struct rrr_mmap_collection *collections,
		size_t collection_count
) {
	for (size_t i = 0; i < collection_count; i++) {
		struct rrr_mmap_collection *collection = &collections[i];
		struct rrr_mmap_collection_private_data *private_data = &private_datas[i];

		memset(private_data, '\0', sizeof(*private_data));
		private_data->version = collection->version - 1;
		private_data->collection = collection;
	}
}

static void *__rrr_mmap_collection_allocate_with_handles_try_old_mmap (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		short do_allow_bad
) {
	void *result = NULL;

	if (collection->mmap_count > 0) {
		RRR_MMAP_ITERATE_BEGIN();
			if (mmap->heap_size == 0) {
				continue;
			}
#ifdef RRR_MMAP_ALLOCATION_DEBUG
			printf("Old try %p heap allow bad %i is bad %i\n", mmap, do_allow_bad, mmap->flags & RRR_MMAP_COLLECTION_FLAG_BAD);
#endif
			if ( (do_allow_bad || (mmap->flags & RRR_MMAP_COLLECTION_FLAG_BAD) == 0) &&
			     (result = __rrr_mmap_allocate_with_handles(shm_handle, mmap_handle, mmap, bytes)) != NULL
			) {
#ifdef RRR_MMAP_ALLOCATION_DEBUG
				struct rrr_shm_collection_slave *shm_slave = collection->shm_slave;
				DEFINE_HEAP();
				printf("Allocate %lu %p = %p shm %lu heap %p size %" PRIrrrbl "\n", i, mmap, result, mmap->shm_heap, heap, bytes);
#endif
				break;
			}
		RRR_MMAP_ITERATE_END();
	}

	return result;
}

static void *__rrr_mmap_collection_allocate_with_handles_try_new_mmap (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
) {
	void *result = NULL;

	RRR_MMAP_ITERATE_BEGIN();
#ifdef RRR_MMAP_ALLOCATION_DEBUG
		printf("Init try %p heap\n", mmap);
#endif
		rrr_biglength allocation_count_dummy;
		// Force empty mmaps to be re-allocated in case we need them to be larger
		if (mmap->heap_size > 0 && __rrr_mmap_is_empty(&allocation_count_dummy, mmap, collection->shm_slave)) {
			__rrr_mmap_collection_mmap_cleanup(collection, mmap);
		}

		if (mmap->heap_size == 0) {
			if (__rrr_mmap_init (mmap, collection, bytes > min_mmap_size ? bytes : min_mmap_size) != 0) {
				break;
			}
#ifdef RRR_MMAP_ALLOCATION_DEBUG
			printf("- OK shm %lu or mmap %p\n", mmap->shm_heap, mmap->mmap_heap);
#endif
			collection->mmap_count++;
			collection->version++;
			result = __rrr_mmap_allocate_with_handles(shm_handle, mmap_handle, mmap, bytes);
#ifdef RRR_MMAP_ALLOCATION_DEBUG
			struct rrr_shm_collection_slave *shm_slave = collection->shm_slave;
			DEFINE_HEAP();
			printf("Allocate %lu %p = %p shm %lu heap %p size %" PRIrrrbl "\n", i, mmap, result, mmap->shm_heap, heap, bytes);
#endif
			break;
		}
	RRR_MMAP_ITERATE_END();

	return result;
}

static void *__rrr_mmap_collection_allocate_with_handles (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
) {
	void *result = NULL;

	LOCK(collection);

	/*
	 * 1. Fill up any existing mmap which is not marked as bad
	 * 2. If none found, try to allocate new mmap
	 * 3. If unable, try to allocate from bad mmaps
	 */

	if ((result = __rrr_mmap_collection_allocate_with_handles_try_old_mmap (
			shm_handle,
			mmap_handle,
			collection,
			bytes,
			0 /* Don't allow bad */
	)) != NULL) {
		goto out;
	}

	if ((result = __rrr_mmap_collection_allocate_with_handles_try_new_mmap (
			shm_handle,
			mmap_handle,
			collection,
			bytes,
			min_mmap_size
	)) != NULL) {
		goto out;
	}

	if ((result = __rrr_mmap_collection_allocate_with_handles_try_old_mmap (
			shm_handle,
			mmap_handle,
			collection,
			bytes,
			1 /* Allow bad */
	)) != NULL) {
		goto out;
	}

#ifdef RRR_MMAP_ALLOCATION_FAILURE_DEBUG
	if (result == NULL) {
		struct rrr_shm_collection_slave *shm_slave = collection->shm_slave;
		RRR_MSG_0("Allocation failure of %" PRIrrrbl " bytes in %s. Dumping mmaps for this group:\n",
				bytes, __func__);
		RRR_MMAP_ITERATE_BEGIN();
			DEFINE_HEAP();
			if (heap == NULL) {
				RRR_MSG_0("== MMAP %llu NO HEAP\n", (long long unsigned int) i);
			}
			else {
				RRR_MSG_0("== MMAP %llu%s\n", (long long unsigned int) i, mmap->flags & RRR_MMAP_COLLECTION_FLAG_BAD ? " BAD" : "");
				rrr_mmap_dump_indexes(mmap, shm_slave);
			}
		RRR_MMAP_ITERATE_END();
	}
#endif

	out:
	UNLOCK(collection);
	return result;
}

void *rrr_mmap_collection_allocate_with_handles (
		rrr_shm_handle *shm_handle,
		rrr_mmap_handle *mmap_handle,
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
) {
	if (collection->shm_master == NULL) {
		RRR_BUG("BUG: %s called on non-pshared mmap collection\n", __func__);
	}

	return __rrr_mmap_collection_allocate_with_handles (
			shm_handle,
			mmap_handle,
			collection,
			bytes,
			min_mmap_size
	);
}

void *rrr_mmap_collection_allocate (
		struct rrr_mmap_collection *collection,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
) {
	rrr_shm_handle shm_handle_dummy;
	rrr_mmap_handle mmap_handle_dummy;

	return __rrr_mmap_collection_allocate_with_handles (
			&shm_handle_dummy,
			&mmap_handle_dummy,
			collection,
			bytes,
			min_mmap_size
	);
}

void *rrr_mmap_collections_allocate (
		struct rrr_mmap_collection *collections,
		size_t index,
		rrr_biglength bytes,
		rrr_biglength min_mmap_size
) {
	rrr_shm_handle shm_handle_dummy;
	rrr_mmap_handle mmap_handle_dummy;

	return __rrr_mmap_collection_allocate_with_handles (
			&shm_handle_dummy,
			&mmap_handle_dummy,
			&collections[index],
			bytes,
			min_mmap_size
	);
}

int rrr_mmap_collections_free (
		struct rrr_mmap_collection_private_data *private_datas,
		size_t collection_count,
		void *ptr
) {
	int ret = 1; // Error

	for (size_t j = 0; j < collection_count; j++) {
		struct rrr_mmap_collection *collection = private_datas[j].collection;

		LOCK(collection);

		if (collection->mmap_count == 0) {
			goto next;
		}

		size_t pos = 0;
		if (__rrr_mmap_collection_minmax_search (
				&pos,
				&private_datas[j],
				(uintptr_t) ptr
		) == 1) {
			struct rrr_mmap *mmap = &collection->mmaps[pos];
			struct rrr_shm_collection_slave *shm_slave = collection->shm_slave;

			DEFINE_HEAP();

#ifdef RRR_MMAP_ALLOCATION_DEBUG
			printf("Free %lu %p = %p shm %lu heap %p\n", pos, mmap, ptr, mmap->shm_heap, heap);
#endif

			__rrr_mmap_free(mmap, shm_slave, (uintptr_t) ptr - (uintptr_t) heap);
	
			ret = 0;
		}

		next:
		UNLOCK(collection);
		if (ret == 0) {
			break;
		}
	}

	return ret;

}
