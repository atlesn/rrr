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

#define RRR_MMAP_HEAP_CHUNK_MIN_SIZE 16

#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "rrr_mmap.h"
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

//#define RRR_MMAP_SENTINEL_DEBUG

#ifdef RRR_MMAP_SENTINEL_DEBUG
static const uint64_t rrr_mmap_sentinel_template = 0xa0a0a0a00a0a0a0a;
#endif

struct rrr_mmap_heap_block_index {
	uint64_t block_used_map;
	uint64_t block_sizes[64];
};

static void __rrr_mmap_free (
		struct rrr_mmap *mmap
) {
	int blocks = 0;
	int iterations = 0;

	if (mmap->to_free_list_count == 0) {
		return;
	}

	size_t to_free_list_sorted_count = 0;
	uintptr_t last_value = 0;
	uintptr_t to_free_list_sorted[RRR_MMAP_TO_FREE_LIST_MAX];
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
	uint64_t block_pos = 0;

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

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

			const uintptr_t ptr = (uintptr_t) mmap->heap + block_pos;

			if (to_free_list_sorted[to_free_list_sorted_pos] == ptr) {
				if ((index->block_used_map & used_mask) == 0) {
					RRR_BUG("BUG: Double free of %p in rrr_mmap_free\n", ptr);
				}

				index->block_used_map &= ~(used_mask);

				if (++to_free_list_sorted_pos == to_free_list_sorted_count) {
					goto out;
				}
//				printf ("mmap free block at %" PRIu64 " used mask %" PRIu64 "\n", block_pos, index->block_used_map);
			}

			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in rrr_mmap_free\n");
			}
		}
	}

	out:

	if (to_free_list_sorted_pos != to_free_list_sorted_count) {
		RRR_BUG("BUG: Invalid free of in rrr_mmap_free, one or more positions not found %lu<>%lu\n",
				to_free_list_sorted_pos, to_free_list_sorted_count);
	}

	mmap->prev_allocation_failure_req_size = 0;
	mmap->to_free_list_count = 0;

//	printf("Free blocks/iterations: %i %i\n", blocks, iterations);
}

void rrr_mmap_free (
		struct rrr_mmap *mmap,
		void *ptr
) {
	pthread_mutex_lock(&mmap->lock);

	mmap->to_free_list[mmap->to_free_list_count++] = (uintptr_t) ptr;

	if (mmap->to_free_list_count == RRR_MMAP_TO_FREE_LIST_MAX) {
		__rrr_mmap_free(mmap);
	}

	pthread_mutex_unlock(&mmap->lock);

	mmap->prev_allocation_failure_req_size = 0;
}

/*static int __rrr_mmap_has (
		struct rrr_mmap *mmap,
		void *ptr
) {
	int ret = 0;

	// Non-mutable values only checked, protected by index lock

	if (ptr >= mmap->heap && ptr < mmap->heap + mmap->heap_size) {
		ret = 1;
	}

	return ret;
}*/

void rrr_mmap_dump_indexes (
		struct rrr_mmap *mmap
) {
	pthread_mutex_lock(&mmap->lock);
	uint64_t block_pos = 0;
	uint64_t total_free_bytes = 0;
	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

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
	pthread_mutex_unlock(&mmap->lock);
}

void __dump_bin (uint64_t n) {
	for (int i = 0; i < 64; i++) {
		printf ("%i", ((n & 1) == 1) ? 1 : 0);
		n >>= 1;
	}
	printf ("\n");
}

void *rrr_mmap_allocate (
		struct rrr_mmap *mmap,
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

//	printf ("mmap allocate request %" PRIu64 "\n", req_size);

	void *result = NULL;

	pthread_mutex_lock(&mmap->lock);

	if (mmap->prev_allocation_failure_req_size != 0 && mmap->prev_allocation_failure_req_size <= req_size) {
		goto out_unlock;
	}

	int retry_count = 0;
	uint64_t block_pos = mmap->prev_allocation_index_pos;

	if (block_pos > 0) {
		retry_count = 1;
	}

	retry:

	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

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
				result = mmap->heap + block_pos;
//				printf("new ptr: %p\n", result);
#ifdef RRR_MMAP_SENTINEL_DEBUG
				*((uint64_t*)(mmap->heap + block_pos + req_size_padded - sizeof(rrr_mmap_sentinel_template))) = rrr_mmap_sentinel_template;
#endif
//				printf ("mmap allocate new block at %" PRIu64 " size %" PRIu64 " used mask %" PRIu64 "\n", block_pos, req_size_padded, index->block_used_map);
				goto out_unlock;
			}
			else {
#ifdef RRR_MMAP_SENTINEL_DEBUG
				if (*((uint64_t*)(mmap->heap + block_pos + index->block_sizes[j] - sizeof(rrr_mmap_sentinel_template))) != rrr_mmap_sentinel_template) {
					RRR_BUG("Sentinel overwritten at end of block at position %" PRIu64 "\n", block_pos);
				}
#endif

//				printf ("block size %" PRIu64 " - %" PRIu64 "\n", j, index->block_sizes[j]);

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
						result = mmap->heap + block_pos;
//						printf("re-use ptr: %p\n", result);
	//					printf ("mmap allocate old block at %" PRIu64 " size %" PRIu64 " used mask %" PRIu64 "\n", block_pos, req_size_padded, index->block_used_map);
						goto out_unlock;
					}
					else if (consecutive_unused_size >= req_size_padded) {
						// Merge blocks if multiple after each other are free
						for (uint64_t k = merge_j; k <= j; k++) {
							index->block_used_map |= (uint64_t) 1 << k;
							index->block_sizes[k] = 0;
						}
						index->block_sizes[merge_j] = consecutive_unused_size;
						result = mmap->heap + merge_block_pos;

//						printf("merge ptr: %p\n", result);

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
	pthread_mutex_unlock(&mmap->lock);

	if (result == NULL) {
		mmap->prev_allocation_failure_req_size = req_size;
//		rrr_mmap_dump_indexes(mmap);
	}

	return result;
}

static int __rrr_mmap_is_empty (
		struct rrr_mmap *mmap
) {
	int ret = 1;

	pthread_mutex_lock(&mmap->lock);

	uint64_t block_pos = 0;
	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);

		if (block_pos > mmap->heap_size) {
			break;
		}

		if (index->block_used_map != 0) {
//			printf("Dirty block %lu\n", block_pos);
			for (uint64_t j = 0; j < 64; j++) {
				uint64_t used_mask = (uint64_t) 1 << j;
				if ((index->block_used_map & used_mask) && index->block_sizes[j] != 0) {
//					printf("Dirty bit %lu:%lu\n", block_pos, j);
					ret = 0;
					goto out_unlock;
				}
			}
		}

		for (uint64_t j = 0; j < 64; j++) {
			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in rrr_mmap_is_empty block size %lu\n", index->block_sizes[j]);
			}
		}
	}

	out_unlock:

	pthread_mutex_unlock(&mmap->lock);

	return ret;
}

static void *__rrr_mmap (size_t size, int is_shared) {
    void *ptr = rrr_posix_mmap(size, is_shared);

    if (ptr != NULL) {
    	memset(ptr, '\0', size);
    }

    return ptr;
}

int rrr_mmap_heap_reallocate (
		struct rrr_mmap *mmap,
		uint64_t heap_size
) {
	int ret = 0;

	pthread_mutex_lock(&mmap->lock);

	uint64_t heap_size_padded = heap_size + (4096 - (heap_size % 4096));

	if (heap_size_padded < mmap->heap_size) {
		RRR_BUG("BUG: Attempted to decrease heap size in rrr_mmap_new_heap_size\n");
	}

	void *new_heap = __rrr_mmap(heap_size_padded, mmap->is_shared);
	if (new_heap == NULL) {
		RRR_MSG_0("Could not re-allocate in rrr_mmap_new_heap_size\n");
		ret = 1;
		goto out_unlock;
	}

	memcpy(new_heap, mmap->heap, mmap->heap_size);
	munmap(mmap->heap, mmap->heap_size);
	mmap->heap = new_heap;
	mmap->heap_size = heap_size_padded;

	out_unlock:
	pthread_mutex_unlock(&mmap->lock);
	return ret;
}

static int __rrr_mmap_init (
		struct rrr_mmap *result,
		uint64_t heap_size,
		int is_shared
) {
	int ret = 0;

	memset(result, '\0', sizeof(*result));

	uint64_t heap_size_padded = heap_size + (4096 - (heap_size % 4096));

	if ((ret = rrr_posix_mutex_init(&result->lock, (is_shared ? RRR_POSIX_MUTEX_IS_PSHARED : 0))) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_mmap_init (%i)\n", ret);
		ret = 1;
		goto out_munmap_heap;
	}

	if ((result->heap = __rrr_mmap(heap_size_padded, is_shared)) == NULL) {
		RRR_MSG_0("Could not allocate memory with mmap in rrr_mmap_init: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;

	}

	result->is_shared = is_shared;
	result->heap_size = heap_size_padded;

	goto out;

	out_munmap_heap:
		munmap(result->heap, heap_size);
	out:
		return ret;
}

int rrr_mmap_new (
		struct rrr_mmap **target,
		uint64_t heap_size,
		int is_shared
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mmap *result = NULL;

	if ((result = __rrr_mmap(sizeof(*result), is_shared)) == NULL) {
		RRR_MSG_0("Could not allocate memory with mmap in rrr_mmap_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}

	if ((ret = __rrr_mmap_init (result, heap_size, is_shared)) != 0) {
		goto out_munmap_main;
	}

	*target = result;
	result = NULL;

	goto out;

	out_munmap_main:
		munmap(result, sizeof(*result));
	out:
		return ret;
}

void __rrr_mmap_cleanup (
		struct rrr_mmap *mmap
) {
	pthread_mutex_destroy(&mmap->lock);
	munmap(mmap->heap, mmap->heap_size);
	memset(mmap, '\0', sizeof(*mmap));
}

void rrr_mmap_destroy (
		struct rrr_mmap *mmap
) {
	pthread_mutex_destroy(&mmap->lock);
	munmap(mmap->heap, mmap->heap_size);
	munmap(mmap, sizeof(*mmap));
}

#define RRR_MMAP_ITERATE_BEGIN() \
	do { for (size_t i = 0; i < RRR_MMAP_COLLECTION_MAX; i++) { \
		struct rrr_mmap *node = &collection->mmaps[i] \

#define RRR_MMAP_ITERATE_END() \
	}} while(0)

static void __rrr_mmap_collection_minmax_update (
		struct rrr_mmap_collection *collection
) {
	size_t pos = 0;
	RRR_MMAP_ITERATE_BEGIN();
		if (node->heap != NULL) {
			collection->minmax[pos].heap_min = (uintptr_t) node->heap;
			collection->minmax[pos].heap_max = (uintptr_t) node->heap + node->heap_size;
			collection->minmax[pos].mmap_idx = i;
			pos++;
		}
		if (pos == collection->mmap_count) {
			break;
		}
	RRR_MMAP_ITERATE_END();
}

static int __rrr_mmap_collection_minmax_search (
		size_t *pos,
		struct rrr_mmap_collection *collection,
		uintptr_t ptr
) {
	for (size_t j = 0; j < collection->mmap_count; j++) {
		if (ptr >= collection->minmax[j].heap_min && ptr < collection->minmax[j].heap_max) {
//			printf("cmp %lu >= %lu && %lu < %lu\n", ptr, collection->minmax[j].heap_min, ptr, collection->minmax[j].heap_max);
			*pos = collection->minmax[j].mmap_idx;
			return 1;
		}
	}
	return 0;
}

void rrr_mmap_collection_maintenance (
		struct rrr_mmap_collection *collection,
		pthread_rwlock_t *index_lock
) {
	int count = 0;

	pthread_rwlock_rdlock(index_lock);
	RRR_MMAP_ITERATE_BEGIN();
		if (node->heap != NULL) {
			pthread_mutex_lock(&node->lock);
			__rrr_mmap_free(node);
			pthread_mutex_unlock(&node->lock);
		}
	RRR_MMAP_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	pthread_rwlock_wrlock(index_lock);
	RRR_MMAP_ITERATE_BEGIN();
		if (node->heap != NULL && __rrr_mmap_is_empty(node)) {
			 if (++node->maintenance_cleanup_strikes == RRR_MMAP_COLLECTION_MAINTENANCE_CLEANUP_STRIKES) {
				 __rrr_mmap_cleanup (node);
				collection->mmap_count--;
				__rrr_mmap_collection_minmax_update(collection);
			 }
		}
		else if (node->heap != NULL) {
			node->maintenance_cleanup_strikes = 0;
			count++;
		}
	RRR_MMAP_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	printf("Maintenance: %i\n", count);
}

void rrr_mmap_collection_clear (
		struct rrr_mmap_collection *collection,
		pthread_rwlock_t *index_lock
) {
	int count = 0;

	rrr_mmap_collection_maintenance(collection, index_lock);

	pthread_rwlock_wrlock(index_lock);
	RRR_MMAP_ITERATE_BEGIN();
		if (node->heap != NULL) {
			__rrr_mmap_cleanup (node);
			collection->mmap_count--;
			count++;
		}
	RRR_MMAP_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	printf("MMAPs left upon cleanup: %i\n", count);
}

void *rrr_mmap_collection_allocate (
		struct rrr_mmap_collection *collection,
		uint64_t bytes,
		uint64_t min_mmap_size,
		pthread_rwlock_t *index_lock,
		int is_shared
) {
	void *result = NULL;

	pthread_rwlock_rdlock(index_lock);
	RRR_MMAP_ITERATE_BEGIN();
		if (node->heap != NULL && (result = rrr_mmap_allocate(node, bytes)) != NULL) {
			break;
		}
	RRR_MMAP_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	if (result) {
		goto out;
	}

	pthread_rwlock_wrlock(index_lock);
	RRR_MMAP_ITERATE_BEGIN();
		if (node->heap == NULL) {
			printf("New collection at %lu\n", i);
			if (__rrr_mmap_init (node, bytes > min_mmap_size ? bytes : min_mmap_size, is_shared) != 0) {
				break;
			}
			collection->mmap_count++;
			__rrr_mmap_collection_minmax_update(collection);
			result = rrr_mmap_allocate(node, bytes);
			break;
		}
	RRR_MMAP_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	out:
	return result;
}

int rrr_mmap_collections_free (
		struct rrr_mmap_collection *collections,
		size_t collection_count,
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
				(uintptr_t) ptr
		) == 1) {
			rrr_mmap_free(&collections[j].mmaps[pos], ptr);
			ret = 0;
		}
	}

	pthread_rwlock_unlock(index_lock);

	return ret;

}
