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

void rrr_mmap_free (
		struct rrr_mmap *mmap,
		void *ptr
) {
	pthread_mutex_lock(mmap->active_lock);

	uint64_t pos = ptr - mmap->heap;

	uint64_t block_pos = 0;
	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);
		if (block_pos > mmap->heap_size) {
			break;
		}

		for (uint64_t j = 0; j < 64; j++) {
			uint64_t used_mask = (uint64_t) 1 << j;

			if (index->block_sizes[j] == 0 && (index->block_used_map & used_mask) == used_mask) {
				// Unusable merged chunk
				continue;
			}

			if (block_pos == pos) {
				if ((index->block_used_map & used_mask) == 0) {
					RRR_BUG("BUG: Double free of %" PRIu64 " in rrr_mmap_free\n", pos);
				}
				index->block_used_map &= ~(used_mask);
//				printf ("mmap free block at %" PRIu64 " used mask %" PRIu64 "\n", block_pos, index->block_used_map);
				goto out_unlock;
			}

			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in rrr_mmap_free\n");
			}
		}
	}

	RRR_BUG("BUG: Invalid data position %" PRIu64 " in rrr_mmap_free\n", pos);

	out_unlock:

	mmap->prev_allocation_failure_req_size = 0;

//	printf("free ptr: %p\n", ptr);
	pthread_mutex_unlock(mmap->active_lock);
}

static int __rrr_mmap_has (
		struct rrr_mmap *mmap,
		void *ptr
) {
	int ret = 0;

	pthread_mutex_lock(mmap->active_lock);

	if (ptr >= mmap->heap && ptr < mmap->heap + mmap->heap_size) {
		ret = 1;
	}

	pthread_mutex_unlock(mmap->active_lock);

	return ret;
}

void rrr_mmap_dump_indexes (
		struct rrr_mmap *mmap
) {
	pthread_mutex_lock(mmap->active_lock);
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
	pthread_mutex_unlock(mmap->active_lock);
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

	pthread_mutex_lock(mmap->active_lock);

	if (mmap->prev_allocation_failure_req_size != 0 && mmap->prev_allocation_failure_req_size <= req_size) {
		goto out_unlock;
	}

	uint64_t block_pos = 0;
	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

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

	out_unlock:
	pthread_mutex_unlock(mmap->active_lock);

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

	pthread_mutex_lock(mmap->active_lock);

	uint64_t block_pos = 0;
	while (block_pos < mmap->heap_size) {
		struct rrr_mmap_heap_block_index *index = (struct rrr_mmap_heap_block_index *) (mmap->heap + block_pos);

		block_pos += sizeof(struct rrr_mmap_heap_block_index);

		if (block_pos > mmap->heap_size) {
			break;
		}

		if (index->block_used_map != 0) {
			ret = 0;
			break;
		}

		for (uint64_t j = 0; j < 64; j++) {
			block_pos += index->block_sizes[j];
			if (block_pos > mmap->heap_size) {
				RRR_BUG("BUG: Heap index corruption in rrr_mmap_is_empty\n");
			}
		}
	}

	pthread_mutex_unlock(mmap->active_lock);

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

	pthread_mutex_lock(mmap->active_lock);

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
	pthread_mutex_unlock(mmap->active_lock);
	return ret;
}

int rrr_mmap_new (
		struct rrr_mmap **target,
		uint64_t heap_size,
		const char *name,
		pthread_mutex_t *custom_lock,
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

	memset(result, '\0', sizeof(*result));

	uint64_t heap_size_padded = heap_size + (4096 - (heap_size % 4096));

	if ((result->heap = __rrr_mmap(heap_size_padded, is_shared)) == NULL) {
		RRR_MSG_0("Could not allocate memory with mmap in rrr_mmap_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_munmap_main;

	}

	result->is_shared = is_shared;
	result->heap_size = heap_size_padded;

//	printf ("mmap new heap size %" PRIu64 "\n", heap_size_padded);

    if ((ret = rrr_posix_mutex_init(&result->default_lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
    	RRR_MSG_0("Could not initialize mutex in rrr_mmap_new (%i)\n", ret);
    	ret = 1;
    	goto out_munmap_heap;
    }

    strncpy(result->name, name, sizeof(result->name));
    result->name[sizeof(result->name) - 1] = '\0';

    result->active_lock = (custom_lock != NULL ? custom_lock : &result->default_lock);

    *target = result;
    result = NULL;

	goto out;

	out_munmap_heap:
		munmap(result->heap, heap_size);
	out_munmap_main:
		munmap(result, sizeof(*result));
	out:
		return ret;
}

void rrr_mmap_destroy (
		struct rrr_mmap *mmap
) {
	pthread_mutex_destroy(&mmap->default_lock);
	munmap(mmap->heap, mmap->heap_size);
	munmap(mmap, sizeof(*mmap));
}

void rrr_mmap_collection_maintenance (
		struct rrr_mmap_collection *collection,
		pthread_rwlock_t *index_lock
) {
	pthread_rwlock_wrlock(index_lock);
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_mmap);
		if (__rrr_mmap_is_empty(node)) {
			printf("Destroy mmap\n");
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; rrr_mmap_destroy(node));
	printf("Maintenance: %i\n", RRR_LL_COUNT(collection));
	pthread_rwlock_unlock(index_lock);
}

void rrr_mmap_collection_clear (
		struct rrr_mmap_collection *collection,
		pthread_rwlock_t *index_lock
) {
	rrr_mmap_collection_maintenance(collection, index_lock);
	pthread_rwlock_wrlock(index_lock);
	RRR_DBG_1("MMAPs left upon cleanup: %i\n", RRR_LL_COUNT(collection));
	RRR_LL_DESTROY(collection, struct rrr_mmap, rrr_mmap_destroy(node));
	pthread_rwlock_unlock(index_lock);
}

void *rrr_mmap_collection_allocate (
		struct rrr_mmap_collection *collection,
		uint64_t bytes,
		uint64_t min_mmap_size,
		pthread_rwlock_t *index_lock,
		pthread_mutex_t *custom_lock,
		const char *name,
		int group,
		int is_shared
) {
	void *result = NULL;
/*
	{
		// 1st attempt

		struct rrr_mmap *mmap_to_use = NULL;

		pthread_rwlock_wrlock(index_lock);
			RRR_LL_ITERATE_BEGIN(collection, struct rrr_mmap);
				if (node->group == group && (node->prev_allocation_failure_req_size == 0 || node->prev_allocation_failure_req_size < bytes)) {
					mmap_to_use = node;
					RRR_LL_ITERATE_SET_DESTROY();
					RRR_LL_ITERATE_LAST();
				}
			RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0);

			if (mmap_to_use != NULL) {
				result = rrr_mmap_allocate(mmap_to_use, bytes);

				if (result == NULL) {
					RRR_LL_APPEND(collection, mmap_to_use);
				}
				else {
					RRR_LL_UNSHIFT(collection, mmap_to_use);
				}
			}

		pthread_rwlock_unlock(index_lock);

		if (result) {
//			printf("1st ok\n");
			goto out;
		}
	}

*/
	{
		// 2nd attempt

		pthread_rwlock_rdlock(index_lock);
			RRR_LL_ITERATE_BEGIN(collection, struct rrr_mmap);
				if (node->group == group && (node->prev_allocation_failure_req_size == 0 || node->prev_allocation_failure_req_size < bytes)) {
					if ((result = rrr_mmap_allocate(node, bytes)) != NULL) {
						RRR_LL_ITERATE_LAST();
					}
				}
			RRR_LL_ITERATE_END();
		pthread_rwlock_unlock(index_lock);

		if (result) {
//			printf("2nd ok\n");
			goto out;
		}
	}

	struct rrr_mmap *mmap_new;

	pthread_rwlock_wrlock(index_lock);
	if (rrr_mmap_new (&mmap_new, bytes > min_mmap_size ? bytes : min_mmap_size, name, custom_lock, is_shared) != 0) {
		pthread_rwlock_unlock(index_lock);
		goto out;
	}

	mmap_new->group = group;

	RRR_LL_UNSHIFT(collection, mmap_new);

//	printf("New collection %i\n", RRR_LL_COUNT(collection));

	result = rrr_mmap_allocate(mmap_new, bytes);
	pthread_rwlock_unlock(index_lock);

	out:
	return result;
}

void rrr_mmap_collection_free (
		struct rrr_mmap_collection *collection,
		pthread_rwlock_t *index_lock,
		void *ptr
) {
	int ok = 0;

	pthread_rwlock_rdlock(index_lock);
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_mmap);
		if (__rrr_mmap_has (node, ptr)) {
			rrr_mmap_free(node, ptr);
			ok = 1;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();
	pthread_rwlock_unlock(index_lock);

	if (!ok) {
		RRR_BUG("BUG: Invalid free of ptr %p in rrr_mmap_collection_free\n", ptr);
	}
}
