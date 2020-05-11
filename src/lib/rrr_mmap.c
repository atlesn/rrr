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

#include "log.h"
#include "rrr_mmap.h"
#include "rrr_strerror.h"
#include "vl_time.h"

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

#define RRR_MMAP_SENTINEL_DEBUG

#ifdef RRR_MMAP_SENTINEL_DEBUG
static const uint64_t rrr_mmap_sentinel_template = 0xa0a0a0a00a0a0a0a;
#endif

struct rrr_mmap_heap_block_index {
	uint64_t block_used_map;
	uint64_t block_sizes[64];
};

void rrr_mmap_free(struct rrr_mmap *mmap, void *ptr) {
	pthread_mutex_lock(&mmap->mutex);

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

//	printf("free ptr: %p\n", ptr);
	pthread_mutex_unlock(&mmap->mutex);
}

void rrr_mmap_dump_indexes (struct rrr_mmap *mmap) {
	pthread_mutex_lock(&mmap->mutex);
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
	pthread_mutex_unlock(&mmap->mutex);
}

void __dump_bin (uint64_t n) {
	for (int i = 0; i < 64; i++) {
		printf ("%i", ((n & 1) == 1) ? 1 : 0);
		n >>= 1;
	}
	printf ("\n");
}

void *rrr_mmap_allocate(struct rrr_mmap *mmap, uint64_t req_size) {
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

	pthread_mutex_lock(&mmap->mutex);

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

#ifdef RRR_MMAP_SENTINEL_DEBUG
// Sentinel should be preserved from previous last block
//				*((uint64_t*)(mmap->heap + merge_block_pos +  consecutive_unused_size - sizeof(rrr_mmap_sentinel_template))) = rrr_mmap_sentinel_template;
#endif
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
	pthread_mutex_unlock(&mmap->mutex);

	if (result == NULL) {
		rrr_mmap_dump_indexes(mmap);
	}

	return result;
}

static void *__rrr_mmap(size_t size) {
    void *ptr = mmap (
    		NULL,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS,
			-1,
			0
	);

    if (ptr != NULL) {
    	memset(ptr, '\0', size);
    }

    return ptr;
}

int rrr_mmap_heap_reallocate (struct rrr_mmap *mmap, uint64_t heap_size) {
	int ret = 0;

	pthread_mutex_lock(&mmap->mutex);
	if (mmap->usercount != 1) {
		RRR_BUG("BUG: Attempted to re-allocate heap while there was more than one user in rrr_mmap_new_heap_size\n");
	}

	uint64_t heap_size_padded = heap_size + (4096 - (heap_size % 4096));

	if (heap_size_padded < mmap->heap_size) {
		RRR_BUG("BUG: Attempted to decrease heap size in rrr_mmap_new_heap_size\n");
	}

	void *new_heap = __rrr_mmap(heap_size_padded);
	if (new_heap == NULL) {
		RRR_MSG_ERR("Could not re-allocate in rrr_mmap_new_heap_size\n");
		ret = 1;
		goto out_unlock;
	}

	memcpy(new_heap, mmap->heap, mmap->heap_size);
	munmap(mmap->heap, mmap->heap_size);
	mmap->heap = new_heap;
	mmap->heap_size = heap_size_padded;

	out_unlock:
	pthread_mutex_unlock(&mmap->mutex);
	return ret;
}

int rrr_mmap_new (struct rrr_mmap **target, uint64_t heap_size) {
	int ret = 0;

	*target = NULL;

	struct rrr_mmap *result = NULL;

    pthread_mutexattr_t attr;
    if ((ret = pthread_mutexattr_init(&attr)) != 0) {
    	RRR_MSG_ERR("Could not initialize mutexattr in rrr_mmap_new (%i)\n", ret);
    	ret = 1;
    	goto out;
    }

	if ((result = __rrr_mmap(sizeof(*result))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory with mmap in rrr_mmap_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_destroy_mutexattr;
	}

	memset(result, '\0', sizeof(*result));

	uint64_t heap_size_padded = heap_size + (4096 - (heap_size % 4096));

	if ((result->heap = __rrr_mmap(heap_size_padded)) == NULL) {
		RRR_MSG_ERR("Could not allocate memory with mmap in rrr_mmap_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_munmap_main;

	}

	result->heap_size = heap_size_padded;

//	printf ("mmap new heap size %" PRIu64 "\n", heap_size_padded);

    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if ((ret = pthread_mutex_init(&result->mutex, &attr)) != 0) {
    	RRR_MSG_ERR("Could not initialize mutex in rrr_mmap_new (%i)\n", ret);
    	ret = 1;
    	goto out_munmap_heap;
    }

    result->usercount++;

    *target = result;
    result = NULL;

    // NOTE : Remember to always destroy mutexattr
	goto out_destroy_mutexattr;

	out_munmap_heap:
		munmap(result->heap, heap_size);
	out_munmap_main:
		munmap(result, sizeof(*result));
	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&attr);
	out:
		return ret;
}

void rrr_mmap_incref (struct rrr_mmap *mmap) {
	pthread_mutex_lock(&mmap->mutex);
	mmap->usercount++;
	pthread_mutex_unlock(&mmap->mutex);
}

void rrr_mmap_destroy (struct rrr_mmap *mmap) {
	int usercount_result;

	pthread_mutex_lock(&mmap->mutex);
	usercount_result = --(mmap->usercount);
	pthread_mutex_unlock(&mmap->mutex);

	if (usercount_result == 0) {
		pthread_mutex_destroy(&mmap->mutex);
		munmap(mmap->heap, mmap->heap_size);
		munmap(mmap, sizeof(*mmap));
	}
}
