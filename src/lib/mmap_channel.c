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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "rrr_strerror.h"
#include "log.h"
#include "mmap_channel.h"
#include "rrr_mmap.h"
#include "random.h"

// Messages larger than this limit are transferred using SHM
#define RRR_MMAP_CHANNEL_SHM_LIMIT 1024
#define RRR_MMAP_CHANNEL_SHM_MIN_ALLOC_SIZE 4096

int rrr_mmap_channel_write_is_possible (struct rrr_mmap_channel *target) {
	int possible = 1;

	pthread_mutex_lock(&target->index_lock);

	struct rrr_mmap_channel_block *block = &(target->blocks[target->wpos]);
	if (block->size_data != 0) {
		possible = 0;
	}

	pthread_mutex_unlock(&target->index_lock);

	return possible;
}

static int __rrr_mmap_channel_block_free (
		struct rrr_mmap_channel *target,
		struct rrr_mmap_channel_block *block
) {
	if (block->shmid != 0) {
		if (block->ptr_shm_or_mmap == NULL) {
			// Attempt to recover from previously failed allocation
			struct shmid_ds ds;
			if (shmctl(block->shmid, IPC_STAT, &ds) != block->shmid) {
				RRR_MSG_0("Warning: shmctl IPC_STAT failed in __rrr_mmap_channel_block_free: %s\n", rrr_strerror(errno));
			}
			else {
				if (ds.shm_nattch > 0) {
					RRR_BUG("Dangling shared memory key in __rrr_mmap_channel_block_free, cannot continue\n");
				}

				if (shmctl(block->shmid, IPC_RMID, NULL) != 0) {
					RRR_MSG_0("shmctl IPC_RMID failed in __rrr_mmap_channel_block_free: %s\n", rrr_strerror(errno));
					return 1;
				}
			}
		}
		else if (shmdt(block->ptr_shm_or_mmap) != 0) {
			RRR_MSG_0("shmdt failed in rrr_mmap_channel_write_using_callback: %s\n", rrr_strerror(errno));
			return 1;
		}
	}
	else if (block->ptr_shm_or_mmap != NULL) {
		rrr_mmap_free(target->mmap, block->ptr_shm_or_mmap);
	}

	block->ptr_shm_or_mmap = NULL;
	block->size_data = 0;
	block->size_capacity = 0;
	block->shmid = 0;

	return 0;
}

void rrr_mmap_channel_writer_free_unused_mmap_blocks (struct rrr_mmap_channel *target) {
	pthread_mutex_lock(&target->index_lock);

	for (int i = 0; i != RRR_MMAP_CHANNEL_SLOTS; i++) {
		if (target->blocks[i].size_data == 0 && target->blocks[i].shmid == 0 && target->blocks[i].ptr_shm_or_mmap != NULL) {
			__rrr_mmap_channel_block_free(target, &target->blocks[i]);
		}
	}

	pthread_mutex_unlock(&target->index_lock);
}

static int __rrr_mmap_channel_allocate (
		struct rrr_mmap_channel *target,
		struct rrr_mmap_channel_block *block,
		size_t data_size
) {
	int ret = 0;

	if (block->size_capacity >= data_size) {
		goto out;
	}
	if ((ret = __rrr_mmap_channel_block_free(target, block)) != 0) {
		goto out;
	}

	if (data_size > RRR_MMAP_CHANNEL_SHM_LIMIT) {
		key_t new_key;

		data_size = data_size - (data_size % RRR_MMAP_CHANNEL_SHM_MIN_ALLOC_SIZE) +
				RRR_MMAP_CHANNEL_SHM_MIN_ALLOC_SIZE;

		int shmid = 0;
		do {
			new_key = rrr_rand();
//			printf("allocate shmget key %i pos %i size %lu\n", new_key, block_pos, data_size);
			if ((shmid = shmget(new_key, data_size, IPC_CREAT|IPC_EXCL|0600)) == -1) {
				if (errno == EEXIST) {
					// OK, try another key
				}
				else {
					RRR_MSG_0("Error from shmget in __rrr_mmap_channel_allocate: %s\n", rrr_strerror(errno));
					ret = 1;
					goto out;
				}
			}
		} while (shmid <= 0);

		block->shmid = shmid;
		block->size_capacity = data_size;

		if ((block->ptr_shm_or_mmap = shmat(shmid, NULL, 0)) == NULL) {
			RRR_MSG_0("shmat failed in __rrr_mmap_channel_allocate: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		if (shmctl(shmid, IPC_RMID, NULL) != 0) {
			RRR_MSG_0("shmctl IPC_RMID failed in __rrr_mmap_channel_allocate: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}
	else {
		if ((block->ptr_shm_or_mmap = rrr_mmap_allocate(target->mmap, data_size)) == NULL) {
//			RRR_MSG_0("Could not allocate mmap memory in __rrr_mmap_channel_allocate \n");
			ret = 1;
			goto out;
		}
		block->size_capacity = data_size;
		block->shmid = 0;
	}

	out:
	return ret;
}

int rrr_mmap_channel_write_using_callback (
		struct rrr_mmap_channel *target,
		size_t data_size,
		int (*callback)(void *target, void *arg),
		void *callback_arg
) {
	int ret = RRR_MMAP_CHANNEL_OK;

	int do_unlock_block = 0;

	pthread_mutex_lock(&target->index_lock);
	struct rrr_mmap_channel_block *block = &(target->blocks[target->wpos]);
	pthread_mutex_unlock(&target->index_lock);

	if (pthread_mutex_trylock(&block->block_lock) != 0) {
		ret = RRR_MMAP_CHANNEL_FULL;
		goto out_unlock;
	}
	do_unlock_block = 1;

	// When the other end is done with the data, it sets size to 0
	if (block->size_data != 0) {
		ret = RRR_MMAP_CHANNEL_FULL;
		goto out_unlock;
	}

	if (__rrr_mmap_channel_allocate(target, block, data_size) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_mmap_channel_write\n");
		ret = 1;
		goto out_unlock;
	}

	ret = callback(block->ptr_shm_or_mmap, callback_arg);

	if (ret != 0) {
		RRR_MSG_0("Error from callback in rrr_mmap_channel_write_using_callback\n");
		ret = 1;
		goto out_unlock;
	}

	block->size_data = data_size;

	RRR_DBG_4("mmap channel %p %s wr blk %i size %li\n", target, target->name, target->wpos, data_size);

	pthread_mutex_unlock(&block->block_lock);
	do_unlock_block = 0;

	pthread_mutex_lock(&target->index_lock);
	target->wpos++;
	if (target->wpos == RRR_MMAP_CHANNEL_SLOTS) {
		target->wpos = 0;
	}
	pthread_mutex_unlock(&target->index_lock);

	out_unlock:
	if (do_unlock_block) {
		pthread_mutex_unlock(&block->block_lock);
	}

	return ret;
}

struct rrr_mmap_channel_write_callback_arg {
	const void *data;
	size_t data_size;
};

static int __rrr_mmap_channel_write_callback (void *target_ptr, void *arg) {
	struct rrr_mmap_channel_write_callback_arg *data = arg;
	memcpy(target_ptr, data->data, data->data_size);
	return 0;
}

int rrr_mmap_channel_write (
		struct rrr_mmap_channel *target,
		const void *data,
		size_t data_size
) {
	struct rrr_mmap_channel_write_callback_arg callback_data = {
			data,
			data_size
	};
	return rrr_mmap_channel_write_using_callback(target, data_size, __rrr_mmap_channel_write_callback, &callback_data);
}

int rrr_mmap_channel_read_with_callback (
		struct rrr_mmap_channel *source,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
) {
	int ret = RRR_MMAP_CHANNEL_OK;

	int do_rpos_increment = 1;

	int do_unlock_block = 0;

	pthread_mutex_lock(&source->index_lock);
	struct rrr_mmap_channel_block *block = &(source->blocks[source->rpos]);
	pthread_mutex_unlock(&source->index_lock);

	if (pthread_mutex_trylock(&block->block_lock) != 0) {
		ret = RRR_MMAP_CHANNEL_EMPTY;
		goto out_unlock;
	}
	do_unlock_block = 1;

	if (block->size_data == 0) {
		ret = RRR_MMAP_CHANNEL_EMPTY;
		goto out_unlock;
	}

	RRR_DBG_4("mmap channel %p %s rd blk %i size %li\n", source, source->name, source->rpos, block->size_data);

	if (block->shmid != 0) {
		const char *data_pointer = NULL;

		if ((data_pointer = shmat(block->shmid, NULL, 0)) == NULL) {
			RRR_MSG_0("Could not get shm pointer in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_unlock;
		}

		if ((ret = callback(data_pointer, block->size_data, callback_arg)) != 0) {
			RRR_MSG_0("Error from callback in rrr_mmap_channel_read_with_callback\n");
			ret = 1;
			do_rpos_increment = 0;
		}

		if (shmdt(data_pointer) != 0) {
			RRR_MSG_0("shmdt failed in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_rpos_increment;
		}
	}
	else {
		if ((ret = callback(block->ptr_shm_or_mmap, block->size_data, callback_arg)) != 0) {
			RRR_MSG_0("Error from callback in rrr_mmap_channel_read_with_callback\n");
			ret = 1;
			do_rpos_increment = 0;
		}
	}

	out_rpos_increment:
	if (do_rpos_increment) {
		block->size_data = 0;
		pthread_mutex_unlock(&block->block_lock);
		do_unlock_block = 0;

		pthread_mutex_lock(&source->index_lock);
		source->rpos++;
		if (source->rpos == RRR_MMAP_CHANNEL_SLOTS) {
			source->rpos = 0;
		}
		pthread_mutex_unlock(&source->index_lock);
	}

//	printf ("mmap channel read from mmap %p to local %p size_data %lu\n", block->ptr, result, *target_size);

	out_unlock:
	if (do_unlock_block) {
		pthread_mutex_unlock(&block->block_lock);
	}
	return ret;
}

int rrr_mmap_channel_read_all (
		struct rrr_mmap_channel *source,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int i = RRR_MMAP_CHANNEL_SLOTS;

	do {
		ret = rrr_mmap_channel_read_with_callback(source, callback, callback_arg);
	} while(ret == 0 && --i > 0);

	return ret;
}

struct rrr_mmap_channel_read_callback_data {
	void *data;
	size_t data_size;
};

static int __rrr_mmap_channel_read_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_mmap_channel_read_callback_data *callback_data = arg;

	int ret = 0;

	if ((callback_data->data = malloc(data_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_mmap_channel_read_callback\n");
		ret = 1;
		goto out;
	}

	memcpy(callback_data->data, data, data_size);
	callback_data->data_size = data_size;

	out:
	return ret;
}

int rrr_mmap_channel_read (
		void **target,
		size_t *target_size,
		struct rrr_mmap_channel *source
) {
	struct rrr_mmap_channel_read_callback_data callback_data = {0};

	int ret = 0;

	*target = NULL;
	*target_size = 0;

	if ((ret = rrr_mmap_channel_read_with_callback(source, __rrr_mmap_channel_read_callback, &callback_data)) != 0) {
		return ret;
	}

	*target = callback_data.data;
	*target_size = callback_data.data_size;

	return ret;
}

void rrr_mmap_channel_bubblesort_pointers (struct rrr_mmap_channel *target, int *was_sorted) {
	*was_sorted = 1;

	for (int i = 0; i < RRR_MMAP_CHANNEL_SLOTS - 1; i++) {
		int j = i + 1;

		struct rrr_mmap_channel_block *block_i = &target->blocks[i];
		struct rrr_mmap_channel_block *block_j = &target->blocks[j];

		if (pthread_mutex_trylock(&block_i->block_lock) == 0) {
			if (block_i->size_data == 0 &&
				block_i->ptr_shm_or_mmap != NULL &&
				pthread_mutex_trylock(&block_j->block_lock
			) == 0) {
				// Swap blocks if pointer of i is larger than pointer of j. Don't re-order
				// filled data blocks.
				if (block_j->size_data == 0 &&
					block_j->ptr_shm_or_mmap != NULL &&
					block_i->ptr_shm_or_mmap > block_j->ptr_shm_or_mmap
				) {
//					printf ("swap i and j (%p > %p)\n", block_i->ptr_shm_or_mmap, block_j->ptr_shm_or_mmap);
					// The data structure here makes sure we don't forget to update
					// this function when the struct changes.
					struct rrr_mmap_channel_block tmp = {
							PTHREAD_MUTEX_INITIALIZER, // Not used
							block_i->size_capacity,
							block_i->size_data,
							block_i->shmid,
							block_i->ptr_shm_or_mmap
					};

					block_i->size_capacity = block_j->size_capacity;
					block_i->size_data = block_j->size_data;
					block_i->shmid = block_j->shmid;
					block_i->ptr_shm_or_mmap = block_j->ptr_shm_or_mmap;

					block_j->size_capacity = tmp.size_capacity;
					block_j->size_data = tmp.size_data;
					block_j->shmid = tmp.shmid;
					block_j->ptr_shm_or_mmap = tmp.ptr_shm_or_mmap;

					*was_sorted = 0;
				}
				pthread_mutex_unlock(&block_j->block_lock);
			}
			pthread_mutex_unlock(&block_i->block_lock);
		}
	}
}

void rrr_mmap_channel_destroy (struct rrr_mmap_channel *target) {
	pthread_mutex_destroy(&target->index_lock);
	int msg_count = 0;
	for (int i = 0; i != RRR_MMAP_CHANNEL_SLOTS; i++) {
		if (target->blocks[i].ptr_shm_or_mmap != NULL) {
			if (++msg_count == 1) {
				RRR_MSG_0("Warning: Pointer was still present in block in rrr_mmap_channel_destroy\n");
			}
		}
		pthread_mutex_destroy(&target->blocks[i].block_lock);
	}
	if (msg_count > 1) {
		RRR_MSG_0("Last message duplicated %i times\n", msg_count - 1);
	}

	rrr_mmap_free(target->mmap, target);
}

void rrr_mmap_channel_writer_free_blocks (struct rrr_mmap_channel *target) {
	pthread_mutex_lock(&target->index_lock);

	// This function does not lock the blocks in case the reader has crashed
	// while holding the mutex
	for (int i = 0; i != RRR_MMAP_CHANNEL_SLOTS; i++) {
		__rrr_mmap_channel_block_free(target, &target->blocks[i]);
	}

	target->wpos = 0;
	target->rpos = 0;

	pthread_mutex_unlock(&target->index_lock);
}

int rrr_mmap_channel_new (struct rrr_mmap_channel **target, struct rrr_mmap *mmap, const char *name) {
	int ret = 0;

	struct rrr_mmap_channel *result = NULL;

	int mutex_i = 0;
	pthread_mutexattr_t attr;

	if ((ret = pthread_mutexattr_init(&attr)) != 0) {
		RRR_MSG_0("Could not initialize mutexattr inrrr_mmap_channel_new (%i)\n", ret);
		ret = 1;
		goto out;
	}

    if ((result = rrr_mmap_allocate(mmap, sizeof(*result))) == NULL) {
    	RRR_MSG_0("Could not allocate memory in rrr_mmap_channel_new\n");
    	ret = 1;
    	goto out_destroy_mutexattr;
    }

	memset(result, '\0', sizeof(*result));

	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

	if ((ret = pthread_mutex_init(&result->index_lock, &attr)) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_mmap_new (%i)\n", ret);
		ret = 1;
		goto out_free;
	}

	for (mutex_i = 0; mutex_i != RRR_MMAP_CHANNEL_SLOTS; mutex_i++) {
		if ((ret = pthread_mutex_init(&result->blocks[mutex_i].block_lock, &attr)) != 0) {
			RRR_MSG_0("Could not initialize mutex in rrr_mmap_new %i\n", ret);
			ret = 1;
			goto out_destroy_mutexes;
		}
	}

    strncpy(result->name, name, sizeof(result->name));
    result->name[sizeof(result->name) - 1] = '\0';

	result->mmap = mmap;

	*target = result;
	result = NULL;

	goto out;

	out_destroy_mutexes:
		for (mutex_i = mutex_i - 1; mutex_i >= 0; mutex_i--) {
			pthread_mutex_destroy(&result->blocks[mutex_i].block_lock);
		}
		pthread_mutex_destroy(&result->index_lock);
	out_free:
		rrr_mmap_free(mmap, result);
	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&attr);
	out:
		return ret;
}
