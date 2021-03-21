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
#include "event.h"
#include "event_functions.h"
#include "util/rrr_time.h"
#include "util/posix.h"

// Messages larger than this limit are transferred using SHM
#define RRR_MMAP_CHANNEL_SHM_LIMIT 1024
#define RRR_MMAP_CHANNEL_SHM_MIN_ALLOC_SIZE 4096

struct rrr_mmap_channel_block {
	pthread_mutex_t block_lock;
	size_t size_capacity;
	size_t size_data; // If set to 0, block is free
	int shmid;
	void *ptr_shm_or_mmap;
};

struct rrr_mmap_channel {
	struct rrr_mmap *mmap;
	pthread_mutex_t index_lock;
	int entry_count;
	int wpos;
	int rpos;
	struct rrr_mmap_channel_block blocks[RRR_MMAP_CHANNEL_SLOTS];
	char name[64];

	unsigned long long int read_starvation_counter;
	unsigned long long int write_full_counter;
};

int rrr_mmap_channel_count (
		struct rrr_mmap_channel *target
) {
	int count;
	pthread_mutex_lock(&target->index_lock);
	count = target->entry_count;
	pthread_mutex_unlock(&target->index_lock);
	return count;
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

static int __rrr_mmap_channel_allocate (
		struct rrr_mmap_channel *target,
		struct rrr_mmap_channel_block *block,
		size_t data_size
) {
	int ret = 0;

	// To reduce the chance of hitting the operating system limit on the total number of
	// shared memory blocks, free the allocation if shm is not needed for this write.
	if (block->shmid != 0 && block->ptr_shm_or_mmap != NULL) {
		if (data_size >= RRR_MMAP_CHANNEL_SHM_MIN_ALLOC_SIZE && data_size <= block->size_capacity) {
			goto out;
		}
	}
	else {
		if (data_size <= block->size_capacity) {
			goto out;
		}
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
		struct rrr_event_queue *queue_notify,
		uint8_t queue_flags,
		size_t data_size,
		int wait_attempts_max,
		unsigned int full_wait_time_us,
		int (*callback)(void *target, void *arg),
		void *callback_arg
) {
	int ret = RRR_MMAP_CHANNEL_OK;

	int do_unlock_block = 0;

	struct rrr_mmap_channel_block *block = NULL;

	goto attempt_block_lock;

	attempt_write_wait:
		// We MUST NOT hold index lock and block lock simultaneously. cond_wait will lock index.
		// NOTE : Index lock is only locked and unlocked locally, not at out
		if (do_unlock_block) {
			pthread_mutex_unlock(&block->block_lock);
			do_unlock_block = 0;
		}

		if (full_wait_time_us == 0 || wait_attempts_max-- == 0) {
			pthread_mutex_lock(&target->index_lock);
			target->write_full_counter++;
			pthread_mutex_unlock(&target->index_lock);
			ret = RRR_MMAP_CHANNEL_FULL;
			goto out_unlock;
		}

		rrr_posix_usleep(full_wait_time_us);

	attempt_block_lock:
		pthread_mutex_lock(&target->index_lock);
		block = &(target->blocks[target->wpos]);
		pthread_mutex_unlock(&target->index_lock);

		if (pthread_mutex_trylock(&block->block_lock) != 0) {
			goto attempt_write_wait;
		}
		do_unlock_block = 1;

	// When the other end is done with the data, it sets size to 0
	if (block->size_data != 0) {
		goto attempt_write_wait;
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

	RRR_MMAP_DBG("mmap channel %p %s wr blk %i size %li\n", target, target->name, target->wpos, data_size);

	pthread_mutex_unlock(&block->block_lock);
	do_unlock_block = 0;

	pthread_mutex_lock(&target->index_lock);
	target->entry_count++;
	target->wpos++;
	if (target->wpos == RRR_MMAP_CHANNEL_SLOTS) {
		target->wpos = 0;
	}
	pthread_mutex_unlock(&target->index_lock);

	if (queue_notify != NULL) {
		rrr_event_pass(queue_notify, RRR_EVENT_FUNCTION_MMAP_CHANNEL_DATA_AVAILABLE, queue_flags, 1);
	}

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
		struct rrr_event_queue *queue_notify,
		uint8_t queue_flags,
		const void *data,
		size_t data_size,
		unsigned int full_wait_time_us,
		int retries_max
) {
	struct rrr_mmap_channel_write_callback_arg callback_data = {
			data,
			data_size
	};
	return rrr_mmap_channel_write_using_callback (
			target,
			queue_notify,
			queue_flags,
			data_size,
			full_wait_time_us,
			retries_max,
			__rrr_mmap_channel_write_callback,
			&callback_data
	);
}

int rrr_mmap_channel_read_with_callback (
		int *read_count,
		struct rrr_mmap_channel *source,
		unsigned int empty_wait_time_us,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
) {
	int ret = RRR_MMAP_CHANNEL_OK;

	*read_count = 0;

	int do_rpos_increment = 1;

	int do_unlock_block = 0;
	int wait_attempts_max = 4;

	struct rrr_mmap_channel_block *block = NULL;

	goto attempt_block_lock;

	attempt_read_wait:
		// We MUST NOT hold index lock and block lock simultaneously.
		if (do_unlock_block) {
			pthread_mutex_unlock(&block->block_lock);
			do_unlock_block = 0;
		}

		if (empty_wait_time_us == 0 || wait_attempts_max-- == 0) {
			pthread_mutex_lock(&source->index_lock);
			source->read_starvation_counter++;
			pthread_mutex_unlock(&source->index_lock);
			ret = RRR_MMAP_CHANNEL_EMPTY;
			goto out_unlock;
		}

		rrr_posix_usleep(empty_wait_time_us);

	attempt_block_lock:
		pthread_mutex_lock(&source->index_lock);

		block = &(source->blocks[source->rpos]);
		int entry_count = source->entry_count;

		pthread_mutex_unlock(&source->index_lock);

		if (entry_count == 0) {
			goto out_unlock;
		}
		if (pthread_mutex_trylock(&block->block_lock) != 0) {
			goto attempt_read_wait;
		}
		do_unlock_block = 1;

	if (block->size_data == 0) {
		goto attempt_read_wait;
	}

	RRR_MMAP_DBG("mmap channel %p %s rd blk %i size %li\n", source, source->name, source->rpos, block->size_data);

	if (block->shmid != 0) {
		const char *data_pointer = NULL;

		if ((data_pointer = shmat(block->shmid, NULL, 0)) == NULL) {
			RRR_MSG_0("Could not get shm pointer in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_unlock;
		}

		if ((ret = callback(data_pointer, block->size_data, callback_arg)) != 0) {
			RRR_MSG_0("Error from callback in __rrr_mmap_channel_read_with_callback\n");
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
			RRR_MSG_0("Error from callback in __rrr_mmap_channel_read_with_callback\n");
			ret = 1;
			do_rpos_increment = 0;
		}
	}

	out_rpos_increment:
	if (do_rpos_increment) {
		*read_count = 1;
		block->size_data = 0;
		pthread_mutex_unlock(&block->block_lock);
		do_unlock_block = 0;

		pthread_mutex_lock(&source->index_lock);
		source->entry_count--;
		source->rpos++;
		if (source->rpos == RRR_MMAP_CHANNEL_SLOTS) {
			source->rpos = 0;
		}
		pthread_mutex_unlock(&source->index_lock);
	}

	out_unlock:
	if (do_unlock_block) {
		pthread_mutex_unlock(&block->block_lock);
	}
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
	if (pthread_mutex_trylock(&target->index_lock) != 0) {
		RRR_MSG_0("Warning: Not destroying index lock of mmap channel %s, it's possibly still being used\n",
				target->name);
	}
	else {
		pthread_mutex_unlock(&target->index_lock);
		pthread_mutex_destroy(&target->index_lock);
	}

	int msg_count = 0;
	for (int i = 0; i != RRR_MMAP_CHANNEL_SLOTS; i++) {
		if (target->blocks[i].ptr_shm_or_mmap != NULL) {
			if (++msg_count == 1) {
				RRR_MSG_1("Note: Pointer was still present in block in rrr_mmap_channel_destroy, fork might not have exited yet or has been killed before cleanup.\n");
			}
		}
		if (pthread_mutex_trylock(&target->blocks[i].block_lock) != 0) {
			RRR_MSG_0("Warning: Not destroying block lock %i of mmap channel %s, it's possibly still being used\n",
					i, target->name);
		}
		else {
			pthread_mutex_unlock(&target->blocks[i].block_lock);
			pthread_mutex_destroy(&target->blocks[i].block_lock);
		}
	}
	if (msg_count > 1) {
		RRR_MSG_1("Note: Last message duplicated %i times\n", msg_count - 1);
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

    if ((result = rrr_mmap_allocate(mmap, sizeof(*result))) == NULL) {
    	RRR_MSG_0("Could not allocate memory in rrr_mmap_channel_new\n");
    	ret = 1;
    	goto out;
    }

	memset(result, '\0', sizeof(*result));

	if ((ret = rrr_posix_mutex_init(&result->index_lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_mmap_channel_new (%i)\n", ret);
		ret = 1;
		goto out_free;
	}

	// Be careful with the counters, we should only destroy initialized locks if we fail
	for (mutex_i = 0; mutex_i != RRR_MMAP_CHANNEL_SLOTS; mutex_i++) {
		if ((ret = rrr_posix_mutex_init(&result->blocks[mutex_i].block_lock, RRR_POSIX_MUTEX_IS_PSHARED)) != 0) {
			RRR_MSG_0("Could not initialize mutex in rrr_mmap_channel_new %i\n", ret);
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
		// Be careful with the counters, we should only destroy initialized locks
		for (mutex_i = mutex_i - 1; mutex_i >= 0; mutex_i--) {
			pthread_mutex_destroy(&result->blocks[mutex_i].block_lock);
		}
		pthread_mutex_destroy(&result->index_lock);
	out_free:
		rrr_mmap_free(mmap, result);
	out:
		return ret;
}

void rrr_mmap_channel_get_counters_and_reset (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		struct rrr_mmap_channel *source
) {
	pthread_mutex_lock(&source->index_lock);

	*read_starvation_counter = source->read_starvation_counter;
	*write_full_counter = source->write_full_counter;

	source->read_starvation_counter = 0;
	source->write_full_counter = 0;

	pthread_mutex_unlock(&source->index_lock);
}
