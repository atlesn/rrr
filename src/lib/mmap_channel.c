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
#include "../global.h"
#include "mmap_channel.h"
#include "rrr_mmap.h"

// Messages larger than this limit are transferred using SHM
#define RRR_MMAP_CHANNEL_SHM_LIMIT 100

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
		struct rrr_mmap_channel_block *block,
		int block_pos
) {
	if (block->is_shm != 0) {
		if (block->ptr_shm_or_mmap == NULL) {
			// Attempt to recover from previously failed allocation
			int key = 0;
			if ((key = ftok(target->tmpfile, block_pos)) <= 0) {
				RRR_MSG_ERR("ftok failed in __rrr_mmap_channel_allocate for file %s: %s\n", target->tmpfile, rrr_strerror(errno));
				return 1;
			}

			int shmid = shmget(key, block->size_capacity, 0600);
			if (shmid <= 0) {
				RRR_MSG_ERR("Error from shmget in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
				return 1;
			}

			struct shmid_ds ds;
			if (shmctl(shmid, IPC_STAT, &ds) != shmid) {
				RRR_MSG_ERR("Warning: shmctl IPC_STAT failed in __rrr_mmap_channel_block_free: %s\n", rrr_strerror(errno));
			}
			else {
				if (ds.shm_nattch > 0) {
					RRR_BUG("Dangling shared memory key in __rrr_mmap_channel_block_free, cannot continue\n");
				}

				if (shmctl(shmid, IPC_RMID, NULL) != 0) {
					RRR_MSG_ERR("shmctl IPC_RMID failed in __rrr_mmap_channel_block_free: %s\n", rrr_strerror(errno));
					return 1;
				}
			}
		}
		else if (shmdt(block->ptr_shm_or_mmap) != 0) {
			RRR_MSG_ERR("shmdt failed in rrr_mmap_channel_write_using_callback: %s\n", rrr_strerror(errno));
			return 1;
		}

		block->is_shm = 0;
		block->ptr_shm_or_mmap = 0;
	}
	else if (block->ptr_shm_or_mmap != NULL) {
		rrr_mmap_free(target->mmap, block->ptr_shm_or_mmap);
	}

	block->ptr_shm_or_mmap = NULL;
	block->size_data = 0;
	block->size_capacity = 0;
	block->is_shm = 0;

	return 0;
}

static int __rrr_mmap_channel_allocate (
		struct rrr_mmap_channel *target,
		struct rrr_mmap_channel_block *block,
		size_t data_size,
		int block_pos
) {
	int ret = 0;

	if (block->size_capacity >= data_size) {
		goto out;
	}
	if ((ret = __rrr_mmap_channel_block_free(target, block, block_pos)) != 0) {
		goto out;
	}

	if (data_size > RRR_MMAP_CHANNEL_SHM_LIMIT) {
		key_t new_key;

		int shmid = 0;
		do {
			if ((new_key = ftok(target->tmpfile, block_pos)) <= 0) {
				RRR_MSG_ERR("ftok failed in __rrr_mmap_channel_allocate for file %s: %s\n", target->tmpfile, rrr_strerror(errno));
				ret = 1;
				goto out;
			}

			printf("allocate shmget key %i file %s pos %i\n", new_key, target->tmpfile, block_pos);
			if ((shmid = shmget(new_key, data_size, IPC_CREAT|IPC_EXCL|0600)) <= 0) {
				if (errno == EEXIST) {
					// OK, try another key
				}
				else {
					RRR_MSG_ERR("Error from shmget in __rrr_mmap_channel_allocate: %s\n", rrr_strerror(errno));
					ret = 1;
					goto out;
				}
			}
		} while (shmid <= 0);

		block->is_shm = 1;
		block->size_capacity = data_size;

		if ((block->ptr_shm_or_mmap = shmat(shmid, NULL, 0)) == NULL) {
			RRR_MSG_ERR("shmat failed in __rrr_mmap_channel_allocate: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		if (shmctl(shmid, IPC_RMID, NULL) != 0) {
			RRR_MSG_ERR("shmctl IPC_RMID failed in __rrr_mmap_channel_allocate: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out;
		}
	}
	else {
		if ((block->ptr_shm_or_mmap = rrr_mmap_allocate(target->mmap, data_size)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory in __rrr_mmap_channel_allocate \n");
			ret = 1;
			goto out;
		}
		block->size_capacity = data_size;
		block->is_shm = 0;
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
	pthread_mutex_lock(&target->index_lock);

	struct rrr_mmap_channel_block *block = &(target->blocks[target->wpos]);

	// When the other end is done with the data, it sets size to 0
	if (block->size_data != 0) {
		ret = RRR_MMAP_CHANNEL_FULL;
		goto out_unlock;
	}

	if (__rrr_mmap_channel_allocate(target, block, data_size, target->wpos) != 0) {
		RRR_MSG_ERR("Could not allocate memory in rrr_mmap_channel_write\n");
		ret = 1;
		goto out_unlock;
	}

	if (callback(block->ptr_shm_or_mmap, callback_arg) != 0) {
		RRR_MSG_ERR("Error from callback in rrr_mmap_channel_write_using_callback\n");
		ret = 1;
		goto out_unlock;
	}

	block->size_data = data_size;

//	printf ("mmap channel write to %p size %li\n", block->ptr, data_size);

	target->wpos++;
	if (target->wpos == RRR_MMAP_CHANNEL_SLOTS) {
		target->wpos = 0;
	}

	out_unlock:
	pthread_mutex_unlock(&target->index_lock);
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

	pthread_mutex_lock(&source->index_lock);

	struct rrr_mmap_channel_block *block = &(source->blocks[source->rpos]);

	pthread_mutex_lock(&block->block_lock);

	if (block->size_data == 0) {
		ret = RRR_MMAP_CHANNEL_EMPTY;
		goto out_unlock;
	}

	if (block->is_shm != 0) {
		const char *data_pointer = NULL;

		int key = 0;
		if ((key = ftok(source->tmpfile, source->rpos)) <= 0) {
			RRR_MSG_ERR("ftok failed in rrr_mmap_channel_read_with_callback for file %s: %s\n", source->tmpfile, rrr_strerror(errno));
			return 1;
		}

		int shmid = shmget(key, block->size_capacity, 0);
		printf("read shmget key %i file %s pos %i\n", key, source->tmpfile, source->rpos);
		if (shmid <= 0) {
			RRR_MSG_ERR("Error from shmget in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_unlock;
		}

		if ((data_pointer = shmat(shmid, NULL, 0)) == NULL) {
			RRR_MSG_ERR("Could not get shm pointer in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_unlock;
		}

		pthread_mutex_unlock(&source->index_lock);
		if ((ret = callback(data_pointer, block->size_data, callback_arg)) != 0) {
			RRR_MSG_ERR("Error from callback in rrr_mmap_channel_read_with_callback\n");
			ret = 1;
			do_rpos_increment = 0;
		}
		pthread_mutex_lock(&source->index_lock);

		if (shmdt(data_pointer) != 0) {
			RRR_MSG_ERR("shmdt failed in rrr_mmap_channel_read_with_callback: %s\n", rrr_strerror(errno));
			ret = 1;
			goto out_rpos_increment;
		}
	}
	else {
		pthread_mutex_unlock(&source->index_lock);
		if ((ret = callback(block->ptr_shm_or_mmap, block->size_data, callback_arg)) != 0) {
			RRR_MSG_ERR("Error from callback in rrr_mmap_channel_read_with_callback\n");
			ret = 1;
			do_rpos_increment = 0;
		}
		pthread_mutex_lock(&source->index_lock);
	}

	out_rpos_increment:
	if (do_rpos_increment) {
		block->size_data = 0;

		source->rpos++;
		if (source->rpos == RRR_MMAP_CHANNEL_SLOTS) {
			source->rpos = 0;
		}
	}

//	printf ("mmap channel read from mmap %p to local %p size_data %lu\n", block->ptr, result, *target_size);

	out_unlock:
	pthread_mutex_unlock(&block->block_lock);
	pthread_mutex_unlock(&source->index_lock);
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

void rrr_mmap_channel_destroy (struct rrr_mmap_channel *target) {
	pthread_mutex_destroy(&target->index_lock);
	for (int i = 0; i != RRR_MMAP_CHANNEL_SLOTS; i++) {
		if (target->blocks[i].ptr_shm_or_mmap != NULL) {
			RRR_MSG_ERR("Warning: Pointer was still present in block in rrr_mmap_channel_destroy\n");
		}
		pthread_mutex_destroy(&target->blocks[i].block_lock);
	}
	rrr_mmap_free(target->mmap, target);
	if (target->tmp_fd != 0) {
		close(target->tmp_fd);
	}
	if (target->tmpfile != NULL && *(target->tmpfile) != '\0') {
		unlink(target->tmpfile);
	}
	RRR_FREE_IF_NOT_NULL(target->tmpfile);
}

void rrr_mmap_channel_writer_free_blocks (struct rrr_mmap_channel *target) {
	pthread_mutex_lock(&target->index_lock);

	for (int i = 0; i != RRR_MMAP_CHANNEL_SLOTS; i++) {
		pthread_mutex_lock(&target->blocks[i].block_lock);
		__rrr_mmap_channel_block_free(target, &target->blocks[i], i);
		pthread_mutex_unlock(&target->blocks[i].block_lock);
	}

	target->wpos = 0;
	target->rpos = 0;

	pthread_mutex_unlock(&target->index_lock);
}

int rrr_mmap_channel_new (struct rrr_mmap_channel **target, struct rrr_mmap *mmap) {
	int ret = 0;

	struct rrr_mmap_channel *result = NULL;

	int mutex_i = 0;
	pthread_mutexattr_t attr;
	char template[128];

	if ((ret = pthread_mutexattr_init(&attr)) != 0) {
		RRR_MSG_ERR("Could not initialize mutexattr inrrr_mmap_channel_new (%i)\n", ret);
		ret = 1;
		goto out;
	}

    if ((result = rrr_mmap_allocate(mmap, sizeof(*result))) == NULL) {
    	RRR_MSG_ERR("Could not allocate memory in rrr_mmap_channel_new\n");
    	ret = 1;
    	goto out_destroy_mutexattr;
    }

	memset(result, '\0', sizeof(*result));

	sprintf(template, RRR_TMP_PATH "/rrr-perl5-shmem-XXXXXX");

	int tmp_fd = 0;
	if ((tmp_fd = mkstemp(template)) < 0) {
		RRR_MSG_ERR("Could not create temporary file %s in rrr_mmap_channel_new: %s\n",
		template, rrr_strerror(errno));
		ret = 1;
		goto out_free;
	}

	result->tmp_fd = tmp_fd;

	if ((result->tmpfile = strdup(template)) == NULL) {
		RRR_MSG_ERR("Could not allocate memory for tmpfile name in rrr_mmap_channel_new\n");
		ret = 1;
		goto out_close_unlink;
	}

	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

	if ((ret = pthread_mutex_init(&result->index_lock, &attr)) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in rrr_mmap_new (%i)\n", ret);
		ret = 1;
		goto out_free_tmpfile;
	}

	for (mutex_i = 0; mutex_i != RRR_MMAP_CHANNEL_SLOTS; mutex_i++) {
		if ((ret = pthread_mutex_init(&result->blocks[mutex_i].block_lock, &attr)) != 0) {
			RRR_MSG_ERR("Could not initialize mutex in rrr_mmap_new %i\n", ret);
			ret = 1;
			goto out_destroy_mutexes;
		}
	}

	result->mmap = mmap;

	*target = result;
	result = NULL;

	goto out;

	out_destroy_mutexes:
		for (mutex_i = mutex_i - 1; mutex_i >= 0; mutex_i--) {
			pthread_mutex_destroy(&result->blocks[mutex_i].block_lock);
		}
		pthread_mutex_destroy(&result->index_lock);
	out_free_tmpfile:
		free(result->tmpfile);
	out_close_unlink:
		close(result->tmp_fd);
		unlink(template); // Use the variable on the stack memory here
	out_free:
		rrr_mmap_free(mmap, result);
	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&attr);
	out:
		return ret;
}
