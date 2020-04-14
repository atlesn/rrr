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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../global.h"
#include "mmap_channel.h"
#include "rrr_mmap.h"

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

int rrr_mmap_channel_write_using_callback (
		struct rrr_mmap_channel *target,
		size_t data_size,
		int (*callback)(void *target, void *arg),
		void *callback_arg
) {
	int ret = RRR_MMAP_CHANNEL_OK;
	pthread_mutex_lock(&target->index_lock);

	struct rrr_mmap_channel_block *block = &(target->blocks[target->wpos]);

	if (block->size_data != 0) {
		ret = RRR_MMAP_CHANNEL_FULL;
		goto out_unlock;
	}

	if (block->size_capacity < data_size) {
		if (block->size_capacity > 0) {
			rrr_mmap_free(target->mmap, block->ptr);
		}
		if ((block->ptr = rrr_mmap_allocate(target->mmap, data_size)) == NULL) {
			RRR_MSG_ERR("Could not allocate memory in rrr_mmap_channel_write\n");
			ret = 1;
			goto out_unlock;
		}
		block->size_capacity = data_size;
	}

	if (callback(block->ptr, callback_arg) != 0) {
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

int rrr_mmap_channel_read (
		void **target,
		size_t *target_size,
		struct rrr_mmap_channel *source
) {
	int ret = RRR_MMAP_CHANNEL_OK;

	void *result = NULL;

	*target = NULL;
	*target_size = 0;

	pthread_mutex_lock(&source->index_lock);

	struct rrr_mmap_channel_block *block = &(source->blocks[source->rpos]);

	if (block->size_data == 0) {
		ret = RRR_MMAP_CHANNEL_EMPTY;
		goto out_unlock;
	}

	if ((result = malloc(block->size_data)) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_mmap_channel_read\n");
		ret = RRR_MMAP_CHANNEL_ERROR;
		goto out_unlock;
	}

	memcpy(result, block->ptr, block->size_data);

	*target = result;
	*target_size = block->size_data;

	block->size_data = 0;

	source->rpos++;
	if (source->rpos == RRR_MMAP_CHANNEL_SLOTS) {
		source->rpos = 0;
	}

//	printf ("mmap channel read from mmap %p to local %p size_data %lu\n", block->ptr, result, *target_size);

	out_unlock:
	pthread_mutex_unlock(&source->index_lock);
	return ret;
}

int rrr_mmap_channel_read_all (
		struct rrr_mmap_channel *source,
		int (*callback)(void *data, size_t data_size, void *arg),
		void *callback_arg
) {
	int ret = 0;

	do {
		void *ptr;
		size_t size;
		if ((ret = rrr_mmap_channel_read(&ptr, &size, source)) == 0) {
			if ((ret = callback(ptr, size, callback_arg)) != 0) {
				RRR_MSG_ERR("Error from callback in rrr_mmap_channel_read_all\n");
			}
		}
		else if (ret == RRR_MMAP_CHANNEL_EMPTY) {
			ret = 0;
			break;
		}
	} while(ret == 0);

	return ret;
}

void rrr_mmap_channel_destroy (struct rrr_mmap_channel *target) {
	for (int i = 0; i < RRR_MMAP_CHANNEL_SLOTS; i++) {
		if (target->blocks[i].ptr != NULL) {
			rrr_mmap_free(target->mmap, target->blocks[i].ptr);
		}
	}
	pthread_mutex_destroy(&target->index_lock);
	rrr_mmap_free(target->mmap, target);
}

int rrr_mmap_channel_new (struct rrr_mmap_channel **target, struct rrr_mmap *mmap) {
	int ret = 0;

	struct rrr_mmap_channel *result = NULL;

    pthread_mutexattr_t attr;
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

    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if ((ret = pthread_mutex_init(&result->index_lock, &attr)) != 0) {
    	RRR_MSG_ERR("Could not initialize mutex in rrr_mmap_new (%i)\n", ret);
    	ret = 1;
    	goto out_free;
    }

    result->mmap = mmap;

    *target = result;
    result = NULL;

    goto out;

    out_free:
		rrr_mmap_free(mmap, result);
    out_destroy_mutexattr:
		pthread_mutexattr_destroy(&attr);
    out:
		return ret;
}
