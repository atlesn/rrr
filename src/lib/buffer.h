/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef VL_BUFFER_H
#define VL_BUFFER_H

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <semaphore.h>

#include "vl_time.h"
#include "../global.h"

//#define FIFO_DEBUG_COUNTER
//#define FIFO_SPIN_DELAY 0 // microseconds
#define FIFO_DEFAULT_RATELIMIT 100 // If this many entries has been inserted without a read, sleep a bit
#define FIFO_MAX_READS 500 // Maximum number of reads per call to a read function

#define FIFO_OK					0
#define FIFO_GLOBAL_ERR			(1<<0)
#define FIFO_CALLBACK_ERR		(1<<1)

#define FIFO_SEARCH_KEEP	0
#define FIFO_SEARCH_STOP	(1<<3)
#define FIFO_SEARCH_GIVE	(1<<4)
#define FIFO_SEARCH_FREE	(1<<5)

#define FIFO_CALLBACK_ARGS \
	struct fifo_callback_args *callback_data, char *data, unsigned long int size

struct fifo_callback_args {
	void *source;
	void *private_data;
	unsigned int flags;
};

struct fifo_buffer_entry {
	char *data;
	unsigned long int size;
	uint64_t order;
	struct fifo_buffer_entry *next;
};

struct fifo_buffer_ratelimit {
	double read_write_balance;
	int prev_entry_count;
	long long int sleep_spin_time;
	uint64_t prev_time;
	int burst_counter;
	long long int spins_per_us;
};

/*
 * Buffer rules:
 * - There may be many readers at the same time
 * - There may only be one writer
 * - Writers need to wait for all reads to complete before obtaining lock
 * - Before locking, writers set the writer_waiting property which prevents new
 *   readers from obtaining read lock thus giving waiting writers priority.
 * - When the invalid property is set, no new readers or writers may work on the
 *   buffer. After all reads and writes have completed, the buffers contents are
 *   deleted.
 * - Writers increment the new_data_available semaphore to inform waiting readers
 *   that data is available. After waiting is completed, regardless of whether a
 *   timeout occurred or not, the readers will check the buffer for new data.
 */

struct fifo_buffer {
	struct fifo_buffer_entry *gptr_first;
	struct fifo_buffer_entry *gptr_last;

	struct fifo_buffer_entry *gptr_write_queue_first;
	struct fifo_buffer_entry *gptr_write_queue_last;

	pthread_mutex_t mutex;
	pthread_mutex_t write_queue_mutex;
	pthread_mutex_t ratelimit_mutex;

	int readers;
	int writers;
	int writer_waiting;
	int readers_waiting;
	int invalid;

	int buffer_do_ratelimit;
	int entry_count;
	int write_queue_entry_count;

	struct fifo_buffer_ratelimit ratelimit;

	void (*free_entry)(void *arg);

	sem_t new_data_available;
};

static inline int fifo_buffer_get_entry_count (struct fifo_buffer *buffer) {
	int ret = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	ret = buffer->entry_count;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	return ret;
}

static inline void fifo_buffer_set_do_ratelimit(struct fifo_buffer *buffer, int set) {
	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->buffer_do_ratelimit = set;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

// TODO : These locking methods are unfair, fix if it matters
static inline void fifo_write_lock(struct fifo_buffer *buffer) {
	int ok = 0;
	while (ok != 2) {
		if (ok == 0) {
			VL_DEBUG_MSG_4("Buffer %p write lock wait for write mutex\n", buffer);
			pthread_mutex_lock(&buffer->mutex);
			VL_DEBUG_MSG_4("Buffer %p write lock wait for writer waiting %i\n", buffer, buffer->writer_waiting);
			if (buffer->writer_waiting == 0) {
				buffer->writer_waiting = 1;
				ok = 1;
			}
			VL_DEBUG_MSG_4("Buffer %p write lock unlock write mutex\n", buffer);
			pthread_mutex_unlock(&buffer->mutex);
		}

		if (ok == 1) {
			pthread_mutex_lock(&buffer->mutex);
			VL_DEBUG_MSG_4("Buffer %p write lock wait for %i readers %i writers\n", buffer, buffer->readers, buffer->writers);
			if (buffer->readers == 0 && buffer->writers == 0) {
				VL_DEBUG_MSG_4("Buffer %p write lock obtained\n", buffer);
				buffer->writers = 1;
				ok = 2;
				pthread_mutex_unlock(&buffer->mutex);
			}
			else {
				pthread_mutex_unlock(&buffer->mutex);
//				usleep(FIFO_SPIN_DELAY);
			}
		}
		else {
//			usleep(FIFO_SPIN_DELAY);
		}
	}

	VL_DEBUG_MSG_4("Buffer %p write lock wait for write mutex end\n", buffer);
	pthread_mutex_lock(&buffer->mutex);
	buffer->writer_waiting = 0;
	VL_DEBUG_MSG_4("Buffer %p write lock unlock write mutex end\n", buffer);
	pthread_mutex_unlock(&buffer->mutex);
}

static inline int fifo_write_trylock(struct fifo_buffer *buffer) {
	int ok = 0;

	pthread_mutex_lock(&buffer->mutex);
	if (buffer->writer_waiting == 0) {
		ok = 1;
	}
	pthread_mutex_unlock(&buffer->mutex);

	if (ok == 0) {
		return 1;
	}

	pthread_mutex_lock(&buffer->mutex);
	if (buffer->readers == 0 && buffer->writers == 0) {
//		VL_DEBUG_MSG_4("Buffer %p write lock obtained\n", buffer);
		VL_DEBUG_MSG_4("Buffer %p write lock obtained in trylock\n", buffer);
		ok = 2;
		buffer->writers = 1;
	}
	pthread_mutex_unlock(&buffer->mutex);

	return (ok == 2 ? 0 : 1);
}

static inline void fifo_write_unlock(struct fifo_buffer *buffer) {
	VL_DEBUG_MSG_4("Buffer %p write unlock\n", buffer);
	pthread_mutex_lock(&buffer->mutex);
	buffer->writers = 0;
	pthread_mutex_unlock(&buffer->mutex);
}

static inline void fifo_read_lock(struct fifo_buffer *buffer) {
	int ok = 0;
	pthread_mutex_lock(&buffer->mutex);
	buffer->readers_waiting++;
	pthread_mutex_unlock(&buffer->mutex);
	while (!ok) {
		VL_DEBUG_MSG_4("Buffer %p read lock wait for mutex\n", buffer);
		pthread_mutex_lock(&buffer->mutex);
		if (buffer->writers == 0 && buffer->writer_waiting == 0) {
			VL_DEBUG_MSG_4("Buffer %p read lock pass 1\n", buffer);
			buffer->readers++;
			ok = 1;
			buffer->readers_waiting--;
			pthread_mutex_unlock(&buffer->mutex);
		}
		else {
			pthread_mutex_unlock(&buffer->mutex);
			//usleep(FIFO_SPIN_DELAY);
		}
	}
}

static inline void fifo_read_unlock(struct fifo_buffer *buffer) {
	VL_DEBUG_MSG_4("Buffer %p read unlock wait for mutex\n", buffer);
	pthread_mutex_lock(&buffer->mutex);
	VL_DEBUG_MSG_4("Buffer %p read unlock\n", buffer);
	buffer->readers--;
	if (buffer->readers < 0) {
		VL_BUG("Readers was <0 in fifo_read_unlock\n");
	}
	pthread_mutex_unlock(&buffer->mutex);
}

static inline int fifo_wait_for_data(struct fifo_buffer *buffer, unsigned int wait_milliseconds) {
	if (wait_milliseconds == 0) {
		return 0;
	}

//	printf ("Waiting for %u milliseconds\n", wait_milliseconds);

	uint64_t time_start = time_get_64();
	uint64_t time_end = time_start + (wait_milliseconds * 1000);

	uint64_t microseconds = time_end % 1000000;
	uint64_t seconds = (time_end - microseconds) / 1000 / 1000;

	struct timespec wait_time;
	wait_time.tv_sec = seconds;
	wait_time.tv_nsec = microseconds * 1000;
	int res = sem_timedwait(&buffer->new_data_available, &wait_time);

/*	uint64_t time_end_real = time_get_64();

	printf ("Waiting time was %" PRIu64 " result was %i\n", (time_end_real - time_start) / 1000, res);*/
/*	if (res != 0) {
		char buf[1024];
		buf[0] = '\0';
		strerror_r(errno, buf, sizeof(buf));
		VL_MSG_ERR("Could wait on semaphore in buffer: %s\n", buf);
		VL_MSG_ERR("Start time was %" PRIu64 " end time was %" PRIu64 "\n", time_start, time_end);
	}
*/
	return res;
}

/*
 * With fifo_read_clear_forward, the callback function MUST
 * handle ALL entries as we cannot add elements back in this
 * case, the callback function may simply write them back
 * using one of the write functions as no locks are active
 * when the callback function is run.
 *
 * For fifo_search the lock is active when the callback function
 * is run, and the callback MUST NOT attempt to write to the same buffer
 * as this causes a deadlock.
 *
 * Callbacks of fifo_search may return these values to control when
 * to stop or when to delete entries (values can be ORed except for
 * the error value). Functions return 0 on success and 1 on error. If
 * the callback of fifo_search returns FIFO_SEARCH_ERR, the search
 * is stopped and fifo_search returns 1.
 *
 * To count elements, a counter may be placed in a custom struct pointed
 * to by the fifo_callback_data struct, and the callback has to do the
 * counting.
 */

int fifo_buffer_clear_with_callback (
		struct fifo_buffer *buffer,
		int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
		struct fifo_callback_args *callback_data
);
int fifo_buffer_clear (
		struct fifo_buffer *buffer
);
int fifo_search (
		struct fifo_buffer *buffer,
		int (*callback)(FIFO_CALLBACK_ARGS),
		struct fifo_callback_args *callback_data,
		unsigned int wait_milliseconds
);
int fifo_read_minimum (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		int (*callback)(FIFO_CALLBACK_ARGS),
		struct fifo_callback_args *callback_data,
		uint64_t minimum_order,
		unsigned int wait_milliseconds
);
int fifo_clear_order_lt (
		struct fifo_buffer *buffer,
		uint64_t order_min
);
int fifo_read_clear_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		int (*callback)(FIFO_CALLBACK_ARGS),
		struct fifo_callback_args *callback_data,
		unsigned int wait_milliseconds
);
int fifo_read (
		struct fifo_buffer *buffer,
		int (*callback)(FIFO_CALLBACK_ARGS),
		struct fifo_callback_args *callback_data,
		unsigned int wait_milliseconds
);

//void fifo_read(struct fifo_buffer *buffer, void (*callback)(char *data, unsigned long int size)); Not needed, dupes fifo_search
void fifo_buffer_write(struct fifo_buffer *buffer, char *data, unsigned long int size);
void fifo_buffer_delayed_write (struct fifo_buffer *buffer, char *data, unsigned long int size);
void fifo_buffer_write_ordered(struct fifo_buffer *buffer, uint64_t order, char *data, unsigned long int size);

void fifo_buffer_invalidate_with_callback (
		struct fifo_buffer *buffer,
		int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
		struct fifo_callback_args *callback_data
);
void fifo_buffer_invalidate(struct fifo_buffer *buffer);
// void fifo_buffer_destroy(struct fifo_buffer *buffer); Not thread safe
int fifo_buffer_init(struct fifo_buffer *buffer);
int fifo_buffer_init_custom_free(struct fifo_buffer *buffer, void (*custom_free)(void *arg));

#endif
