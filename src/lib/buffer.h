/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_BUFFER_H
#define RRR_BUFFER_H

#include <pthread.h>
#include <inttypes.h>
#include <semaphore.h>

//#define FIFO_DEBUG_COUNTER
//#define FIFO_SPIN_DELAY 0 // microseconds
#define RRR_FIFO_DEFAULT_RATELIMIT 100 // If this many entries has been inserted without a read, sleep a bit
#define RRR_FIFO_MAX_READS 500 // Maximum number of reads per call to a read function

#define RRR_FIFO_OK					0
#define RRR_FIFO_GLOBAL_ERR			(1<<0)
#define RRR_FIFO_CALLBACK_ERR		(1<<1)

#define RRR_FIFO_SEARCH_KEEP	0
#define RRR_FIFO_SEARCH_STOP	(1<<3)
#define RRR_FIFO_SEARCH_GIVE	(1<<4)
#define RRR_FIFO_SEARCH_FREE	(1<<5)
#define RRR_FIFO_SEARCH_REPLACE	(1<<6)

#define RRR_FIFO_WRITE_AGAIN	(1<<10)
#define RRR_FIFO_WRITE_DROP		(1<<11)
#define RRR_FIFO_WRITE_ORDERED	(1<<12)

#define RRR_FIFO_READ_CALLBACK_ARGS \
	void *arg, char *data, unsigned long int size

#define RRR_FIFO_WRITE_CALLBACK_ARGS \
	char **data, unsigned long int *size, uint64_t *order, void *arg

/*
void {
	void *source;
	void *private_data;
	unsigned int flags;
};
*/

struct rrr_fifo_buffer_entry {
	char *data;
	unsigned long int size;
	uint64_t order;
	struct rrr_fifo_buffer_entry *next;
	pthread_mutex_t lock;
};

struct rrr_fifo_buffer_ratelimit {
	double read_write_balance;
	int prev_entry_count;
	long long int sleep_spin_time;
	uint64_t prev_time;
	int burst_counter;
	long long int spins_per_us;
};

struct rrr_fifo_buffer_stats {
	uint64_t total_entries_written;
	uint64_t total_entries_deleted;
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

struct rrr_fifo_buffer {
	struct rrr_fifo_buffer_entry *gptr_first;
	struct rrr_fifo_buffer_entry *gptr_last;

	struct rrr_fifo_buffer_entry *gptr_write_queue_first;
	struct rrr_fifo_buffer_entry *gptr_write_queue_last;

	pthread_rwlock_t rwlock;
	pthread_mutex_t write_queue_mutex;
	pthread_mutex_t ratelimit_mutex;
	pthread_mutex_t stats_mutex;

	int buffer_do_ratelimit;
	int entry_count;
	int write_queue_entry_count;

	struct rrr_fifo_buffer_ratelimit ratelimit;
	struct rrr_fifo_buffer_stats stats;

	void (*free_entry)(void *arg);

	sem_t new_data_available;
};
void rrr_fifo_buffer_get_stats_populate (
		struct rrr_fifo_buffer_stats *target,
		uint64_t entries_written,
		uint64_t entries_deleted
);
int rrr_fifo_buffer_get_stats (
		struct rrr_fifo_buffer_stats *stats,
		struct rrr_fifo_buffer *buffer
);
void rrr_fifo_buffer_destroy (
		struct rrr_fifo_buffer *buffer
);
int rrr_fifo_buffer_init (
		struct rrr_fifo_buffer *buffer
);
void rrr_fifo_buffer_full_limit_set (
		struct rrr_fifo_buffer *buffer,
		int limit
);
int rrr_fifo_buffer_init_custom_free (
		struct rrr_fifo_buffer *buffer,
		void (*custom_free)(void *arg)
);
void rrr_fifo_buffer_set_do_ratelimit (
		struct rrr_fifo_buffer *buffer,
		int set
);

static inline int rrr_fifo_buffer_get_entry_count (
		struct rrr_fifo_buffer *buffer
) {
	int ret = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	ret = buffer->entry_count;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	return ret;
}

static inline int rrr_fifo_buffer_get_ratelimit_active (
		struct rrr_fifo_buffer *buffer
) {
	int ret = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	ret = buffer->buffer_do_ratelimit;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	return ret;
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

void rrr_fifo_buffer_clear_with_callback (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
);
void rrr_fifo_buffer_clear (
		struct rrr_fifo_buffer *buffer
);
int rrr_fifo_buffer_search_return_value_process (
		unsigned char *do_keep,
		unsigned char *do_give,
		unsigned char *do_free,
		unsigned char *do_stop,
		int actions
);
int rrr_fifo_buffer_search (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		unsigned int wait_milliseconds
);
int rrr_fifo_buffer_search_and_replace (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg,
		unsigned int wait_milliseconds,
		int call_again_after_looping
);
int rrr_fifo_buffer_read_clear_forward (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		unsigned int wait_milliseconds
);
int rrr_fifo_buffer_read (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(RRR_FIFO_READ_CALLBACK_ARGS),
		void *callback_data,
		unsigned int wait_milliseconds
);
int rrr_fifo_buffer_read_minimum (
		struct rrr_fifo_buffer *buffer,
		struct rrr_fifo_buffer_entry *last_element,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		uint64_t minimum_order,
		unsigned int wait_milliseconds
);
int rrr_fifo_buffer_with_write_lock_do (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *arg1, void *arg2),
		void *callback_arg1,
		void *callback_arg2
);
int rrr_fifo_buffer_write (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg
);
int rrr_fifo_buffer_write_delayed (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg
);

#endif
