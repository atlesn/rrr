/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_BUFFER_PROTECTED_H
#define RRR_BUFFER_PROTECTED_H

#include <pthread.h>
#include <inttypes.h>

#define RRR_FIFO_PROTECTED_DEFAULT_RATELIMIT 100 // If this many entries has been inserted without a read, sleep a bit
#define RRR_FIFO_PROTECTED_MAX_READS 500 // Maximum number of reads per call to a read function

#define RRR_FIFO_PROTECTED_OK             0
#define RRR_FIFO_PROTECTED_GLOBAL_ERR     (1<<0)
#define RRR_FIFO_PROTECTED_CALLBACK_ERR   (1<<1)

#define RRR_FIFO_PROTECTED_SEARCH_STOP    (1<<3)
#define RRR_FIFO_PROTECTED_SEARCH_FREE    (1<<5)

#define RRR_FIFO_PROTECTED_WRITE_AGAIN    (1<<10)
#define RRR_FIFO_PROTECTED_WRITE_DROP     (1<<11)
#define RRR_FIFO_PROTECTED_WRITE_ORDERED  (1<<12)

#define RRR_FIFO_PROTECTED_READ_CALLBACK_ARGS \
	void *arg, char *data, unsigned long int size

#define RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS \
	char **data, unsigned long int *size, uint64_t *order, void *arg

/*
void {
	void *source;
	void *private_data;
	unsigned int flags;
};
*/

struct rrr_fifo_protected_entry {
	char *data;
	unsigned long int size;
	uint64_t order;
	struct rrr_fifo_protected_entry *next;
	pthread_mutex_t lock;
};

struct rrr_fifo_protected_ratelimit {
	double read_write_balance;
	unsigned int prev_entry_count;
	unsigned int burst_counter;
	long long int sleep_spin_time;
	long long int spins_per_us;
	uint64_t prev_time;
};

struct rrr_fifo_protected_stats {
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
 */

struct rrr_fifo_protected {
	struct rrr_fifo_protected_entry *gptr_first;
	struct rrr_fifo_protected_entry *gptr_last;

	struct rrr_fifo_protected_entry *gptr_write_queue_first;
	struct rrr_fifo_protected_entry *gptr_write_queue_last;

	pthread_rwlock_t rwlock;
	pthread_mutex_t write_queue_mutex;
	pthread_mutex_t ratelimit_mutex;
	pthread_mutex_t stats_mutex;

	int buffer_do_ratelimit;
	unsigned int entry_count;
	unsigned int write_queue_entry_count;

	struct rrr_fifo_protected_ratelimit ratelimit;
	struct rrr_fifo_protected_stats stats;

	void (*free_callback)(void *arg);
};
void rrr_fifo_protected_get_stats_populate (
		struct rrr_fifo_protected_stats *target,
		uint64_t entries_written,
		uint64_t entries_deleted
);
int rrr_fifo_protected_get_stats ( ////
		struct rrr_fifo_protected_stats *stats,
		struct rrr_fifo_protected *buffer
);
void rrr_fifo_protected_destroy ( ////
		struct rrr_fifo_protected *buffer
);
int rrr_fifo_protected_init (
		struct rrr_fifo_protected *buffer,
		void (*free_callback)(void *arg)
);
void rrr_fifo_protected_set_do_ratelimit (
		struct rrr_fifo_protected *buffer,
		int set
);
unsigned int rrr_fifo_protected_get_entry_count (
		struct rrr_fifo_protected *buffer
);
int rrr_fifo_protected_get_entry_count_combined (
		struct rrr_fifo_protected *buffer
);
int rrr_fifo_protected_get_ratelimit_active (
		struct rrr_fifo_protected *buffer
);

/*
 * With fifo_read_clear_forward, the callback function MUST
 * handle ALL entries as we cannot add elements back in this
 * case, the callback function may simply write them back
 * using one of the write functions as no locks are active
 * when the callback function is run.
 *
 * To count elements, a counter may be placed in a custom struct pointed
 * to by the fifo_callback_data struct, and the callback has to do the
 * counting.
 */

int rrr_fifo_protected_read_clear_forward (
		struct rrr_fifo_protected *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
);
int rrr_fifo_protected_with_write_lock_do (
		struct rrr_fifo_protected *buffer,
		int (*callback)(void *arg1, void *arg2),
		void *callback_arg1,
		void *callback_arg2
);
int rrr_fifo_protected_write (
		struct rrr_fifo_protected *buffer,
		int (*callback)(RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS),
		void *callback_arg
);
int rrr_fifo_protected_write_delayed (
		struct rrr_fifo_protected *buffer,
		int (*callback)(RRR_FIFO_PROTECTED_WRITE_CALLBACK_ARGS),
		void *callback_arg
);

#endif
