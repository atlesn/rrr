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

#ifndef RRR_MMAP_CHANNEL_H
#define RRR_MMAP_CHANNEL_H

#include <pthread.h>
#include <sys/types.h>

#include "log.h"
#include "read_constants.h"

#define RRR_MMAP_CHANNEL_SLOTS 1024

#define RRR_MMAP_CHANNEL_OK               RRR_READ_OK
#define RRR_MMAP_CHANNEL_ERROR           RRR_READ_HARD_ERROR
#define RRR_MMAP_CHANNEL_FULL_OR_EMPTY   RRR_READ_SOFT_ERROR
#define RRR_MMAP_CHANNEL_FULL            RRR_READ_SOFT_ERROR
#define RRR_MMAP_CHANNEL_EMPTY           RRR_READ_SOFT_ERROR

// These are used to filter out debug messages generated
// by the mmap channel as they  are attempted to be sent on
// the same channel (causes recursion attempt and error message)
#define RRR_MMAP_DEBUGLEVEL   __RRR_LOG_PREFIX_4
#define RRR_MMAP_DBG(...)    RRR_DBG_4(__VA_ARGS__)

struct rrr_mmap;
struct rrr_mmap_channel;
struct rrr_event_queue;

int rrr_mmap_channel_count (
		struct rrr_mmap_channel *target
);
int rrr_mmap_channel_write_using_callback (
		struct rrr_mmap_channel *target,
		struct rrr_event_queue *queue_notify,
		size_t data_size,
		int wait_attempts_max,
		unsigned int full_wait_time_us,
		int (*callback)(void *target, void *arg),
		void *callback_arg,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_mmap_channel_write (
		struct rrr_mmap_channel *target,
		struct rrr_event_queue *queue_notify,
		const void *data,
		size_t data_size,
		unsigned int full_wait_time_us,
		int retries_max,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_mmap_channel_read_with_callback (
		int *read_count,
		struct rrr_mmap_channel *source,
		int (*callback)(const void *data, size_t data_size, void *arg),
		void *callback_arg
);
void rrr_mmap_channel_bubblesort_pointers (
		struct rrr_mmap_channel *target,
		int *was_sorted
);
void rrr_mmap_channel_destroy (
		struct rrr_mmap_channel *target
);
void rrr_mmap_channel_writer_free_blocks (
		struct rrr_mmap_channel *target
);
int rrr_mmap_channel_new (
		struct rrr_mmap_channel **target,
		struct rrr_mmap *mmap,
		const char *name
);
void rrr_mmap_channel_get_counters_and_reset (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		struct rrr_mmap_channel *source
);

#endif /* RRR_MMAP_CHANNEL_H */
