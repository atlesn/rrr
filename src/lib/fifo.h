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

#ifndef RRR_FIFO_H
#define RRR_FIFO_H

#include <inttypes.h>

#include "fifo_common.h"
#include "rrr_types.h"

#define RRR_FIFO_DEFAULT_RATELIMIT 100 // If this many entries has been inserted without a read, sleep a bit
#define RRR_FIFO_MAX_READS 500 // Maximum number of reads per call to a read function

#define RRR_FIFO_OK             RRR_FIFO_COMMON_OK
#define RRR_FIFO_GLOBAL_ERR     RRR_FIFO_COMMON_GLOBAL_ERR
#define RRR_FIFO_CALLBACK_ERR   RRR_FIFO_COMMON_CALLBACK_ERR

#define RRR_FIFO_SEARCH_KEEP    RRR_FIFO_COMMON_SEARCH_KEEP
#define RRR_FIFO_SEARCH_STOP    RRR_FIFO_COMMON_SEARCH_STOP
#define RRR_FIFO_SEARCH_GIVE    RRR_FIFO_COMMON_SEARCH_GIVE
#define RRR_FIFO_SEARCH_FREE    RRR_FIFO_COMMON_SEARCH_FREE
#define RRR_FIFO_SEARCH_REPLACE RRR_FIFO_COMMON_SEARCH_REPLACE

#define RRR_FIFO_WRITE_AGAIN    RRR_FIFO_COMMON_WRITE_AGAIN
#define RRR_FIFO_WRITE_DROP     RRR_FIFO_COMMON_WRITE_DROP
#define RRR_FIFO_WRITE_ORDERED  RRR_FIFO_COMMON_WRITE_ORDERED

#define RRR_FIFO_CLEAR_CALLBACK_ARGS  void *callback_data, char **data, unsigned long int size

#define RRR_FIFO_READ_CALLBACK_ARGS   RRR_FIFO_COMMON_READ_CALLBACK_ARGS
#define RRR_FIFO_READ_CALLBACK_ARGS   RRR_FIFO_COMMON_READ_CALLBACK_ARGS
#define RRR_FIFO_WRITE_CALLBACK_ARGS  RRR_FIFO_COMMON_WRITE_CALLBACK_ARGS

struct rrr_fifo_entry {
	char *data;
	unsigned long int size;
	uint64_t order;
	struct rrr_fifo_entry *next;
};

struct rrr_fifo {
	struct rrr_fifo_entry *gptr_first;
	struct rrr_fifo_entry *gptr_last;

	rrr_length entry_count;

	void (*free_entry)(void *arg);
};

void rrr_fifo_destroy (
		struct rrr_fifo *buffer
);
int rrr_fifo_init (
		struct rrr_fifo *buffer
);
int rrr_fifo_init_custom_free (
		struct rrr_fifo *buffer,
		void (*custom_free)(void *arg)
);

static inline rrr_length rrr_fifo_get_entry_count (
		struct rrr_fifo *buffer
) {
	return buffer->entry_count;
}

void rrr_fifo_clear_with_callback (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_CLEAR_CALLBACK_ARGS),
		void *callback_data
);
void rrr_fifo_clear (
		struct rrr_fifo *buffer
);
int rrr_fifo_search (
		struct rrr_fifo *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
);
int rrr_fifo_search_and_replace (
		struct rrr_fifo *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg,
		int call_again_after_looping
);
int rrr_fifo_read_clear_forward_all (
		struct rrr_fifo *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
);
int rrr_fifo_read (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_READ_CALLBACK_ARGS),
		void *callback_data
);
int rrr_fifo_read_minimum (
		struct rrr_fifo *buffer,
		struct rrr_fifo_entry *last_element,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		uint64_t minimum_order
);
int rrr_fifo_write (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg
);

#endif
