/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

struct fifo_buffer_entry {
	char *data;
	unsigned long int size;
	uint64_t order;
	struct fifo_buffer_entry *next;
};

struct fifo_buffer {
	struct fifo_buffer_entry *gptr_first;
	struct fifo_buffer_entry *gptr_last;
	pthread_mutex_t mutex;
	int readers;
	int writers;
	int invalid;
};

static inline void fifo_write_lock(struct fifo_buffer *buffer) {
	int ok = 0;
	while (ok != 3) {
		pthread_mutex_lock(&buffer->mutex);
		if (buffer->writers == 0) {
			ok = 1;
		}
		if (ok == 1) {
			buffer->writers = 1;
			ok = 2;
		}
		if (ok == 2) {
			if (buffer->readers == 0) {
				ok = 3;
			}
		}
		pthread_mutex_unlock(&buffer->mutex);
	}
}

static inline void fifo_write_unlock(struct fifo_buffer *buffer) {
	pthread_mutex_lock(&buffer->mutex);
	buffer->writers = 0;
	pthread_mutex_unlock(&buffer->mutex);
}

static inline void fifo_read_to_write_lock(struct fifo_buffer *buffer) {
	int ok = 0;
	while (ok != 3) {
		pthread_mutex_lock(&buffer->mutex);

		buffer->readers--;

		if (buffer->writers == 0) {
			ok = 1;
		}
		if (ok == 1) {
			buffer->writers = 1;
			ok = 2;
		}
		if (ok == 2) {
			if (buffer->readers == 0) {
				ok = 3;
			}
		}
		pthread_mutex_unlock(&buffer->mutex);
	}
}

static inline void fifo_read_lock(struct fifo_buffer *buffer) {
	int ok = 0;
	while (!ok) {
		pthread_mutex_lock(&buffer->mutex);
		if (buffer->writers == 0) {
			buffer->readers++;
			ok = 1;
		}
		pthread_mutex_unlock(&buffer->mutex);
	}
}

static inline void fifo_read_unlock(struct fifo_buffer *buffer) {
	pthread_mutex_lock(&buffer->mutex);
	buffer->readers--;
	pthread_mutex_unlock(&buffer->mutex);
}

int fifo_clear_order_lt (
		struct fifo_buffer *buffer,
		uint64_t order_min
);
int fifo_read_clear_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		void (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
);
int fifo_read_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		void (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
);

void fifo_read(struct fifo_buffer *buffer, void (*callback)(char *data, unsigned long int size));
void fifo_buffer_write(struct fifo_buffer *buffer, char *data, unsigned long int size);
void fifo_buffer_write_ordered(struct fifo_buffer *buffer, uint64_t order, char *data, unsigned long int size);

void fifo_buffer_invalidate(struct fifo_buffer *buffer);
void fifo_buffer_destroy(struct fifo_buffer *buffer);
void fifo_buffer_init(struct fifo_buffer *buffer);

#endif
