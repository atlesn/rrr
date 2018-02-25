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

struct fifo_buffer_entry {
	char *data;
	unsigned long int size;
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

/*
 * This reading method holds a write lock for a minum amount of time by
 * taking control of the start of the queue making it inaccessible to
 * others.
 */
//static inline int fifo_read_clear_forward (
static int __attribute__ ((noinline))  fifo_read_clear_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		void (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
) {
	int ret = 0;
	fifo_write_lock(buffer);
	if (buffer->invalid) {
		printf ("Buffer was invalid\n");
		fifo_write_unlock(buffer); return -1;
	}

	struct fifo_buffer_entry *current = buffer->gptr_first;
	struct fifo_buffer_entry *stop = NULL;

	if (last_element != NULL) {
		buffer->gptr_first = last_element->next;
		stop = last_element->next;
		if (stop == NULL) {
			buffer->gptr_last = NULL;
		}
	}
	else {
		buffer->gptr_first = NULL;
		buffer->gptr_last = NULL;
	}

	fifo_write_unlock(buffer);

	while (current != stop) {
		struct fifo_buffer_entry *next = current->next;

		ret++;

		printf ("Read buffer entry %p, give away data %p\n", current, current->data);

		callback(callback_data, current->data, current->size);

		free(current);

		current = next;
	}

	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time.
 */
static inline void fifo_read(struct fifo_buffer *buffer, void (*callback)(char *data, unsigned long int size)) {
	fifo_read_lock(buffer);
	if (buffer->invalid) { fifo_read_unlock(buffer); return; }

	struct fifo_buffer_entry *first = buffer->gptr_first;
	while (first != NULL) {
		callback(first->data, first->size);
		first = first->next;
	}

	fifo_read_unlock(buffer);
}
/*
 * This writing method holds the lock for a minimum amount of time, only to
 * update the pointers to the end.
 */
static inline void fifo_buffer_write(struct fifo_buffer *buffer, char *data, unsigned long int size) {
	struct fifo_buffer_entry *entry = malloc(sizeof(*entry));
	memset (entry, '\0', sizeof(*entry));
	entry->data = data;
	entry->size = size;

	fifo_write_lock(buffer);

	if (buffer->invalid) { free(entry->data); free(entry); fifo_write_unlock(buffer); return; }

	if (buffer->gptr_last == NULL) {
		buffer->gptr_last = entry;
		buffer->gptr_first = entry;
	}
	else {
		buffer->gptr_last->next = entry;
		buffer->gptr_last = entry;
	}

	printf ("New buffer entry %p data %p\n", entry, entry->data);

	fifo_write_unlock(buffer);
}

void fifo_buffer_invalidate(struct fifo_buffer *buffer);
void fifo_buffer_destroy(struct fifo_buffer *buffer);
void fifo_buffer_init(struct fifo_buffer *buffer);

#endif
