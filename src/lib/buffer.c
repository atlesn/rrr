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

#include <stdlib.h>
#include <pthread.h>

#include "buffer.h"

void fifo_buffer_invalidate(struct fifo_buffer *buffer) {
	pthread_mutex_lock (&buffer->mutex);
	if (buffer->invalid) { pthread_mutex_unlock (&buffer->mutex); return; }
	buffer->invalid = 1;
	pthread_mutex_unlock (&buffer->mutex);

	pthread_mutex_lock (&buffer->mutex);
	printf ("Buffer waiting for %i readers and %i writers before invalidate\n", buffer->readers, buffer->writers);
	while (buffer->readers > 0 || buffer->writers > 0) {
	}
	struct fifo_buffer_entry *entry = buffer->gptr_first;
	while (entry != NULL) {
		struct fifo_buffer_entry *next = entry->next;
		printf ("Free buffer entry %p data %p\n", entry, entry->data);

		printf ("Buffer free entry %p with data %p\n", entry, entry->data);

		free (entry->data);
		free (entry);
		entry = next;
	}
	pthread_mutex_unlock (&buffer->mutex);
}

void fifo_buffer_destroy(struct fifo_buffer *buffer) {
	pthread_mutex_destroy (&buffer->mutex);
	printf ("Buffer destroy buffer struct %p\n", buffer);
}

void fifo_buffer_init(struct fifo_buffer *buffer) {
	memset (buffer, '\0', sizeof(*buffer));
	pthread_mutex_init (&buffer->mutex, NULL);
}

/*
 * This reading method holds a write lock for a minum amount of time by
 * taking control of the start of the queue making it inaccessible to
 * others.
 */
int fifo_read_clear_forward (
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
 * This reading method holds a read lock througout the
 * reading process
 */
int fifo_read_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		void (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
) {
	int ret = 0;
	fifo_read_lock(buffer);
	if (buffer->invalid) {
		printf ("Buffer was invalid\n");
		fifo_read_unlock(buffer); return -1;
	}

	struct fifo_buffer_entry *current = buffer->gptr_first;
	struct fifo_buffer_entry *stop = last_element;

	while (current != stop) {
		struct fifo_buffer_entry *next = current->next;

		ret++;

		printf ("Read buffer entry %p, preserve data %p\n", current, current->data);

		callback(callback_data, current->data, current->size);

		current = next;
	}

	fifo_read_unlock(buffer);

	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time.
 */
void fifo_read(struct fifo_buffer *buffer, void (*callback)(char *data, unsigned long int size)) {
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
void fifo_buffer_write(struct fifo_buffer *buffer, char *data, unsigned long int size) {
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


void fifo_buffer_write_ordered(struct fifo_buffer *buffer, uint64_t order, char *data, unsigned long int size) {
	struct fifo_buffer_entry *entry = malloc(sizeof(*entry));
	memset (entry, '\0', sizeof(*entry));
	entry->data = data;
	entry->size = size;
	entry->order = order;

	fifo_write_lock(buffer);

	struct fifo_buffer_entry *pos = buffer->gptr_first;
	if (pos == NULL) {
		buffer->gptr_first = entry;
		buffer->gptr_last = entry;
		entry->next = NULL;
		goto out;
	}

	while (pos != NULL) {
		if (pos->order >= order) {
			if (pos == buffer->gptr_first) {
				buffer->gptr_first = entry;
			}
			entry->next = pos;
			goto out;
		}
		pos = pos->next;
	}

	buffer->gptr_last->next = entry;
	buffer->gptr_last = entry;
	entry->next = NULL;

	out:
	printf ("New ordered buffer entry %p data %p\n", entry, entry->data);

	fifo_write_unlock(buffer);
}
