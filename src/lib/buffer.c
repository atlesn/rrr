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
#include <inttypes.h>

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
		printf ("Buffer free entry %p with data %p order %" PRIu64 "\n", entry, entry->data, entry->order);

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
 * Search entries and act according to the return value of the callback function. We
 * can delete entries or stop looping. See buffer.h . The callback function is expected
 * to take control of the memory of an entry which fifo_search deletes, if not
 * it will be leaked.
 */
int fifo_search (
	struct fifo_buffer *buffer,
	int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
	struct fifo_callback_args *callback_data
) {
	fifo_read_lock(buffer);

	int err = 0;

	struct fifo_buffer_entry *entry;
	struct fifo_buffer_entry *next;
	struct fifo_buffer_entry *prev = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = next) {
		next = entry->next;

		int did_something = 0;
		int actions = callback(callback_data, entry->data, entry->size);

		if (actions == FIFO_SEARCH_KEEP) { // Just a 0
			goto keep;
		}
		if (actions == FIFO_SEARCH_ERR) {
			err = 1;
			break;
		}
		if ((actions & FIFO_SEARCH_GIVE) != 0) {
			fifo_read_to_write_lock(buffer);
			if (entry == buffer->gptr_first) {
				buffer->gptr_first = entry->next;
			}
			if (entry == buffer->gptr_last) {
				buffer->gptr_last = prev;
			}
			if (prev != NULL) {
				prev->next = entry->next;
			}
			free(entry); // Don't free data, callback takes care of it
			entry = NULL;
			fifo_write_to_read_lock(buffer);
			did_something = 1;
		}
		if ((actions & FIFO_SEARCH_STOP) != 0) {
			break;
		}
		else if (did_something == 0) {
			fprintf (stderr, "Bug: Unkown return value %i to fifo_search\n", actions);
			exit (EXIT_FAILURE);
		}

		keep:
		prev = entry;
	}

	fifo_read_unlock(buffer);

	return err;
}

int fifo_clear_order_lt (
		struct fifo_buffer *buffer,
		uint64_t order_min
) {
	fifo_read_lock(buffer);

	struct fifo_buffer_entry *entry;
	struct fifo_buffer_entry *clear_end = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = entry->next){
		if (entry->order < order_min) {
			// All entries up to here are to be cleared
			clear_end = entry;
		}
		else {
			break;
		}
	}

	if (clear_end) {
		// Change to write lock and cut the part we're clearing out. Release the lock
		// and free the data.
		fifo_read_to_write_lock(buffer);

		struct fifo_buffer_entry *clear_start = buffer->gptr_first;
		struct fifo_buffer_entry *clear_stop = clear_end->next;
		buffer->gptr_first = clear_end->next;

		if (clear_end->next == NULL) {
			// We are clearing the whole buffer
			buffer->gptr_last = NULL;
			buffer->gptr_first = NULL;
		}

		fifo_write_unlock(buffer);

		struct fifo_buffer_entry *next;
		for (entry = clear_start; entry != clear_stop; entry = next) {
			next = entry->next;

			printf ("Buffer free entry %p in ordered clear with data %p order %" PRIu64 "\n", entry, entry->data, entry->order);

			free(entry->data);
			free(entry);
		}

		return 0;
	}

	fifo_read_unlock(buffer);
	return 0;
}

/*
 * This reading method holds a write lock for a minum amount of time by
 * taking control of the start of the queue making it inaccessible to
 * others.
 */
int fifo_read_clear_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
		struct fifo_callback_args *callback_data
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

		//printf ("Read buffer entry %p, give away data %p\n", current, current->data);

		int ret_tmp = callback(callback_data, current->data, current->size);
		ret = ret != 0 ? 1 : (ret_tmp != 0 ? 1 : 0);

		free(current);

		current = next;
	}

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

	//printf ("New buffer entry %p data %p\n", entry, entry->data);

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

	// Check if buffer is empty
	if (pos == NULL) {
		buffer->gptr_first = entry;
		buffer->gptr_last = entry;
		entry->next = NULL;
		goto out;
	}

	// Quick check to see if we're bigger than last element
	if (buffer->gptr_last->order < order) {
		// Insert at end
		buffer->gptr_last->next = entry;
		buffer->gptr_last = entry;
		entry->next = NULL;
		goto out;
	}

	struct fifo_buffer_entry *prev = NULL;
	for (; pos != NULL && pos->order < order; pos = pos->next) {
		prev = pos;
	}

	if (pos == NULL) {
		// Insert at end (we check this at the beginning, but still...)
		buffer->gptr_last->next = entry;
		buffer->gptr_last = entry;
		entry->next = NULL;
	}
	else if (prev != NULL) {
		// Insert in the middle
		prev->next = entry;
		entry->next = pos;
	}
	else {
		// Insert front
		entry->next = buffer->gptr_first;
		buffer->gptr_first = entry;
	}

	out:
	//printf ("New ordered buffer entry %p data %p\n", entry, entry->data);

	fifo_write_unlock(buffer);
}
