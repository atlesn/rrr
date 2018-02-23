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
	while (buffer->readers > 0 || buffer->writers > 0) {
	}
	struct fifo_buffer_entry *entry = buffer->gptr_first;
	while (entry != NULL) {
		struct fifo_buffer_entry *next = entry->next;
		free (entry);
		entry = next;
	}
	pthread_mutex_unlock (&buffer->mutex);
}

void fifo_buffer_destroy(struct fifo_buffer *buffer) {
	pthread_mutex_destroy (&buffer->mutex);
	free(buffer);
}

struct fifo_buffer *fifo_buffer_init() {
	struct fifo_buffer *buffer = malloc(sizeof(*buffer));
	memset (buffer, '\0', sizeof(*buffer));
	pthread_mutex_init (&buffer->mutex, NULL);
	return buffer;
}
