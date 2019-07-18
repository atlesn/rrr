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

#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include "buffer.h"
#include "../global.h"

/*
 * Set the invalid flag on the buffer, preventing new readers and writers from
 * using the buffer. After already initiated reads and writes have completed,
 * free the buffer contents.
 */
void fifo_buffer_invalidate(struct fifo_buffer *buffer) {
	pthread_mutex_lock (&buffer->mutex);
	if (buffer->invalid) { pthread_mutex_unlock (&buffer->mutex); return; }
	buffer->invalid = 1;
	pthread_mutex_unlock (&buffer->mutex);

	pthread_mutex_lock (&buffer->mutex);
	VL_DEBUG_MSG_1 ("Buffer %p waiting for %i readers and %i writers before invalidate\n", buffer, buffer->readers, buffer->writers);
	while (buffer->readers > 0 || buffer->writers > 0) {
		pthread_mutex_unlock (&buffer->mutex);
		pthread_mutex_lock (&buffer->mutex);
	}
	struct fifo_buffer_entry *entry = buffer->gptr_first;
	int freed_counter = 0;
	while (entry != NULL) {
		struct fifo_buffer_entry *next = entry->next;
		VL_DEBUG_MSG_4 ("Buffer %p free entry %p with data %p order %" PRIu64 "\n", buffer, entry, entry->data, entry->order);

		free (entry->data);
		free (entry);
		freed_counter++;
		entry = next;
	}
	VL_DEBUG_MSG_1 ("Buffer %p freed %i entries\n", buffer, freed_counter);
	pthread_mutex_unlock (&buffer->mutex);
}

void fifo_buffer_destroy(struct fifo_buffer *buffer) {
	pthread_mutex_destroy (&buffer->mutex);
	pthread_mutex_destroy (&buffer->write_mutex);
	pthread_mutex_destroy (&buffer->ratelimit_mutex);
	sem_destroy(&buffer->new_data_available);
	VL_DEBUG_MSG_1 ("Buffer destroy buffer struct %p\n", buffer);
}

int fifo_buffer_init(struct fifo_buffer *buffer) {
	int ret = 0;

	memset (buffer, '\0', sizeof(*buffer));

	buffer->invalid = 1;
	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->buffer_do_ratelimit = 0;
	buffer->ratelimit.sleep_spin_time = 2000000;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	ret |= pthread_mutex_init (&buffer->mutex, NULL);
	ret |= pthread_mutex_init (&buffer->write_mutex, NULL);
	ret |= pthread_mutex_init (&buffer->ratelimit_mutex, NULL);

	int sem_ret = sem_init(&buffer->new_data_available, 1, 0);
	if (sem_ret != 0) {
		char buf[1024];
		buf[0] = '\0';
		strerror_r(errno, buf, sizeof(buf));
		VL_MSG_ERR("Could not initialize semaphore in buffer: %s\n", buf);
		ret = 1;
	}

	if (ret == 0) {
		buffer->invalid = 0;
	}
	else {
		ret = 1;
	}

	return ret;
}

void __fifo_buffer_set_data_available(struct fifo_buffer *buffer) {
	int sem_status = 0;
	sem_getvalue(&buffer->new_data_available, &sem_status);
	if (sem_status == 0) {
		sem_post(&buffer->new_data_available);
	}
}

/*
 * Search entries and act according to the return value of the callback function. We
 * can delete entries or stop looping. See buffer.h . The callback function is expected
 * to take control of the memory of an entry which fifo_search deletes, if not
 * it will be leaked unless the callback also tells us to free the data using FIFO_SEARCH_FREE.
 */
int fifo_search (
	struct fifo_buffer *buffer,
	int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
	struct fifo_callback_args *callback_data,
	unsigned int wait_milliseconds
) {
	fifo_wait_for_data(buffer, wait_milliseconds);

	fifo_write_lock(buffer);
	if (buffer->invalid) {
		VL_DEBUG_MSG_1 ("Buffer was invalid\n");
		fifo_write_unlock(buffer);
		return FIFO_GLOBAL_ERR;
	}

	int err = 0;
	int cleared_entries = 0;

	struct fifo_buffer_entry *entry;
	struct fifo_buffer_entry *next;
	struct fifo_buffer_entry *prev = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = next) {
		VL_DEBUG_MSG_4("Buffer %p search loop entry %p next %p prev %p\n", buffer, entry, entry->next, prev);
		next = entry->next;

		int did_something = 0;
		int actions = callback(callback_data, entry->data, entry->size);

		if (actions == FIFO_SEARCH_KEEP) { // Just a 0
			goto keep;
		}
		if (actions == FIFO_SEARCH_ERR) {
			err = FIFO_CALLBACK_ERR;
			break;
		}
		if ((actions & FIFO_SEARCH_GIVE) != 0) {
			if (entry == buffer->gptr_first) {
				buffer->gptr_first = entry->next;
			}
			if (entry == buffer->gptr_last) {
				buffer->gptr_last = prev;
			}
			if (prev != NULL) {
				prev->next = entry->next;
			}

			cleared_entries++;

			if ((actions & FIFO_SEARCH_FREE) != 0) {
				free(entry->data);
			}
			VL_DEBUG_MSG_4("Buffer %p free entry %p after GIVE command\n", buffer, entry);
			free(entry);

			entry = NULL;
			did_something = 1;
		}
		if ((actions & FIFO_SEARCH_STOP) != 0) {
			break;
		}
		else if (did_something == 0) {
			VL_MSG_ERR ("Bug: Unkown return value %i to fifo_search\n", actions);
			exit (EXIT_FAILURE);
		}

		keep:
		prev = entry;
	}

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count -= cleared_entries;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	if (buffer->gptr_first != NULL) {
		__fifo_buffer_set_data_available(buffer);
	}

	fifo_write_unlock(buffer);

	return err;
}

/*
 * Delete entries with and order value < order_min. We assume the buffer is
 * already ordered by using fifo_buffer_write_ordered writes only.
 */
int fifo_clear_order_lt (
		struct fifo_buffer *buffer,
		uint64_t order_min
) {
	fifo_write_lock(buffer);
	if (buffer->invalid) {
		VL_DEBUG_MSG_1 ("Buffer was invalid\n");
		fifo_write_unlock(buffer);
		return FIFO_GLOBAL_ERR;
	}

	int cleared_entries = 0;

	struct fifo_buffer_entry *entry;
	struct fifo_buffer_entry *clear_end = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = entry->next){
		if (entry->order < order_min) {
			// All entries up to here are to be cleared
			clear_end = entry;
			cleared_entries++;
		}
		else {
			break;
		}
	}

	if (clear_end) {
		struct fifo_buffer_entry *clear_start = buffer->gptr_first;
		struct fifo_buffer_entry *clear_stop = clear_end->next;
		buffer->gptr_first = clear_end->next;

		if (clear_end->next == NULL) {
			// We are clearing the whole buffer
			buffer->gptr_last = NULL;
			buffer->gptr_first = NULL;
		}

		struct fifo_buffer_entry *next;
		for (entry = clear_start; entry != clear_stop; entry = next) {
			next = entry->next;

			VL_DEBUG_MSG_4 ("Buffer free entry %p in ordered clear with data %p order %" PRIu64 "\n", entry, entry->data, entry->order);

			free(entry->data);
			free(entry);
		}
	}

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count -= cleared_entries;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	if (buffer->gptr_first != NULL) {
		__fifo_buffer_set_data_available(buffer);
	}

	fifo_write_unlock(buffer);
	return 0;
}

int fifo_verify_counter(struct fifo_buffer *buffer) {
	int counter = 0;
	int claimed_count = 0;
	fifo_read_lock(buffer);

	claimed_count = buffer->entry_count;

	struct fifo_buffer_entry *current = buffer->gptr_first;
	while (current) {
		struct fifo_buffer_entry *next = current->next;
		counter++;
		current = next;
	}

	fifo_read_unlock(buffer);

	return (counter != claimed_count);
}

/*
 * This reading method holds a write lock for a minimum amount of time by
 * taking control of the start of the queue making it inaccessible to
 * others. The callback function must store the data pointer or free it.
 */
int fifo_read_clear_forward (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
		struct fifo_callback_args *callback_data,
		unsigned int wait_milliseconds
) {
	fifo_wait_for_data(buffer, wait_milliseconds);

	int ret = FIFO_OK;
	fifo_write_lock(buffer);
	if (buffer->invalid) {
		VL_DEBUG_MSG_1 ("Buffer was invalid\n");
		fifo_write_unlock(buffer);
		return FIFO_GLOBAL_ERR;
	}

	struct fifo_buffer_entry *current = buffer->gptr_first;
	struct fifo_buffer_entry *stop = NULL;

	int max_counter = FIFO_MAX_READS;
	struct fifo_buffer_entry *last_element_max = current;
	while (last_element_max != NULL && --max_counter) {
		if (last_element_max == last_element) {
			break;
		}
		last_element_max = last_element_max->next;
	}

	if (max_counter == 0) {
		last_element = last_element_max;
	}

	if (last_element != NULL) {
		buffer->gptr_first = last_element->next;
		stop = last_element->next;
		if (stop == NULL) {
			buffer->gptr_last = NULL;
		}
	}
	else {
		last_element = buffer->gptr_last;
		buffer->gptr_first = NULL;
		buffer->gptr_last = NULL;
	}

	if (buffer->gptr_first != NULL) {
		__fifo_buffer_set_data_available(buffer);
	}

	fifo_write_unlock(buffer);

	int processed_entries = 0;
	while (current != stop) {
		struct fifo_buffer_entry *next = current->next;

		VL_DEBUG_MSG_4 ("Read buffer entry %p, give away data %p\n", current, current->data);

		int ret_tmp = callback(callback_data, current->data, current->size);
		processed_entries++;
		if (ret_tmp != 0) {
			if ((ret_tmp & (FIFO_SEARCH_GIVE)) != 0) {
				VL_BUG("Bug: FIFO_SEARCH_GIVE returned to fifo_read_clear_forward, we always GIVE by default\n");
			}
			if ((ret_tmp & FIFO_SEARCH_FREE) != 0) {
					// Entry has not been processed and/or freed callback (for some reason)
					free(current->data);
			}
			if ((ret_tmp & FIFO_SEARCH_STOP) != 0) {
				// Stop processing and put the rest back into the buffer
				fifo_write_lock(buffer);
				struct fifo_buffer_entry *new_first = next;

				if (next == NULL) {
					// We are done anyway
				}
				else {
					last_element->next = buffer->gptr_first;
					buffer->gptr_first = new_first;
					if (buffer->gptr_last == NULL) {
						buffer->gptr_last = last_element;
					}
				}

				fifo_write_unlock(buffer);
				free(current);
				break;
			}
			if ((ret_tmp & FIFO_CALLBACK_ERR) != 0) {
				// Callback will free the memory also on error, unless FIFO_SEARCH_FREE is specified
				ret = 1;
			}
			ret_tmp &= ~(FIFO_SEARCH_GIVE|FIFO_SEARCH_FREE|FIFO_SEARCH_STOP|FIFO_CALLBACK_ERR);
			if (ret_tmp != 0) {
				VL_BUG("Unknown flags %i returned to fifo_read_clear_forward\n", ret_tmp);
			}
		}

		free(current);

		current = next;
	}

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count -= processed_entries;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

#ifdef FIFO_DEBUG_COUNTER
	if (fifo_verify_counter(buffer) != 0) {
		VL_BUG("Buffer size mismatch\n");
	}
#endif /* FIFO_DEBUG_COUNTER */

	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time. The callback function must not free the data or store it's pointer.
 * This function does not check FIFO_MAX_READS.
 *
 * TODO : Possibly unused function
 */
void fifo_read (
		struct fifo_buffer *buffer,
		int (*callback)(char *data, unsigned long int size),
		unsigned int wait_milliseconds
) {
	fifo_wait_for_data(buffer, wait_milliseconds);

	fifo_read_lock(buffer);
	if (buffer->invalid) { fifo_read_unlock(buffer); return; }

	struct fifo_buffer_entry *first = buffer->gptr_first;
	while (first != NULL) {
		int ret_tmp = callback(first->data, first->size);
		if (ret_tmp != 0) {
			if ((ret_tmp & FIFO_SEARCH_STOP) != 0) {
				break;
			}
			else if ((ret_tmp & (FIFO_SEARCH_GIVE|FIFO_SEARCH_FREE)) != 0) {
				VL_BUG("Bug: FIFO_SEARCH_GIVE or FIFO_SEARCH_FREE returned to fifo_read\n");
			}
		}
		first = first->next;
	}

	if (buffer->gptr_first != NULL) {
		__fifo_buffer_set_data_available(buffer);
	}

	fifo_read_unlock(buffer);
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time. The callback function must not free the data or store it's pointer.
 * Only elements with an order value higher than minimum_order are read. If the
 * callback function produces an error, we stop.
 */
int fifo_read_minimum (
		struct fifo_buffer *buffer,
		struct fifo_buffer_entry *last_element,
		int (*callback)(struct fifo_callback_args *callback_data, char *data, unsigned long int size),
		struct fifo_callback_args *callback_data,
		uint64_t minimum_order,
		unsigned int wait_milliseconds
) {
	fifo_wait_for_data(buffer, wait_milliseconds);

	fifo_read_lock(buffer);
	if (buffer->invalid) { fifo_read_unlock(buffer); return FIFO_GLOBAL_ERR; }
	int res = 0;
	struct fifo_buffer_entry *first = buffer->gptr_first;

	int processed_entries = 0;
	while (first != NULL) {
		if (first->order > minimum_order) {
			int res_ = callback(callback_data, first->data, first->size);

			if (++processed_entries == FIFO_MAX_READS || first == last_element) {
				break;
			}
			if (res_ == 0) {
				// Do nothing
			}
			else if ((res & FIFO_SEARCH_STOP) != 0) {
				res = 0;
				break;
			}
			else if ((res & (FIFO_SEARCH_GIVE|FIFO_SEARCH_FREE)) != 0) {
				VL_BUG("Bug: FIFO_SEARCH_GIVE or FIFO_SEARCH_FREE returned to fifo_read_minimum\n");
			}
			else {
				res = res_;
				break;
			}
		}

		first = first->next;
	}

	if (buffer->gptr_first != NULL) {
		__fifo_buffer_set_data_available(buffer);
	}

	fifo_read_unlock(buffer);

	return (res != 0 ? res : FIFO_OK);
}


void __fifo_buffer_do_ratelimit(struct fifo_buffer *buffer) {
	if (!buffer->buffer_do_ratelimit) {
		return;
	}

	struct fifo_buffer_ratelimit *ratelimit = &buffer->ratelimit;

	pthread_mutex_lock(&buffer->ratelimit_mutex);

	long long unsigned int spin_time =
			ratelimit->sleep_spin_time + (buffer->entry_count * buffer->entry_count);
	/*
	 * If the spin loop is longer than some time period we switch to sleeping instead. We then
	 * sleep one time for 9 entries before we loop again and measure the time once more. The 10th
	 * time (at the spin), we subtract the approximate number of spins we already did while sleeping
	 * on the other 9.
	 *
	 * If the spin loop is longer than some time period, we only spin every 10 times.
	 */

	if (++(ratelimit->burst_counter) == 10) {
		ratelimit->burst_counter = 0;

		unsigned long int do_usleep = 0;

		/* If we know how long the spinlock lasts, sleep half the period */
		if (ratelimit->spins_per_us > 0) {
			do_usleep = spin_time / 2 / ratelimit->spins_per_us;

			if (do_usleep < 50) {
				do_usleep = 0;
			}
			else {
				spin_time = spin_time / 2;
			}
		}

		pthread_mutex_unlock(&buffer->ratelimit_mutex);
		uint64_t time_start = time_get_64();
		long long int spin_time_orig = spin_time;
		while (--spin_time > 0) {
			asm("");
		}
		uint64_t time_end = time_get_64();
		uint64_t time_diff = (time_end - time_start) + 1; // +1 to prevent division by zero
		if (do_usleep) {
			usleep(do_usleep);
		}
		pthread_mutex_lock(&buffer->ratelimit_mutex);

/*		printf ("Spin time %lu rounds %llu usleep %lu\n",
				time_diff,
				spin_time_orig,
				do_usleep
		);*/

		long long int current_spins_per_us = spin_time_orig / time_diff;

		if (ratelimit->spins_per_us == 0) {
			ratelimit->spins_per_us = current_spins_per_us;
		}
		else {
			// Give little weight to the new value when updating
			ratelimit->spins_per_us = (ratelimit->spins_per_us * 9 + current_spins_per_us) / 10;
		}
//		VL_DEBUG_MSG_1("spintime %llu spins per us %llu\n", time_diff, buffer->spins_per_us);
	}

	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

void __fifo_buffer_update_ratelimit(struct fifo_buffer *buffer) {
	struct fifo_buffer_ratelimit *ratelimit = &buffer->ratelimit;

	pthread_mutex_lock(&buffer->ratelimit_mutex);

	uint64_t time_now = time_get_64();

	if (ratelimit->prev_time == 0) {
		ratelimit->prev_time = time_now;
		ratelimit->prev_entry_count = buffer->entry_count;
		goto out_unlock;
	}

	// Work every 250ms
	if (time_now - ratelimit->prev_time < 250000) {
		goto out_unlock;
	}

	int entry_diff = ratelimit->prev_entry_count - buffer->entry_count;

	if (entry_diff > 0) {
		// Readers are faster
		ratelimit->read_write_balance = (ratelimit->read_write_balance + entry_diff) / 2;
	}
	else if (entry_diff < 0) {
		// Writers are faster
		ratelimit->read_write_balance = (ratelimit->read_write_balance + entry_diff) / 2;
		ratelimit->sleep_spin_time += 1000;
	}
	else {
		ratelimit->sleep_spin_time -= (ratelimit->sleep_spin_time / 10);
	}

	ratelimit->sleep_spin_time = ratelimit->sleep_spin_time - (ratelimit->read_write_balance * 10);

	if (ratelimit->sleep_spin_time < 1) {
		ratelimit->sleep_spin_time = 1;
	}
	else if (ratelimit->sleep_spin_time > 10000000000) {
		ratelimit->sleep_spin_time = 10000000000;
	}

	unsigned long long int spintime_us = (ratelimit->sleep_spin_time / (ratelimit->spins_per_us + 1));

	VL_DEBUG_MSG_4("Buffer %p read/write balance %f spins %llu (%llu us) spins/us %llu entries %i (do sleep = %i)\n",
			buffer,
			ratelimit->read_write_balance,
			ratelimit->sleep_spin_time,
			spintime_us,
			ratelimit->spins_per_us,
			buffer->entry_count,
			buffer->buffer_do_ratelimit
	);

	ratelimit->prev_time = time_now;
	ratelimit->prev_entry_count = buffer->entry_count;

	out_unlock:
	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

/*
 * This writing method holds the lock for a minimum amount of time, only to
 * update the pointers to the end. If the buffer turns out to be invalid, we
 * simply free the data and return.
 */
void fifo_buffer_write(struct fifo_buffer *buffer, char *data, unsigned long int size) {
	struct fifo_buffer_entry *entry = malloc(sizeof(*entry));
	memset (entry, '\0', sizeof(*entry));
	entry->data = data;
	entry->size = size;

	fifo_write_lock(buffer);

	if (buffer->invalid) {
		fifo_write_unlock(buffer);
		free(entry->data);
		free(entry);
		return;
	}

	if (buffer->gptr_last == NULL) {
		buffer->gptr_last = entry;
		buffer->gptr_first = entry;
	}
	else {
		buffer->gptr_last->next = entry;
		buffer->gptr_last = entry;
	}

	VL_DEBUG_MSG_4 ("New buffer entry %p data %p\n", entry, entry->data);

	__fifo_buffer_set_data_available(buffer);

	__fifo_buffer_update_ratelimit(buffer);

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count++;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	fifo_write_unlock(buffer);

	__fifo_buffer_do_ratelimit(buffer);
}

/*
 * This write method insert data in order according to the order 8-byte value.
 */
void fifo_buffer_write_ordered(struct fifo_buffer *buffer, uint64_t order, char *data, unsigned long int size) {
	struct fifo_buffer_entry *entry = malloc(sizeof(*entry));
	memset (entry, '\0', sizeof(*entry));
	entry->data = data;
	entry->size = size;
	entry->order = order;

	fifo_write_lock(buffer);

	if (buffer->invalid) {
		fifo_write_unlock(buffer);
		free(entry->data);
		free(entry);
		return;
	}

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
	VL_DEBUG_MSG_4 ("New ordered buffer entry %p data %p\n", entry, entry->data);

	__fifo_buffer_set_data_available(buffer);

	__fifo_buffer_update_ratelimit(buffer);

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count++;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	fifo_write_unlock(buffer);

	__fifo_buffer_do_ratelimit(buffer);
}
