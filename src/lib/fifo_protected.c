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

#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include "fifo_protected.h"
#include "log.h"
#include "allocator.h"
#include "util/posix.h"
#include "util/slow_noop.h"
#include "util/rrr_time.h"

//#define RRR_FIFO_PROTECTED_BUFFER_RATELIMIT_DEBUG 1

static inline void __rrr_fifo_protected_write_lock(struct rrr_fifo_protected *buffer) {
	while (pthread_rwlock_trywrlock(&buffer->rwlock) != 0) {
		pthread_testcancel();
		rrr_posix_usleep(10);
	}
}

static inline void __rrr_fifo_protected_read_lock(struct rrr_fifo_protected *buffer) {
	while (pthread_rwlock_tryrdlock(&buffer->rwlock) != 0) {
		pthread_testcancel();
		rrr_posix_usleep(10);
	}
}

static inline void __rrr_fifo_protected_unlock(struct rrr_fifo_protected *buffer) {
	pthread_rwlock_unlock(&buffer->rwlock);
}

static inline void __rrr_fifo_protected_unlock_void(void *arg) {
	__rrr_fifo_protected_unlock(arg);
}

#define RRR_FIFO_PROTECTED_BUFFER_WITH_STATS_LOCK_DO(action)   \
    pthread_mutex_lock(&buffer->stats_mutex);                  \
    action;                                                    \
    pthread_mutex_unlock(&buffer->stats_mutex)

static inline void __rrr_fifo_protected_stats_add_written (struct rrr_fifo_protected *buffer, rrr_length num) {
	RRR_FIFO_PROTECTED_BUFFER_WITH_STATS_LOCK_DO(buffer->stats.total_entries_written += num);
}

static inline void __rrr_fifo_protected_stats_add_deleted (struct rrr_fifo_protected *buffer, rrr_length num) {
	RRR_FIFO_PROTECTED_BUFFER_WITH_STATS_LOCK_DO(buffer->stats.total_entries_deleted += num);
}

void rrr_fifo_protected_get_stats_populate (
		struct rrr_fifo_protected_stats *target,
		uint64_t entries_written,
		uint64_t entries_deleted
) {
	target->total_entries_written = entries_written;
	target->total_entries_deleted = entries_deleted;
}

int rrr_fifo_protected_get_stats (
		struct rrr_fifo_protected_stats *stats,
		struct rrr_fifo_protected *buffer
) {
	RRR_FIFO_PROTECTED_BUFFER_WITH_STATS_LOCK_DO(*stats = buffer->stats);
	return 0;
}

static void __rrr_fifo_protected_entry_lock (struct rrr_fifo_protected_entry *entry) {
	pthread_mutex_lock(&entry->lock);
}

static void __rrr_fifo_protected_entry_unlock (struct rrr_fifo_protected_entry *entry) {
	pthread_mutex_unlock(&entry->lock);
}

static void __rrr_fifo_protected_entry_unlock_void (void *arg) {
	struct rrr_fifo_protected_entry *entry = arg;
	pthread_mutex_unlock(&entry->lock);
}

// Buffer write lock must be held
static void __rrr_fifo_protected_entry_destroy_unlocked (
		struct rrr_fifo_protected *buffer,
		struct rrr_fifo_protected_entry *entry
) {
	__rrr_fifo_protected_entry_lock(entry);
	if (entry->data != NULL) {
		buffer->free_callback(entry->data);
	}
	__rrr_fifo_protected_entry_unlock(entry);
	pthread_mutex_destroy(&entry->lock);
	rrr_free(entry);
}

static void __rrr_fifo_protected_entry_destroy_simple_void (
		void *ptr
) {
	struct rrr_fifo_protected_entry *entry = ptr;
	pthread_mutex_destroy(&entry->lock);
	rrr_free(entry);
}

static void __rrr_fifo_protected_entry_destroy_data_unlocked (
		struct rrr_fifo_protected *buffer,
		struct rrr_fifo_protected_entry *entry
) {
	__rrr_fifo_protected_entry_lock(entry);
	if (entry->data != NULL) {
		buffer->free_callback(entry->data);
		entry->data = NULL;
	}
	__rrr_fifo_protected_entry_unlock(entry);
}

static void __rrr_fifo_protected_entry_release_data_unlocked (
		struct rrr_fifo_protected_entry *entry
) {
	entry->data = NULL;
	entry->size = 0;
}

// Buffer write lock must be held
static int __rrr_fifo_protected_entry_new_unlocked (
		struct rrr_fifo_protected_entry **result
) {
	int ret = 0;

	*result = NULL;

	struct rrr_fifo_protected_entry *entry = rrr_allocate(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate entry in __rrr_fifo_protected_entry_new_unlocked \n");
		ret = 1;
		goto out;
	}

	memset (entry, '\0', sizeof(*entry));

	if (rrr_posix_mutex_init(&entry->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_fifo_protected_entry_new_unlocked\n");
		ret = 1;
		goto out_free;
	}

	*result = entry;

	goto out;

	out_free:
		rrr_free(entry);
	out:
		return ret;
}

// Buffer write lock must be held
static int __rrr_fifo_write_queue_merge_nolock (
		struct rrr_fifo_protected *buffer
) {
	int ret = 0;

	pthread_mutex_lock(&buffer->write_queue_mutex);

	// Do not use the counter to check for empty queue, it might be in
	// an inconsistent state in case of overflow.
	if (buffer->gptr_write_queue_first != NULL) {
		struct rrr_fifo_protected_entry *first = buffer->gptr_write_queue_first;

		// Write all metadata again to force write while holding buffer write lock
		while (first) {
			// TODO : Unsure if compiler optimizes this away, looks like GCC actually does the writing
			struct rrr_fifo_protected_entry tmp = *first;
			*first = tmp;
			first = first->next;
		}

		// Merge write queue and buffer
		if (buffer->gptr_last == NULL) {
			buffer->gptr_first = buffer->gptr_write_queue_first;
			buffer->gptr_last = buffer->gptr_write_queue_last;
		}
		else {
			buffer->gptr_last->next = buffer->gptr_write_queue_first;
			buffer->gptr_last = buffer->gptr_write_queue_last;
		}

		buffer->gptr_write_queue_first = NULL;
		buffer->gptr_write_queue_last = NULL;

		__rrr_fifo_protected_stats_add_written(buffer, buffer->write_queue_entry_count);

		pthread_mutex_lock(&buffer->ratelimit_mutex);
		if ((ret = rrr_length_add_err (&buffer->entry_count, buffer->write_queue_entry_count)) != 0) {
			RRR_MSG_0("Entry count overflow in buffer during write queue merge\n");
			ret = RRR_FIFO_PROTECTED_GLOBAL_ERR;
		}
		buffer->write_queue_entry_count = 0;
		pthread_mutex_unlock(&buffer->ratelimit_mutex);

	}

	pthread_mutex_unlock(&buffer->write_queue_mutex);

	return ret;
}

/*
 * Remove all entries from a buffer
 */
static void __rrr_fifo_protected_clear (
		struct rrr_fifo_protected *buffer
) {
	__rrr_fifo_protected_write_lock(buffer);
	pthread_cleanup_push(__rrr_fifo_protected_unlock_void, buffer);

	if (__rrr_fifo_write_queue_merge_nolock(buffer) != 0) {
		RRR_MSG_0("Warning: Buffer entry count overflow during clear operation\n");
	}

	struct rrr_fifo_protected_entry *entry = buffer->gptr_first;
	unsigned int freed_counter = 0;
	while (entry != NULL) {
		struct rrr_fifo_protected_entry *next = entry->next;
		RRR_DBG_4 ("buffer %p free entry %p with data %p order %" PRIu64 "\n", buffer, entry, entry->data, entry->order);
		__rrr_fifo_protected_entry_destroy_unlocked(buffer, entry);
		freed_counter++;
		entry = next;
	}

	__rrr_fifo_protected_stats_add_deleted(buffer, freed_counter);

	RRR_DBG_4 ("buffer %p freed %i entries\n", buffer, freed_counter);

	buffer->gptr_first = NULL;
	buffer->gptr_last = NULL;
	buffer->entry_count = 0;

	pthread_cleanup_pop(1);
}

void rrr_fifo_protected_destroy (
		struct rrr_fifo_protected *buffer
) {
	__rrr_fifo_protected_clear(buffer);
	pthread_rwlock_destroy (&buffer->rwlock);
	pthread_mutex_destroy (&buffer->write_queue_mutex);
	pthread_mutex_destroy (&buffer->ratelimit_mutex);
	pthread_mutex_destroy (&buffer->stats_mutex);
}

int rrr_fifo_protected_init (
		struct rrr_fifo_protected *buffer,
		void (*free_callback)(void *arg)
) {
	int ret = 0;

	memset (buffer, '\0', sizeof(*buffer));

	ret = rrr_posix_mutex_init (&buffer->write_queue_mutex, 0);
	if (ret != 0) {
		goto out;
	}

	ret = rrr_posix_rwlock_init(&buffer->rwlock, 0);
	if (ret != 0) {
		goto out_destroy_write_queue_mutex;
	}

	ret = rrr_posix_mutex_init (&buffer->ratelimit_mutex, 0);
	if (ret != 0) {
		goto out_destroy_rwlock;
	}

	ret = rrr_posix_mutex_init (&buffer->stats_mutex, 0);
	if (ret != 0) {
		goto out_destroy_ratelimit_mutex;
	}

	buffer->buffer_do_ratelimit = 0;
	buffer->ratelimit.sleep_spin_time = 2000000;
	buffer->free_callback = free_callback;

	goto out;
//	out_destroy_stats_mutex:
//		pthread_mutex_destroy(&buffer->stats_mutex);
	out_destroy_ratelimit_mutex:
		pthread_mutex_destroy(&buffer->ratelimit_mutex);
	out_destroy_rwlock:
		pthread_rwlock_destroy(&buffer->rwlock);
	out_destroy_write_queue_mutex:
		pthread_mutex_destroy(&buffer->write_queue_mutex);
	out:
		return (ret != 0 ? 1 : 0);
}

void rrr_fifo_protected_set_do_ratelimit (
		struct rrr_fifo_protected *buffer,
		int set
) {
	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->buffer_do_ratelimit = set;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

rrr_length rrr_fifo_protected_get_entry_count (
		struct rrr_fifo_protected *buffer
) {
	rrr_length ret = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	ret = buffer->entry_count;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	return ret;
}

static int __rrr_fifo_protected_is_populated (
		struct rrr_fifo_protected *buffer
) {
	int ret = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	ret = buffer->entry_count || buffer->write_queue_entry_count;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	return ret;
}

int rrr_fifo_protected_get_ratelimit_active (
		struct rrr_fifo_protected *buffer
) {
	int ret = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	ret = buffer->buffer_do_ratelimit;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	return ret;
}

static int __rrr_fifo_protected_write_callback_return_check (
		int *do_ordered_write,
		int *write_again,
		int *do_drop,
		int ret_to_check
) {
	int ret = 0;

	*write_again = 0;
	*do_ordered_write = 0;
	*do_drop = 0;

	if (ret_to_check == 0) {
		goto out;
	}

	if ((ret_to_check & RRR_FIFO_PROTECTED_WRITE_ORDERED) == RRR_FIFO_PROTECTED_WRITE_ORDERED) {
		if ((ret_to_check & ~(RRR_FIFO_PROTECTED_WRITE_AGAIN|RRR_FIFO_PROTECTED_WRITE_ORDERED|RRR_FIFO_PROTECTED_WRITE_DROP)) != 0) {
			RRR_BUG("BUG: Callback return WRITE_ORDERED along with other illegal return values %i in __rrr_fifo_protected_write_callback_return_check\n", ret_to_check);
		}
		*do_ordered_write = 1;
	}

	if ((ret_to_check & RRR_FIFO_PROTECTED_WRITE_AGAIN) == RRR_FIFO_PROTECTED_WRITE_AGAIN) {
		if ((ret_to_check & ~(RRR_FIFO_PROTECTED_WRITE_AGAIN|RRR_FIFO_PROTECTED_WRITE_ORDERED|RRR_FIFO_PROTECTED_WRITE_DROP)) != 0) {
			RRR_BUG("BUG: Callback return WRITE_AGAIN along with other illegal return values %i in __rrr_fifo_protected_write_callback_return_check\n", ret_to_check);
		}
		*write_again = 1;
	}

	if ((ret_to_check & RRR_FIFO_PROTECTED_GLOBAL_ERR) == RRR_FIFO_PROTECTED_GLOBAL_ERR) {
		if ((ret_to_check & ~(RRR_FIFO_PROTECTED_GLOBAL_ERR)) != 0) {
			RRR_BUG("BUG: Callback returned GLOBAL_ERR along with return values %i in __rrr_fifo_protected_write_callback_return_check\n", ret_to_check);
		}
		ret = 1;
		goto out;
	}

	if ((ret_to_check & RRR_FIFO_PROTECTED_WRITE_DROP) == RRR_FIFO_PROTECTED_WRITE_DROP) {
		if ((ret_to_check &= ~(RRR_FIFO_PROTECTED_WRITE_DROP|RRR_FIFO_PROTECTED_WRITE_AGAIN)) != 0) {
			RRR_BUG("BUG: Callback returned WRITE_DROP along with return values %i in __rrr_fifo_protected_write_callback_return_check\n", ret_to_check);
		}
		*do_drop = 1;
		goto out;
	}

	ret_to_check &= ~(RRR_FIFO_PROTECTED_WRITE_AGAIN|RRR_FIFO_PROTECTED_WRITE_ORDERED|RRR_FIFO_PROTECTED_WRITE_DROP);

	if (ret_to_check != 0) {
		RRR_BUG("Unknown return values %i from callback in __rrr_fifo_protected_write_callback_return_check\n", ret_to_check);
	}

	out:
	return ret;
}

static void __rrr_fifo_protected_write_update_pointers (
		struct rrr_fifo_protected *buffer,
		struct rrr_fifo_protected_entry *entry,
		uint64_t order,
		int do_ordered_write
) {
	struct rrr_fifo_protected_entry *pos = buffer->gptr_first;

	if (pos == NULL) {
		buffer->gptr_first = entry;
		buffer->gptr_last = entry;
		entry->next = NULL;
	}
	else if (do_ordered_write) {
		// Quick check to see if we're bigger than last element
		if (buffer->gptr_last->order < order) {
			// Insert at end
			buffer->gptr_last->next = entry;
			buffer->gptr_last = entry;
			entry->next = NULL;
		}
		else {
			struct rrr_fifo_protected_entry *prev = NULL;
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
				// Insert at front
				entry->next = buffer->gptr_first;
				buffer->gptr_first = entry;
			}
		}
	}
	else {
		buffer->gptr_last->next = entry;
		buffer->gptr_last = entry;
		entry->next = NULL;
	}
}

/*
 * This reading method holds a write lock for a minimum amount of time by
 * taking control of the start of the queue making it inaccessible to
 * others. The callback function must store the data pointer or free it.
 * Reads at most RRR_FIFO_PROTECTED_MAX_READS entries.
 */
int rrr_fifo_protected_read_clear_forward (
		struct rrr_fifo_protected *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
) {
	int ret = RRR_FIFO_PROTECTED_OK;

	int combined_count = __rrr_fifo_protected_is_populated(buffer);
	if (combined_count == 0) {
		goto out;
	}

	struct rrr_fifo_protected_entry *last_element = NULL;
	struct rrr_fifo_protected_entry *current = NULL;
	struct rrr_fifo_protected_entry *stop = NULL;
	int max_counter = RRR_FIFO_PROTECTED_MAX_READS;

	__rrr_fifo_protected_write_lock(buffer);
	pthread_cleanup_push(__rrr_fifo_protected_unlock_void, buffer);

	if ((ret = __rrr_fifo_write_queue_merge_nolock(buffer)) != 0) {
		RRR_MSG_0("Could not merge write queue in rrr_fifo_protected_read_clear_forward\n");
		goto unlock_intermediate;
	}

	// Must be set after write queue merge
	last_element = current = buffer->gptr_first;

	while (last_element != NULL && --max_counter) {
		last_element = last_element->next;
	}

	if (last_element != NULL) {
		// Perform splice
		buffer->gptr_first = last_element->next;
		stop = last_element->next;
		if (stop == NULL) {
			buffer->gptr_last = NULL;
		}
	}
	else {
		// Take all entries
		last_element = buffer->gptr_last;
		buffer->gptr_first = NULL;
		buffer->gptr_last = NULL;
	}

	unlock_intermediate:
	pthread_cleanup_pop(1);

	if (ret != 0) {
		__rrr_fifo_protected_clear (buffer);
		goto out;
	}

	rrr_length processed_entries = 0;
	while (current != stop) {
		struct rrr_fifo_protected_entry *next = NULL;

		int ret_tmp = 0;

		{
			// Don't access entry pointers outside lock
			// Also, don't hold read lock while in callback
			__rrr_fifo_protected_read_lock(buffer);

			next = current->next;

			unsigned long int size = current->size;
			char *data = current->data;

			__rrr_fifo_protected_unlock(buffer); 

			{
				__rrr_fifo_protected_entry_lock(current);
				pthread_cleanup_push(__rrr_fifo_protected_entry_unlock_void, current);

				ret_tmp = callback(callback_data, data, size);

				pthread_cleanup_pop(1);
			}
		}

		rrr_length_inc_bug(&processed_entries);

		if (ret_tmp != 0) {
			{
				__rrr_fifo_protected_write_lock(buffer);
				pthread_cleanup_push(__rrr_fifo_protected_unlock_void, buffer);
				if ((ret_tmp & RRR_FIFO_PROTECTED_SEARCH_FREE) != 0) {
					// Callback wants us to free memory
					ret_tmp = ret_tmp & ~(RRR_FIFO_PROTECTED_SEARCH_FREE);
					__rrr_fifo_protected_entry_destroy_data_unlocked(buffer, current);
				}
				else {
					__rrr_fifo_protected_entry_release_data_unlocked(current);
				}
				pthread_cleanup_pop(1);
			}

			if ((ret_tmp & RRR_FIFO_PROTECTED_CALLBACK_ERR) != 0) {
				// Callback will free the memory also on error, unless FIFO_SEARCH_FREE is specified
				ret |= RRR_FIFO_PROTECTED_CALLBACK_ERR;
			}
			if ((ret_tmp & RRR_FIFO_PROTECTED_GLOBAL_ERR) != 0) {
				// Callback will free the memory also on error, unless FIFO_SEARCH_FREE is specified
				ret |= RRR_FIFO_PROTECTED_GLOBAL_ERR;
			}
			if ((ret_tmp & (RRR_FIFO_PROTECTED_SEARCH_STOP|RRR_FIFO_PROTECTED_CALLBACK_ERR|RRR_FIFO_PROTECTED_GLOBAL_ERR)) != 0) {
				// Stop processing and put the rest back into the buffer
				{
					__rrr_fifo_protected_write_lock(buffer);
					pthread_cleanup_push(__rrr_fifo_protected_unlock_void, buffer);
					struct rrr_fifo_protected_entry *new_first = next;

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

					ret = ret_tmp & ~(RRR_FIFO_PROTECTED_SEARCH_STOP);

					__rrr_fifo_protected_entry_destroy_unlocked(buffer, current);
					pthread_cleanup_pop(1);
				}

				break;
			}
			ret_tmp &= ~(RRR_FIFO_PROTECTED_SEARCH_FREE|RRR_FIFO_PROTECTED_SEARCH_STOP|RRR_FIFO_PROTECTED_CALLBACK_ERR|RRR_FIFO_PROTECTED_GLOBAL_ERR);
			if (ret_tmp != 0) {
				RRR_BUG("Unknown flags %i returned to fifo_read_clear_forward\n", ret_tmp);
			}
		}

		{
			__rrr_fifo_protected_write_lock(buffer);
			// Don't free data
			__rrr_fifo_protected_entry_release_data_unlocked(current);
			__rrr_fifo_protected_entry_destroy_unlocked(buffer, current);
			__rrr_fifo_protected_unlock(buffer);
		}

		current = next;
	}

	__rrr_fifo_protected_stats_add_deleted(buffer, processed_entries);

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	rrr_length_sub_bug (&buffer->entry_count, processed_entries);
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	out:
	return ret;
}

static void __rrr_fifo_protected_do_ratelimit(struct rrr_fifo_protected *buffer) {
	if (!buffer->buffer_do_ratelimit) {
		return;
	}

#ifdef RRR_FIFO_PROTECTED_BUFFER_RATELIMIT_DEBUG
	uint64_t ratelimit_in = rrr_time_get_64();
#endif

	pthread_mutex_lock(&buffer->ratelimit_mutex);

	struct rrr_fifo_protected_ratelimit *ratelimit = &buffer->ratelimit;

	// Use signed!!
	long long int spin_time =
			ratelimit->sleep_spin_time + (buffer->entry_count * buffer->entry_count * buffer->write_queue_entry_count * buffer->write_queue_entry_count);
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

		size_t do_usleep = 0;

		/* If we know how long the spinlock lasts, sleep half the period */
		if (ratelimit->spins_per_us > 0) {
			do_usleep = (size_t) (spin_time / 2 / ratelimit->spins_per_us);

			if (do_usleep < 50) {
				do_usleep = 0;
			}
			else {
				spin_time = spin_time / 2;
			}
		}

		pthread_mutex_unlock(&buffer->ratelimit_mutex);
		uint64_t time_start = rrr_time_get_64();
		long long int spin_time_orig = spin_time;

		// Make sure we don't wrap around
		while (--spin_time > 0) {
			rrr_slow_noop();
		}
		uint64_t time_end = rrr_time_get_64();
		uint64_t time_diff = (time_end - time_start) + 1; // +1 to prevent division by zero
		if (do_usleep) {
			// Max 1s
			rrr_posix_usleep(do_usleep > 1000000 ? 1000000 : 0);
		}
		pthread_mutex_lock(&buffer->ratelimit_mutex);

		long long int current_spins_per_us = spin_time_orig / (int) time_diff;

		if (ratelimit->spins_per_us == 0) {
			ratelimit->spins_per_us = current_spins_per_us;
		}
		else {
			// Give little weight to the new value when updating
			ratelimit->spins_per_us = (ratelimit->spins_per_us * 9 + current_spins_per_us) / 10;
		}
	}

	pthread_mutex_unlock(&buffer->ratelimit_mutex);

#ifdef RRR_FIFO_PROTECTED_BUFFER_RATELIMIT_DEBUG
	uint64_t time = rrr_time_get_64() - ratelimit_in;
	if (time > 0) {
		printf("Ratelimit %p: %" PRIu64 "\tc: %" PRIrrrl "\n", buffer, time, buffer->entry_count);
	}
#endif
}

static void __rrr_fifo_protected_update_ratelimit(struct rrr_fifo_protected *buffer) {
	struct rrr_fifo_protected_ratelimit *ratelimit = &buffer->ratelimit;

	pthread_mutex_lock(&buffer->ratelimit_mutex);

	uint64_t time_now = rrr_time_get_64();

	if (ratelimit->prev_time == 0) {
		ratelimit->prev_time = time_now;
		ratelimit->prev_entry_count = buffer->entry_count + buffer->write_queue_entry_count;
		goto out_unlock;
	}

	// Work every 250ms
	if (time_now - ratelimit->prev_time < 250000) {
		goto out_unlock;
	}

	int entry_diff = (int) (ratelimit->prev_entry_count - buffer->entry_count - buffer->write_queue_entry_count);

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

	ratelimit->sleep_spin_time = (long long int) ((double) ratelimit->sleep_spin_time - (ratelimit->read_write_balance * 10));

	if (ratelimit->sleep_spin_time < 1) {
		ratelimit->sleep_spin_time = 1;
	}
	else if (ratelimit->sleep_spin_time > 10000000000) {
		ratelimit->sleep_spin_time = 10000000000;
	}

	long long int spintime_us = (ratelimit->sleep_spin_time / (ratelimit->spins_per_us + 1));

	RRR_DBG_4("buffer %p read/write balance %f spins %llu (%lli us) spins/us %llu entries %i (do sleep = %i)\n",
			buffer,
			ratelimit->read_write_balance,
			ratelimit->sleep_spin_time,
			spintime_us,
			ratelimit->spins_per_us,
			buffer->entry_count,
			buffer->buffer_do_ratelimit
	);

	ratelimit->prev_time = time_now;
	ratelimit->prev_entry_count = buffer->entry_count + buffer->write_queue_entry_count;

	out_unlock:
	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

int rrr_fifo_protected_with_write_lock_do (
		struct rrr_fifo_protected *buffer,
		int (*callback)(void *arg1, void *arg2),
		void *callback_arg1,
		void *callback_arg2
) {
	int ret = 0;

	__rrr_fifo_protected_write_lock(buffer);
	pthread_cleanup_push(__rrr_fifo_protected_unlock_void, buffer);

	ret = callback(callback_arg1, callback_arg2);
	if (ret != RRR_FIFO_PROTECTED_OK && ret != RRR_FIFO_PROTECTED_GLOBAL_ERR) {
		RRR_BUG("Bug: Unknown return value %i to rrr_fifo_protected_with_write_lock_do\n", ret);
	}

	pthread_cleanup_pop(1);

	return ret;
}

/*
 * This writing method holds the lock for a minimum amount of time, only to
 * update the pointers to the end. To provide memory fence, the data should be
 * allocated and written to inside the callback.
 */
int rrr_fifo_protected_write (
		struct rrr_fifo_protected *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int write_again = 0;

	do {
		struct rrr_fifo_protected_entry *entry = NULL;
		int do_free_callback = 0;

		__rrr_fifo_protected_write_lock(buffer);
		ret = __rrr_fifo_protected_entry_new_unlocked(&entry);
		__rrr_fifo_protected_unlock(buffer);

		if (ret != 0) {
			RRR_MSG_0("Could not allocate entry in rrr_fifo_protected_write\n");
			ret = 1;
			goto loop_out_no_entry_free;
		}

		pthread_cleanup_push(__rrr_fifo_protected_entry_destroy_simple_void, entry);

		uint64_t order = 0;

		__rrr_fifo_protected_entry_lock(entry);
		pthread_cleanup_push(__rrr_fifo_protected_entry_unlock_void, entry);
		ret = callback(&entry->data, &entry->size, &order, callback_arg);
		pthread_cleanup_pop(1);

		__rrr_fifo_protected_write_lock(buffer);
		pthread_cleanup_push(__rrr_fifo_protected_unlock_void, buffer);

		int do_ordered_write = 0;
		int do_drop = 0;

		if ((ret = __rrr_fifo_protected_write_callback_return_check(&do_ordered_write, &write_again, &do_drop, ret)) != 0) {
			goto loop_out_drop;
		}

		if (do_drop) {
			goto loop_out_drop;
		}

		if (entry->data == NULL) {
			RRR_BUG("Data from callback was NULL in rrr_fifo_protected_write, must return DROP\n");
		}

		__rrr_fifo_protected_write_update_pointers (buffer, entry, order, do_ordered_write);
		entry = NULL;

		__rrr_fifo_protected_update_ratelimit(buffer);
		__rrr_fifo_protected_stats_add_written(buffer, 1);

		pthread_mutex_lock(&buffer->ratelimit_mutex);
		if ((ret = rrr_length_inc_err (&buffer->entry_count)) != 0) {
			write_again = 0;
		}
		pthread_mutex_unlock(&buffer->ratelimit_mutex);

		if (ret != 0) {
			__rrr_fifo_protected_clear(buffer);
			goto loop_out_no_drop;
		}

		do_free_callback = 0;

		goto loop_out_no_drop;
		loop_out_drop:
			do_free_callback = 1;
		loop_out_no_drop:
			pthread_cleanup_pop(1);
			pthread_cleanup_pop(do_free_callback);
		loop_out_no_entry_free:
			__rrr_fifo_protected_do_ratelimit(buffer);
	} while (write_again);

	return ret;
}

/*
 * This writing method will write entries to the temporary write queue. This will not block
 * if there are readers or an ordinary writer on the buffer. The read functions will, each time
 * they run, check if there are no other readers, and if so, they will push the delayed entries
 * to the end of the buffer. Some read functions hold write lock anyway, and these will always
 * merge in the write queue. This method may also be used to add entries while already being
 * in write context.
 */
int rrr_fifo_protected_write_delayed (
		struct rrr_fifo_protected *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock (&buffer->write_queue_mutex);

	struct rrr_fifo_protected_entry *entry = NULL;;
	int write_again = 0;

	do {
		if ((__rrr_fifo_protected_entry_new_unlocked(&entry)) != 0) {
			RRR_MSG_0("Could not allocate entry in rrr_fifo_protected_delayed_write\n");
			ret = 1;
			goto out;
		}

		// We support storing the order parameter but the entries will not be
		// ordered while writing
		uint64_t order = 0;

		__rrr_fifo_protected_entry_lock(entry);
		ret = callback(&entry->data, &entry->size, &order, callback_arg);
		__rrr_fifo_protected_entry_unlock(entry);

		entry->order = order;

		if (ret != 0) {
			if ((ret & RRR_FIFO_PROTECTED_WRITE_AGAIN) == RRR_FIFO_PROTECTED_WRITE_AGAIN) {
				if ((ret &= ~RRR_FIFO_PROTECTED_WRITE_AGAIN) != 0) {
					RRR_BUG("BUG: Callback return WRITE_AGAIN along with other return values %i in rrr_fifo_protected_delayed_write\n", ret);
				}
				write_again = 1;
			}
			else if ((ret & RRR_FIFO_PROTECTED_GLOBAL_ERR) == RRR_FIFO_PROTECTED_GLOBAL_ERR) {
				if ((ret &= ~RRR_FIFO_PROTECTED_GLOBAL_ERR) != 0) {
					RRR_BUG("BUG: Callback returned GLOBAL_ERR along with return values %i in rrr_fifo_protected_delayed_write\n", ret);
				}
				goto out;
			}
			else if ((ret & RRR_FIFO_PROTECTED_WRITE_DROP) == RRR_FIFO_PROTECTED_WRITE_DROP) {
				if ((ret &= ~RRR_FIFO_PROTECTED_WRITE_DROP) != 0) {
					RRR_BUG("BUG: Callback returned WRITE_CANCEL along with return values %i in rrr_fifo_protected_delayed_write\n", ret);
				}
				ret = 0;
				goto out;
			}
			else {
				RRR_BUG("Unknown return values %i from callback in rrr_fifo_protected_delayed_write\n", ret);
			}
		}
		else {
			write_again = 0;
		}

		if (entry->data == NULL) {
			RRR_BUG("Data from callback was NULL in rrr_fifo_protected_write\n");
		}

		if (buffer->gptr_write_queue_first == NULL) {
			buffer->gptr_write_queue_last = entry;
			buffer->gptr_write_queue_first = entry;
		}
		else {
			buffer->gptr_write_queue_last->next = entry;
			buffer->gptr_write_queue_last = entry;
		}

		{
			pthread_mutex_lock(&buffer->ratelimit_mutex);
			if ((ret = rrr_length_inc_err (&buffer->write_queue_entry_count)) != 0) {
				write_again = 0;
			}
			pthread_mutex_unlock(&buffer->ratelimit_mutex);

			if (ret != 0) {
				pthread_mutex_unlock (&buffer->write_queue_mutex);
				__rrr_fifo_protected_clear(buffer);
				pthread_mutex_lock (&buffer->write_queue_mutex);
				goto out;
			}

		}

		pthread_mutex_unlock (&buffer->write_queue_mutex);
		__rrr_fifo_protected_do_ratelimit(buffer);
		pthread_mutex_lock (&buffer->write_queue_mutex);

		entry = NULL;
	} while (write_again);


	out:
		pthread_mutex_unlock (&buffer->write_queue_mutex);
		if (entry != NULL) {
			__rrr_fifo_protected_entry_destroy_unlocked(buffer, entry);
		}
		return ret;
}
