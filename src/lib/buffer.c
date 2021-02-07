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

#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include "buffer.h"
#include "log.h"
#include "util/posix.h"
#include "util/slow_noop.h"
#include "util/rrr_time.h"

//#define RRR_FIFO_BUFFER_DEBUG 1

static inline void rrr_fifo_write_lock(struct rrr_fifo_buffer *buffer) {
	while (pthread_rwlock_trywrlock(&buffer->rwlock) != 0) {
		pthread_testcancel();
		rrr_posix_usleep(10);
	}
}

static inline int rrr_fifo_write_trylock(struct rrr_fifo_buffer *buffer) {
	if (pthread_rwlock_trywrlock(&buffer->rwlock) != 0) {
		return 1;
	}
	return 0;
}

static inline void rrr_fifo_read_lock(struct rrr_fifo_buffer *buffer) {
	while (pthread_rwlock_tryrdlock(&buffer->rwlock) != 0) {
		pthread_testcancel();
		rrr_posix_usleep(10);
	}
}

static inline void rrr_fifo_unlock(struct rrr_fifo_buffer *buffer) {
	pthread_rwlock_unlock(&buffer->rwlock);
}

static inline void rrr_fifo_unlock_void(void *arg) {
	rrr_fifo_unlock(arg);
}

#ifdef RRR_FIFO_BUFFER_DEBUG
static void __rrr_fifo_consistency_check(struct rrr_fifo_buffer *buffer) {
	if (	(buffer->gptr_first != NULL && buffer->gptr_last == NULL) ||
			(buffer->gptr_first == NULL && buffer->gptr_last != NULL) ||
			(buffer->gptr_write_queue_first != NULL && buffer->gptr_write_queue_last == NULL) ||
			(buffer->gptr_write_queue_first == NULL && buffer->gptr_write_queue_last != NULL) ||
			(buffer->gptr_last != NULL && buffer->gptr_last->next != NULL) ||
			(buffer->gptr_write_queue_last != NULL && buffer->gptr_write_queue_last->next != NULL) ||
			(buffer->gptr_first != NULL && buffer->gptr_first == buffer->gptr_last && buffer->gptr_first->next != NULL) ||
			(		buffer->gptr_write_queue_first != NULL &&
					buffer->gptr_write_queue_first == buffer->gptr_write_queue_last &&
					buffer->gptr_write_queue_first->next != NULL
			)
	) {
		RRR_BUG("BUG: fifo buffer consistency error");
	}
}

static int __rrr_fifo_verify_counter(struct rrr_fifo_buffer *buffer) {
	int counter = 0;
	int claimed_count = 0;
//	fifo_read_lock(buffer);

	claimed_count = buffer->entry_count;

	struct rrr_fifo_buffer_entry *current = buffer->gptr_first;
	while (current) {
		struct rrr_fifo_buffer_entry *next = current->next;
		counter++;
		current = next;
	}

//	fifo_read_unlock(buffer);

	return (counter != claimed_count);
}

#define RRR_FIFO_BUFFER_CONSISTENCY_CHECK()				\
	__rrr_fifo_consistency_check(buffer);				\
	__rrr_fifo_verify_counter(buffer)

#define RRR_FIFO_BUFFER_CONSISTENCY_CHECK_WRITE_LOCK() 	\
	rrr_fifo_write_lock(buffer);						\
	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();				\
	rrr_fifo_unlock(buffer)

#else

#define RRR_FIFO_BUFFER_CONSISTENCY_CHECK() \
	do { } while (0)
#define RRR_FIFO_BUFFER_CONSISTENCY_CHECK_WRITE_LOCK() \
	do { } while (0)

#endif

#define RRR_FIFO_BUFFER_WITH_STATS_LOCK_DO(action)		\
	pthread_mutex_lock(&buffer->stats_mutex);					\
	action;												\
	pthread_mutex_unlock(&buffer->stats_mutex)

static inline void __rrr_fifo_buffer_stats_add_written (struct rrr_fifo_buffer *buffer, int num) {
	RRR_FIFO_BUFFER_WITH_STATS_LOCK_DO(buffer->stats.total_entries_written += num);
}

static inline void __rrr_fifo_buffer_stats_add_deleted (struct rrr_fifo_buffer *buffer, int num) {
	RRR_FIFO_BUFFER_WITH_STATS_LOCK_DO(buffer->stats.total_entries_deleted += num);
}

void rrr_fifo_buffer_get_stats_populate (
		struct rrr_fifo_buffer_stats *target,
		uint64_t entries_written,
		uint64_t entries_deleted
) {
	target->total_entries_written = entries_written;
	target->total_entries_deleted = entries_deleted;
}

int rrr_fifo_buffer_get_stats (
		struct rrr_fifo_buffer_stats *stats,
		struct rrr_fifo_buffer *buffer
) {
	RRR_FIFO_BUFFER_WITH_STATS_LOCK_DO(*stats = buffer->stats);
	return 0;
}

static void __rrr_fifo_buffer_entry_lock (struct rrr_fifo_buffer_entry *entry) {
	pthread_mutex_lock(&entry->lock);
}

static void __rrr_fifo_buffer_entry_unlock (struct rrr_fifo_buffer_entry *entry) {
	pthread_mutex_unlock(&entry->lock);
}

static void __rrr_fifo_buffer_entry_unlock_void (void *arg) {
	struct rrr_fifo_buffer_entry *entry = arg;
	pthread_mutex_unlock(&entry->lock);
}

// Buffer write lock must be held
static void __rrr_fifo_buffer_entry_destroy_unlocked (
		struct rrr_fifo_buffer *buffer,
		struct rrr_fifo_buffer_entry *entry
) {
	__rrr_fifo_buffer_entry_lock(entry);
	if (entry->data != NULL) {
		buffer->free_entry(entry->data);
	}
	__rrr_fifo_buffer_entry_unlock(entry);
	pthread_mutex_destroy(&entry->lock);
	free(entry);
}

static void __rrr_fifo_buffer_entry_destroy_simple_void (
		void *ptr
) {
	struct rrr_fifo_buffer_entry *entry = ptr;
	pthread_mutex_destroy(&entry->lock);
	free(entry);
}

static void __rrr_fifo_buffer_entry_destroy_data_unlocked (
		struct rrr_fifo_buffer *buffer,
		struct rrr_fifo_buffer_entry *entry
) {
	__rrr_fifo_buffer_entry_lock(entry);
	if (entry->data != NULL) {
		buffer->free_entry(entry->data);
		entry->data = NULL;
	}
	__rrr_fifo_buffer_entry_unlock(entry);
}

static void __rrr_fifo_buffer_entry_release_data_unlocked (
		struct rrr_fifo_buffer_entry *entry
) {
	entry->data = NULL;
	entry->size = 0;
}

// Buffer write lock must be held
static int __rrr_fifo_buffer_entry_new_unlocked (
		struct rrr_fifo_buffer_entry **result
) {
	int ret = 0;

	*result = NULL;

	struct rrr_fifo_buffer_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate entry in __rrr_fifo_buffer_entry_new_unlocked \n");
		ret = 1;
		goto out;
	}

	memset (entry, '\0', sizeof(*entry));

	if (rrr_posix_mutex_init(&entry->lock, 0) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_fifo_buffer_entry_new_unlocked\n");
		ret = 1;
		goto out_free;
	}

	*result = entry;

	goto out;

	out_free:
		free(entry);
	out:
		return ret;
}

// Buffer write lock must be held
static void __rrr_fifo_merge_write_queue_nolock (
		struct rrr_fifo_buffer *buffer
) {
	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	pthread_mutex_lock(&buffer->write_queue_mutex);

	if (buffer->gptr_write_queue_first != NULL) {
		struct rrr_fifo_buffer_entry *first = buffer->gptr_write_queue_first;

		// Write all metadata again to force write while holding buffer write lock
		while (first) {
			// TODO : Unsure if compiler optimizes this away, looks like GCC actually does the writing
			struct rrr_fifo_buffer_entry tmp = *first;
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

		RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

		__rrr_fifo_buffer_stats_add_written(buffer, buffer->write_queue_entry_count);

		pthread_mutex_lock(&buffer->ratelimit_mutex);
		buffer->entry_count += buffer->write_queue_entry_count;
		buffer->write_queue_entry_count = 0;
		pthread_mutex_unlock(&buffer->ratelimit_mutex);
	}

	pthread_mutex_unlock(&buffer->write_queue_mutex);
}

void rrr_fifo_buffer_destroy (
		struct rrr_fifo_buffer *buffer
) {
	rrr_fifo_buffer_clear_with_callback(buffer, NULL, NULL);
	pthread_rwlock_destroy (&buffer->rwlock);
	pthread_mutex_destroy (&buffer->write_queue_mutex);
	pthread_mutex_destroy (&buffer->ratelimit_mutex);
	pthread_mutex_destroy (&buffer->stats_mutex);
	sem_destroy(&buffer->new_data_available);
}

static void __rrr_fifo_default_free (
		void *ptr
) {
	free(ptr);
}

int rrr_fifo_buffer_init (
		struct rrr_fifo_buffer *buffer
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

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->buffer_do_ratelimit = 0;
	buffer->ratelimit.sleep_spin_time = 2000000;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	if (sem_init(&buffer->new_data_available, 1, 0) != 0) {
		goto out_destroy_stats_mutex;
	}

	pthread_rwlock_wrlock(&buffer->rwlock);
	buffer->free_entry = &__rrr_fifo_default_free;
	pthread_rwlock_unlock(&buffer->rwlock);

	goto out;
//	out_destroy_sem:
//		sem_destroy(&buffer->new_data_available);
	out_destroy_stats_mutex:
		pthread_mutex_destroy(&buffer->stats_mutex);
	out_destroy_ratelimit_mutex:
		pthread_mutex_destroy(&buffer->ratelimit_mutex);
	out_destroy_rwlock:
		pthread_rwlock_destroy(&buffer->rwlock);
	out_destroy_write_queue_mutex:
		pthread_mutex_destroy(&buffer->write_queue_mutex);
	out:
		return (ret != 0 ? 1 : 0);
}

int rrr_fifo_buffer_init_custom_free (
		struct rrr_fifo_buffer *buffer,
		void (*custom_free)(void *arg)
) {
	int ret = rrr_fifo_buffer_init(buffer);
	if (ret == 0) {
		pthread_rwlock_wrlock(&buffer->rwlock);
		buffer->free_entry = custom_free;
		pthread_rwlock_unlock(&buffer->rwlock);
	}
	return ret;
}

static void __rrr_fifo_buffer_set_data_available (
		struct rrr_fifo_buffer *buffer
) {
	int sem_status = 0;
	sem_getvalue(&buffer->new_data_available, &sem_status);
	if (sem_status == 0) {
		sem_post(&buffer->new_data_available);
	}
}

static void __rrr_fifo_attempt_write_queue_merge (
		struct rrr_fifo_buffer *buffer
) {
	pthread_mutex_lock(&buffer->ratelimit_mutex);
	if (buffer->write_queue_entry_count == 0) {
		pthread_mutex_unlock(&buffer->ratelimit_mutex);
		return;
	}

	int entry_count = buffer->entry_count;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	// If the buffer is empty, we force a merge with the write queue. If
	// not, we only merge if we happen to obtain a write lock immediately
	if (entry_count == 0) {
		rrr_fifo_write_lock(buffer);
		__rrr_fifo_merge_write_queue_nolock(buffer);
		rrr_fifo_unlock(buffer);
	}
	else if (rrr_fifo_write_trylock(buffer) == 0) {
		__rrr_fifo_merge_write_queue_nolock(buffer);
		rrr_fifo_unlock(buffer);
	}
	else {
		return;
	}

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	__rrr_fifo_buffer_set_data_available(buffer);
}

static inline int rrr_fifo_wait_for_data (
		struct rrr_fifo_buffer *buffer,
		unsigned int wait_milliseconds
) {
	if (wait_milliseconds == 0) {
		return 0;
	}

	uint64_t time_start = rrr_time_get_64();
	uint64_t time_end = time_start + (wait_milliseconds * 1000);

	uint64_t microseconds = time_end % 1000000;
	uint64_t seconds = (time_end - microseconds) / 1000 / 1000;

	struct timespec wait_time;
	wait_time.tv_sec = seconds;
	wait_time.tv_nsec = microseconds * 1000;
	int res = sem_timedwait(&buffer->new_data_available, &wait_time);

	return res;
}

void rrr_fifo_buffer_set_do_ratelimit (
		struct rrr_fifo_buffer *buffer,
		int set
) {
	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->buffer_do_ratelimit = set;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

/*
 * Remove all entries from a buffer
 */
void rrr_fifo_buffer_clear_with_callback (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
) {
	rrr_fifo_write_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	__rrr_fifo_merge_write_queue_nolock(buffer);

	struct rrr_fifo_buffer_entry *entry = buffer->gptr_first;
	int freed_counter = 0;
	while (entry != NULL) {
		struct rrr_fifo_buffer_entry *next = entry->next;
		RRR_DBG_4 ("Buffer %p free entry %p with data %p order %" PRIu64 "\n", buffer, entry, entry->data, entry->order);

		__rrr_fifo_buffer_entry_lock(entry);
		pthread_cleanup_push(__rrr_fifo_buffer_entry_unlock_void, entry);

		int ret_tmp = 0;
		if (callback != NULL && (ret_tmp = callback(callback_data, entry->data, entry->size)) != RRR_FIFO_OK) {
			RRR_BUG("Non-zero return from callback not allowed in fifo_buffer_clear_with_callback, return was %i\n", ret_tmp);
		}

		pthread_cleanup_pop(1);

		__rrr_fifo_buffer_entry_destroy_unlocked(buffer, entry);
		freed_counter++;
		entry = next;
	}

	__rrr_fifo_buffer_stats_add_deleted(buffer, freed_counter);

	RRR_DBG_4 ("Buffer %p freed %i entries\n", buffer, freed_counter);

	buffer->gptr_first = NULL;
	buffer->gptr_last = NULL;
	buffer->entry_count = 0;

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	pthread_cleanup_pop(1);
}

void rrr_fifo_buffer_clear (
		struct rrr_fifo_buffer *buffer
) {
	rrr_fifo_buffer_clear_with_callback(buffer, NULL, NULL);
}

// TODO : Use this in the search function
int rrr_fifo_buffer_search_return_value_process (
		unsigned char *do_keep,
		unsigned char *do_give,
		unsigned char *do_free,
		unsigned char *do_stop,
		int actions
) {
	int err = RRR_FIFO_OK;

	*do_keep = 0;
	*do_give = 0;
	*do_free = 0;
	*do_stop = 0;

	if (actions == RRR_FIFO_SEARCH_KEEP) { // Just a 0
		*do_keep = 1;
		goto out;
	}
	if ((actions & RRR_FIFO_CALLBACK_ERR) != 0) {
		err = RRR_FIFO_CALLBACK_ERR;
		goto out;
	}
	if ((actions & RRR_FIFO_SEARCH_GIVE) != 0) {
		*do_give = 1;
		if ((actions & RRR_FIFO_SEARCH_FREE) != 0) {
			*do_free = 1;
		}
	}
	if ((actions & RRR_FIFO_SEARCH_STOP) != 0) {
		*do_stop = 1;
	}

	if (*do_free == 0 && *do_stop == 0) {
		RRR_BUG("Unknown return value %i to rrr_fifo_buffer_search_return_value_process\n");
	}

	out:
	return err;
}

/*
 * Search entries and act according to the return value of the callback function. We
 * can delete entries or stop looping. See buffer.h . The callback function is expected
 * to take control of the memory of an entry which fifo_search deletes, if not
 * it will be leaked unless the callback also tells us to free the data using FIFO_SEARCH_FREE.
 */
int rrr_fifo_buffer_search (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		unsigned int wait_milliseconds
) {
	__rrr_fifo_attempt_write_queue_merge(buffer);
	rrr_fifo_wait_for_data(buffer, wait_milliseconds);

	int err = 0;

	rrr_fifo_write_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	__rrr_fifo_merge_write_queue_nolock(buffer);

	int cleared_entries = 0;

	struct rrr_fifo_buffer_entry *entry;
	struct rrr_fifo_buffer_entry *next;
	struct rrr_fifo_buffer_entry *prev = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = next) {
		RRR_DBG_4("Buffer %p search loop entry %p next %p prev %p\n", buffer, entry, entry->next, prev);
		next = entry->next;

		int did_something = 0;
		int actions = 0;

		__rrr_fifo_buffer_entry_lock(entry);
		actions = callback(callback_data, entry->data, entry->size);
		__rrr_fifo_buffer_entry_unlock(entry);

		if (actions == RRR_FIFO_SEARCH_KEEP) { // Just a 0
			goto keep;
		}
		if ((actions & RRR_FIFO_CALLBACK_ERR) != 0) {
			err = RRR_FIFO_CALLBACK_ERR;
			break;
		}
		if ((actions & RRR_FIFO_SEARCH_GIVE) != 0) {
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

			// If we are not asked to free, zero out the pointer to stop it from being
			// destroyed by entry destroy functions
			if ((actions & RRR_FIFO_SEARCH_FREE) == 0) {
				entry->data = NULL;
			}

			__rrr_fifo_buffer_entry_destroy_unlocked(buffer, entry);

			entry = prev;
			did_something = 1;
		}
		if ((actions & RRR_FIFO_SEARCH_STOP) != 0) {
			break;
		}
		else if (did_something == 0) {
			RRR_BUG ("Bug: Unkown return value %i to fifo_search\n", actions);
		}

		keep:
		prev = entry;
	}

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	__rrr_fifo_buffer_stats_add_deleted(buffer, cleared_entries);

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count -= cleared_entries;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	if (buffer->gptr_first != NULL) {
		__rrr_fifo_buffer_set_data_available(buffer);
	}

	pthread_cleanup_pop(1);

	return err;
}

static int __rrr_fifo_buffer_write_callback_return_check (
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

	if ((ret_to_check & RRR_FIFO_WRITE_ORDERED) == RRR_FIFO_WRITE_ORDERED) {
		if ((ret_to_check & ~(RRR_FIFO_WRITE_AGAIN|RRR_FIFO_WRITE_ORDERED|RRR_FIFO_WRITE_DROP)) != 0) {
			RRR_BUG("BUG: Callback return WRITE_ORDERED along with other illegal return values %i in __rrr_fifo_buffer_write_callback_return_check\n", ret_to_check);
		}
		*do_ordered_write = 1;
	}

	if ((ret_to_check & RRR_FIFO_WRITE_AGAIN) == RRR_FIFO_WRITE_AGAIN) {
		if ((ret_to_check & ~(RRR_FIFO_WRITE_AGAIN|RRR_FIFO_WRITE_ORDERED|RRR_FIFO_WRITE_DROP)) != 0) {
			RRR_BUG("BUG: Callback return WRITE_AGAIN along with other illegal return values %i in __rrr_fifo_buffer_write_callback_return_check\n", ret_to_check);
		}
		*write_again = 1;
	}

	if ((ret_to_check & RRR_FIFO_GLOBAL_ERR) == RRR_FIFO_GLOBAL_ERR) {
		if ((ret_to_check & ~(RRR_FIFO_GLOBAL_ERR)) != 0) {
			RRR_BUG("BUG: Callback returned GLOBAL_ERR along with return values %i in __rrr_fifo_buffer_write_callback_return_check\n", ret_to_check);
		}
		ret = 1;
		goto out;
	}

	if ((ret_to_check & RRR_FIFO_WRITE_DROP) == RRR_FIFO_WRITE_DROP) {
		if ((ret_to_check &= ~(RRR_FIFO_WRITE_DROP|RRR_FIFO_WRITE_AGAIN)) != 0) {
			RRR_BUG("BUG: Callback returned WRITE_DROP along with return values %i in __rrr_fifo_buffer_write_callback_return_check\n", ret_to_check);
		}
		*do_drop = 1;
		goto out;
	}

	ret_to_check &= ~(RRR_FIFO_WRITE_AGAIN|RRR_FIFO_WRITE_ORDERED|RRR_FIFO_WRITE_DROP);

	if (ret_to_check != 0) {
		RRR_BUG("Unknown return values %i from callback in __rrr_fifo_buffer_write_callback_return_check\n", ret_to_check);
	}

	out:
	return ret;
}

static void __rrr_fifo_buffer_write_update_pointers (
		struct rrr_fifo_buffer *buffer,
		struct rrr_fifo_buffer_entry *entry,
		uint64_t order,
		int do_ordered_write
) {
	struct rrr_fifo_buffer_entry *pos = buffer->gptr_first;

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
			struct rrr_fifo_buffer_entry *prev = NULL;
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

static int __rrr_fifo_buffer_search_and_replace_call_again (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_fifo_buffer_entry *entry = NULL;

	int do_loop = 1;

	while (ret == 0 && do_loop) {
		if ((__rrr_fifo_buffer_entry_new_unlocked(&entry)) != 0) {
			RRR_MSG_0("Could not allocate entry in __rrr_fifo_buffer_search_and_replace_call_again\n");
			ret = 1;
			goto out;
		}

		int do_drop = 0;

		pthread_cleanup_push(__rrr_fifo_buffer_entry_destroy_simple_void, entry);

		uint64_t order = 0;

		__rrr_fifo_buffer_entry_lock(entry);
		pthread_cleanup_push(__rrr_fifo_buffer_entry_unlock_void, entry);
		ret = callback(&entry->data, &entry->size, &order, callback_arg);
		pthread_cleanup_pop(1);

		int do_ordered_write = 0;

		if ((ret = __rrr_fifo_buffer_write_callback_return_check(&do_ordered_write, &do_loop, &do_drop, ret)) != 0) {
			do_drop = 1;
			goto loop_out;
		}

		if (!do_drop) {
			if (entry->data == NULL) {
				RRR_BUG("Data from callback was NULL in rrr_fifo_buffer_write, must return DROP\n");
			}
			__rrr_fifo_buffer_write_update_pointers(buffer, entry, order, 0);
		}

		loop_out:
		pthread_cleanup_pop(do_drop);
	}

	out:
	return ret;
}

/*
 * Iterates the buffer and allows callback to modify data pointers of the
 * buffer entries as well as deleting entries. After the iteration, the
 * callback is called again (if requested) like with the standard write
 * function. The write lock of the buffer is held the whole time.
 *
 * This behavior allows the application to, when inserting an entry, first
 * to check if the new entry should replace and old one (like if it's ID
 * already exists and IDs should be unique), and if the ID did not exist
 * in the buffer, insert the entry at the end.
 *
 * If call again after looping is specified, this will be done also if STOP
 * is returned during iteration. If the callback don't wish to write anything
 * at the end, it should then return DROP|STOP.
 */
int rrr_fifo_buffer_search_and_replace (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg,
		unsigned int wait_milliseconds,
		int call_again_after_looping
) {
	__rrr_fifo_attempt_write_queue_merge(buffer);
	rrr_fifo_wait_for_data(buffer, wait_milliseconds);

	int ret = 0;

	rrr_fifo_write_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	__rrr_fifo_merge_write_queue_nolock(buffer);

	int cleared_entries = 0;
	int new_entries = 0;

	struct rrr_fifo_buffer_entry *entry;
	struct rrr_fifo_buffer_entry *next;
	struct rrr_fifo_buffer_entry *prev = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = next) {
		RRR_DBG_4("Buffer %p search_and_replace loop entry %p data %p next %p prev %p\n",
				buffer, entry, entry->data, entry->next, prev);
		next = entry->next;

		int did_something = 0;
		int actions = 0;

		__rrr_fifo_buffer_entry_lock(entry);

		char *data = entry->data;
		unsigned long int size = entry->size;
		uint64_t order = entry->order;

		actions = callback(&data, &size, &order, callback_arg);

		__rrr_fifo_buffer_entry_unlock(entry);

		if (actions == RRR_FIFO_SEARCH_KEEP) { // Just a 0
			goto keep;
		}
		if ((actions & RRR_FIFO_CALLBACK_ERR) != 0) {
			ret = RRR_FIFO_CALLBACK_ERR;
			break;
		}
		if ((actions & (RRR_FIFO_SEARCH_REPLACE|RRR_FIFO_SEARCH_GIVE)) != 0 ) {
			// If we are not asked to free, zero out the pointer to stop it from being
			// destroyed by entry destroy functions
			if ((actions & RRR_FIFO_SEARCH_FREE) == 0) {
				entry->data = NULL;
			}

			if ((actions & (RRR_FIFO_SEARCH_GIVE)) != 0 ) {
				if ((actions & (RRR_FIFO_SEARCH_REPLACE)) != 0 ) {
					RRR_BUG("BUG: Both GIVE and REPLACE returned to fifo_buffer_search_and_replace\n");
				}

				if (entry == buffer->gptr_first) {
					buffer->gptr_first = entry->next;
				}
				if (entry == buffer->gptr_last) {
					buffer->gptr_last = prev;
				}
				if (prev != NULL) {
					prev->next = entry->next;
				}

				__rrr_fifo_buffer_entry_destroy_unlocked(buffer, entry);

				cleared_entries++;
			}
			else {
				if (entry->data == data) {
					RRR_BUG("BUG: Callback of fifo_buffer_search_and_replace tells us to replace, but the data pointer did not change\n");
				}

				__rrr_fifo_buffer_entry_destroy_data_unlocked(buffer, entry);

				entry->data = data;
				entry->size = size;
				entry->order = order;

				cleared_entries++;
				new_entries++;
			}

			entry = prev;
			did_something = 1;
		}
		if ((actions & RRR_FIFO_SEARCH_STOP) != 0) {
			break;
		}
		else if (did_something == 0) {
			RRR_BUG ("Bug: Unknown return value %i to fifo_buffer_search_and_replace\n", actions);
		}

		keep:
		prev = entry;
	}

	if (ret == RRR_FIFO_OK && call_again_after_looping) {
		ret = __rrr_fifo_buffer_search_and_replace_call_again(buffer, callback, callback_arg);
	}

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	__rrr_fifo_buffer_stats_add_written(buffer, new_entries);
	__rrr_fifo_buffer_stats_add_deleted(buffer, cleared_entries);

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count -= cleared_entries;
	buffer->entry_count += new_entries;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	if (buffer->gptr_first != NULL) {
		__rrr_fifo_buffer_set_data_available(buffer);
	}

	pthread_cleanup_pop(1);

	return ret;
}

/*
 * This reading method holds a write lock for a minimum amount of time by
 * taking control of the start of the queue making it inaccessible to
 * others. The callback function must store the data pointer or free it.
 */
int rrr_fifo_buffer_read_clear_forward (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		unsigned int wait_milliseconds
) {
	rrr_fifo_wait_for_data(buffer, wait_milliseconds);

	int ret = RRR_FIFO_OK;

	struct rrr_fifo_buffer_entry *last_element = NULL;
	struct rrr_fifo_buffer_entry *current = NULL;
	struct rrr_fifo_buffer_entry *stop = NULL;
	int max_counter = RRR_FIFO_MAX_READS;

	rrr_fifo_write_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	__rrr_fifo_merge_write_queue_nolock(buffer);

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

	if (buffer->gptr_first != NULL) {
		__rrr_fifo_buffer_set_data_available(buffer);
	}

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	pthread_cleanup_pop(1);

	int processed_entries = 0;
	while (current != stop) {
		struct rrr_fifo_buffer_entry *next = NULL;

		int ret_tmp = 0;

		// Don't access entry pointers outside lock
		{
			rrr_fifo_read_lock(buffer);
			pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

			__rrr_fifo_buffer_entry_lock(current);
			pthread_cleanup_push(__rrr_fifo_buffer_entry_unlock_void, current);

			next = current->next;

			ret_tmp = callback(callback_data, current->data, current->size);

			pthread_cleanup_pop(1);
			pthread_cleanup_pop(1);
		}

		processed_entries++;

		if (ret_tmp != 0) {
			{
				rrr_fifo_write_lock(buffer);
				pthread_cleanup_push(rrr_fifo_unlock_void, buffer);
				if ((ret_tmp & RRR_FIFO_SEARCH_FREE) != 0) {
					// Callback wants us to free memory
					ret_tmp = ret_tmp & ~(RRR_FIFO_SEARCH_FREE);
					__rrr_fifo_buffer_entry_destroy_data_unlocked(buffer, current);
				}
				else {
					__rrr_fifo_buffer_entry_release_data_unlocked(current);
				}
				pthread_cleanup_pop(1);
			}

			if ((ret_tmp & (RRR_FIFO_SEARCH_GIVE)) != 0) {
				RRR_BUG("Bug: FIFO_SEARCH_GIVE returned to fifo_read_clear_forward, we always GIVE by default\n");
			}
			if ((ret_tmp & RRR_FIFO_CALLBACK_ERR) != 0) {
				// Callback will free the memory also on error, unless FIFO_SEARCH_FREE is specified
				ret |= RRR_FIFO_CALLBACK_ERR;
			}
			if ((ret_tmp & RRR_FIFO_GLOBAL_ERR) != 0) {
				// Callback will free the memory also on error, unless FIFO_SEARCH_FREE is specified
				ret |= RRR_FIFO_GLOBAL_ERR;
			}
			if ((ret_tmp & (RRR_FIFO_SEARCH_STOP|RRR_FIFO_CALLBACK_ERR|RRR_FIFO_GLOBAL_ERR)) != 0) {
				// Stop processing and put the rest back into the buffer
				{
					rrr_fifo_write_lock(buffer);
					pthread_cleanup_push(rrr_fifo_unlock_void, buffer);
					struct rrr_fifo_buffer_entry *new_first = next;

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

					ret = ret_tmp & ~(RRR_FIFO_SEARCH_STOP);

					__rrr_fifo_buffer_entry_destroy_unlocked(buffer, current);
					pthread_cleanup_pop(1);
				}

				break;
			}
			ret_tmp &= ~(RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE|RRR_FIFO_SEARCH_STOP|RRR_FIFO_CALLBACK_ERR|RRR_FIFO_GLOBAL_ERR);
			if (ret_tmp != 0) {
				RRR_BUG("Unknown flags %i returned to fifo_read_clear_forward\n", ret_tmp);
			}
		}

		{
			rrr_fifo_write_lock(buffer);
			// Don't free data
			__rrr_fifo_buffer_entry_release_data_unlocked(current);
			__rrr_fifo_buffer_entry_destroy_unlocked(buffer, current);
			rrr_fifo_unlock(buffer);
		}

		current = next;
	}

	__rrr_fifo_buffer_stats_add_deleted(buffer, processed_entries);

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	buffer->entry_count -= processed_entries;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

#ifdef FIFO_DEBUG_COUNTER
	if (fifo_verify_counter(buffer) != 0) {
		RRR_BUG("Buffer size mismatch\n");
	}
#endif /* FIFO_DEBUG_COUNTER */

	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time. The callback function must not free the data or store it's pointer.
 * This function does not check FIFO_MAX_READS.
 */
int rrr_fifo_buffer_read (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(RRR_FIFO_READ_CALLBACK_ARGS),
		void *callback_data,
		unsigned int wait_milliseconds
) {
	rrr_fifo_wait_for_data(buffer, wait_milliseconds);
	__rrr_fifo_attempt_write_queue_merge(buffer);

	int ret = RRR_FIFO_OK;

	rrr_fifo_read_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	struct rrr_fifo_buffer_entry *first = buffer->gptr_first;
	while (first != NULL) {
		int ret_tmp = 0;

		__rrr_fifo_buffer_entry_lock(first);
		ret_tmp = callback(callback_data, first->data, first->size);
		__rrr_fifo_buffer_entry_unlock(first);

		if (ret_tmp != 0) {
			if ((ret_tmp & RRR_FIFO_SEARCH_STOP) != 0) {
				ret |= (ret_tmp & ~RRR_FIFO_SEARCH_STOP);
				break;
			}
			else if ((ret_tmp & (RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE)) != 0) {
				RRR_BUG("Bug: FIFO_SEARCH_GIVE or FIFO_SEARCH_FREE returned to fifo_read\n");
			}
			else if ((ret_tmp & RRR_FIFO_GLOBAL_ERR) != 0) {
				ret = RRR_FIFO_GLOBAL_ERR;
				break;
			}
			else {
				ret |= ret_tmp;
			}

			ret_tmp &= ~(RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE|RRR_FIFO_SEARCH_STOP|RRR_FIFO_CALLBACK_ERR|RRR_FIFO_GLOBAL_ERR);
			if (ret_tmp != 0) {
				RRR_BUG("Unknown flags %i returned to fifo_read\n", ret_tmp);
			}
		}
		first = first->next;
	}

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	if (buffer->gptr_first != NULL) {
		__rrr_fifo_buffer_set_data_available(buffer);
	}

	pthread_cleanup_pop(1);

	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time. The callback function must not free the data or store it's pointer.
 * Only elements with an order value higher than minimum_order are read. If the
 * callback function produces an error, we stop.
 */

int rrr_fifo_buffer_read_minimum (
		struct rrr_fifo_buffer *buffer,
		struct rrr_fifo_buffer_entry *last_element,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		uint64_t minimum_order,
		unsigned int wait_milliseconds
) {
	rrr_fifo_wait_for_data(buffer, wait_milliseconds);
	__rrr_fifo_attempt_write_queue_merge(buffer);

	int res = 0;

	rrr_fifo_read_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	struct rrr_fifo_buffer_entry *first = buffer->gptr_first;

	int processed_entries = 0;
	while (first != NULL) {
		if (first->order > minimum_order) {
			int res_ = 0;

			__rrr_fifo_buffer_entry_lock(first);
			res_ = callback(callback_data, first->data, first->size);
			__rrr_fifo_buffer_entry_unlock(first);

			if (++processed_entries == RRR_FIFO_MAX_READS || first == last_element) {
				break;
			}
			if (res_ == RRR_FIFO_OK) {
				// Do nothing
			}
			else if ((res_ & RRR_FIFO_SEARCH_STOP) != 0) {
				res = res_ & ~(RRR_FIFO_SEARCH_STOP);
				break;
			}
			else if ((res_ & (RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE)) != 0) {
				RRR_BUG("Bug: FIFO_SEARCH_GIVE or FIFO_SEARCH_FREE returned to fifo_read_minimum\n");
			}
			else {
				res = res_;
				break;
			}
		}

		first = first->next;
	}

	RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

	if (buffer->gptr_first != NULL) {
		__rrr_fifo_buffer_set_data_available(buffer);
	}

	pthread_cleanup_pop(1);

	return (res != 0 ? res : RRR_FIFO_OK);
}

static void __rrr_fifo_buffer_do_ratelimit(struct rrr_fifo_buffer *buffer) {
	if (!buffer->buffer_do_ratelimit) {
		return;
	}

	pthread_mutex_lock(&buffer->ratelimit_mutex);

	struct rrr_fifo_buffer_ratelimit *ratelimit = &buffer->ratelimit;

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
		uint64_t time_start = rrr_time_get_64();
		long long int spin_time_orig = spin_time;

		// Make sure we don't wrap around
		while (--spin_time > 0) {
			rrr_slow_noop();
		}
		uint64_t time_end = rrr_time_get_64();
		uint64_t time_diff = (time_end - time_start) + 1; // +1 to prevent division by zero
		if (do_usleep) {
			rrr_posix_usleep(do_usleep);
		}
		pthread_mutex_lock(&buffer->ratelimit_mutex);

		long long int current_spins_per_us = spin_time_orig / time_diff;

		if (ratelimit->spins_per_us == 0) {
			ratelimit->spins_per_us = current_spins_per_us;
		}
		else {
			// Give little weight to the new value when updating
			ratelimit->spins_per_us = (ratelimit->spins_per_us * 9 + current_spins_per_us) / 10;
		}
	}

	pthread_mutex_unlock(&buffer->ratelimit_mutex);
}

static void __rrr_fifo_buffer_update_ratelimit(struct rrr_fifo_buffer *buffer) {
	struct rrr_fifo_buffer_ratelimit *ratelimit = &buffer->ratelimit;

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

	int entry_diff = ratelimit->prev_entry_count - buffer->entry_count - buffer->write_queue_entry_count;

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

	RRR_DBG_4("Buffer %p read/write balance %f spins %llu (%llu us) spins/us %llu entries %i (do sleep = %i)\n",
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

int rrr_fifo_buffer_with_write_lock_do (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(void *arg1, void *arg2),
		void *callback_arg1,
		void *callback_arg2
) {
	int ret = 0;

	rrr_fifo_write_lock(buffer);
	pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

	ret = callback(callback_arg1, callback_arg2);
	if (ret != RRR_FIFO_OK && ret != RRR_FIFO_GLOBAL_ERR) {
		RRR_BUG("Bug: Unknown return value %i to rrr_fifo_buffer_with_write_lock_do\n", ret);
	}

	pthread_cleanup_pop(1);

	return ret;
}

/*
 * This writing method holds the lock for a minimum amount of time, only to
 * update the pointers to the end. To provide memory fence, the data should be
 * allocated and written to inside the callback.
 */
int rrr_fifo_buffer_write (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int write_again = 0;

	int entry_count_before = 0;
	int entry_count_after = 0;

	pthread_mutex_lock(&buffer->ratelimit_mutex);
	entry_count_before = buffer->entry_count;
	pthread_mutex_unlock(&buffer->ratelimit_mutex);

	do {
		struct rrr_fifo_buffer_entry *entry = NULL;
		int do_free_entry = 0;

		rrr_fifo_write_lock(buffer);
		pthread_cleanup_push(rrr_fifo_unlock_void, buffer);

		if ((__rrr_fifo_buffer_entry_new_unlocked(&entry)) != 0) {
			RRR_MSG_0("Could not allocate entry in rrr_fifo_buffer_write\n");
			ret = 1;
			goto loop_out_no_entry_free;
		}

		pthread_cleanup_push(__rrr_fifo_buffer_entry_destroy_simple_void, entry);

		uint64_t order = 0;

		__rrr_fifo_buffer_entry_lock(entry);
		pthread_cleanup_push(__rrr_fifo_buffer_entry_unlock_void, entry);
		ret = callback(&entry->data, &entry->size, &order, callback_arg);
		pthread_cleanup_pop(1);

		int do_ordered_write = 0;
		int do_drop = 0;

		if ((ret = __rrr_fifo_buffer_write_callback_return_check(&do_ordered_write, &write_again, &do_drop, ret)) != 0) {
			goto loop_out_drop;
		}

		if (do_drop) {
			goto loop_out_drop;
		}

		if (entry->data == NULL) {
			RRR_BUG("Data from callback was NULL in rrr_fifo_buffer_write, must return DROP\n");
		}

		RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

		__rrr_fifo_buffer_write_update_pointers (buffer, entry, order, do_ordered_write);
		entry = NULL;

		RRR_FIFO_BUFFER_CONSISTENCY_CHECK();

		__rrr_fifo_buffer_set_data_available(buffer);
		__rrr_fifo_buffer_update_ratelimit(buffer);
		__rrr_fifo_buffer_stats_add_written(buffer, 1);

		pthread_mutex_lock(&buffer->ratelimit_mutex);
		buffer->entry_count++;
		entry_count_after = buffer->entry_count;
		pthread_mutex_unlock(&buffer->ratelimit_mutex);

		do_free_entry = 0;

		goto loop_out_no_drop;
		loop_out_drop:
			do_free_entry = 1;
		loop_out_no_drop:
			pthread_cleanup_pop(do_free_entry);
		loop_out_no_entry_free:
			pthread_cleanup_pop(1);

		__rrr_fifo_buffer_do_ratelimit(buffer);
	} while (write_again);

	if (entry_count_before != 0 || entry_count_after != 0) {
		RRR_DBG_4("buffer %p write loop complete, %i entries before %i after writing (some might have been removed)\n",
				buffer, entry_count_before, entry_count_after);
	}

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
int rrr_fifo_buffer_write_delayed (
		struct rrr_fifo_buffer *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg
) {
	int ret = 0;

	pthread_mutex_lock (&buffer->write_queue_mutex);

	struct rrr_fifo_buffer_entry *entry = NULL;;
	int write_again = 0;

	do {
		if ((__rrr_fifo_buffer_entry_new_unlocked(&entry)) != 0) {
			RRR_MSG_0("Could not allocate entry in rrr_fifo_buffer_delayed_write\n");
			ret = 1;
			goto out;
		}

		// We support storing the order parameter but the entries will not be
		// ordered while writing
		uint64_t order = 0;

		__rrr_fifo_buffer_entry_lock(entry);
		ret = callback(&entry->data, &entry->size, &order, callback_arg);
		__rrr_fifo_buffer_entry_unlock(entry);

		entry->order = order;

		if (ret != 0) {
			if ((ret & RRR_FIFO_WRITE_AGAIN) == RRR_FIFO_WRITE_AGAIN) {
				if ((ret &= ~RRR_FIFO_WRITE_AGAIN) != 0) {
					RRR_BUG("BUG: Callback return WRITE_AGAIN along with other return values %i in rrr_fifo_buffer_delayed_write\n", ret);
				}
				write_again = 1;
			}
			else if ((ret & RRR_FIFO_GLOBAL_ERR) == RRR_FIFO_GLOBAL_ERR) {
				if ((ret &= ~RRR_FIFO_GLOBAL_ERR) != 0) {
					RRR_BUG("BUG: Callback returned GLOBAL_ERR along with return values %i in rrr_fifo_buffer_delayed_write\n", ret);
				}
				goto out;
			}
			else if ((ret & RRR_FIFO_WRITE_DROP) == RRR_FIFO_WRITE_DROP) {
				if ((ret &= ~RRR_FIFO_WRITE_DROP) != 0) {
					RRR_BUG("BUG: Callback returned WRITE_CANCEL along with return values %i in rrr_fifo_buffer_delayed_write\n", ret);
				}
				ret = 0;
				goto out;
			}
			else {
				RRR_BUG("Unknown return values %i from callback in rrr_fifo_buffer_delayed_write\n", ret);
			}
		}
		else {
			write_again = 0;
		}

		if (entry->data == NULL) {
			RRR_BUG("Data from callback was NULL in rrr_fifo_buffer_write\n");
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
			buffer->write_queue_entry_count++;
			pthread_mutex_unlock(&buffer->ratelimit_mutex);
		}

		// Can't do this here, might deadlock (many call delayed_write while holding)
		// the write lock
		// RRR_FIFO_BUFFER_CONSISTENCY_CHECK_WRITE_LOCK();

		pthread_mutex_unlock (&buffer->write_queue_mutex);
		__rrr_fifo_buffer_do_ratelimit(buffer);
		pthread_mutex_lock (&buffer->write_queue_mutex);

		entry = NULL;
	} while (write_again);


	out:
		pthread_mutex_unlock (&buffer->write_queue_mutex);
		if (entry != NULL) {
			__rrr_fifo_buffer_entry_destroy_unlocked(buffer, entry);
		}
		return ret;
}
