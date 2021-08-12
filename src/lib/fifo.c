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

#include "fifo.h"
#include "log.h"
#include "allocator.h"
#include "util/posix.h"
#include "util/slow_noop.h"
#include "util/rrr_time.h"

static void __rrr_fifo_entry_destroy (
		struct rrr_fifo *buffer,
		struct rrr_fifo_entry *entry
) {
	if (entry->data != NULL) {
		buffer->free_entry(entry->data);
	}
	rrr_free(entry);
}

static void __rrr_fifo_entry_destroy_simple_void (
		void *ptr
) {
	struct rrr_fifo_entry *entry = ptr;
	rrr_free(entry);
}

static void __rrr_fifo_entry_destroy_data (
		struct rrr_fifo *buffer,
		struct rrr_fifo_entry *entry
) {
	if (entry->data != NULL) {
		buffer->free_entry(entry->data);
		entry->data = NULL;
	}
}

static void __rrr_fifo_entry_release_data (
		struct rrr_fifo_entry *entry
) {
	entry->data = NULL;
	entry->size = 0;
}

static int __rrr_fifo_entry_new (
		struct rrr_fifo_entry **result
) {
	int ret = 0;

	*result = NULL;

	struct rrr_fifo_entry *entry = rrr_allocate(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate entry in __rrr_fifo_entry_new \n");
		ret = 1;
		goto out;
	}

	memset (entry, '\0', sizeof(*entry));

	*result = entry;

	goto out;

//	out_free:
//		rrr_free(entry);
	out:
		return ret;
}

void rrr_fifo_destroy (
		struct rrr_fifo *buffer
) {
	rrr_fifo_clear_with_callback(buffer, NULL, NULL);
}

static void __rrr_fifo_default_free (
		void *ptr
) {
	rrr_free(ptr);
}

int rrr_fifo_init (
		struct rrr_fifo *buffer
) {
	memset (buffer, '\0', sizeof(*buffer));

	buffer->free_entry = &__rrr_fifo_default_free;

	return 0;
}

int rrr_fifo_init_custom_free (
		struct rrr_fifo *buffer,
		void (*custom_free)(void *arg)
) {
	int ret = rrr_fifo_init(buffer);
	buffer->free_entry = custom_free;
	return ret;
}

/*
 * With fifo_read_clear_with_callback, the callback function MUST
 * handle ALL entries as we cannot add elements back in this
 * case, the callback function may simply write them back
 * using one of the write functions as no locks are active
 * when the callback function is run. If the callback takes ownership
 * of the data or frees it, the data pointer must be set to NULL.
 *
 * Callbacks of fifo_search may return these values to control when
 * to stop or when to delete entries (values can be ORed except for
 * the error value). Functions return 0 on success and 1 on error. If
 * the callback of fifo_search returns FIFO_SEARCH_ERR, the search
 * is stopped and fifo_search returns 1.
 *
 * To count elements, a counter may be placed in a custom struct pointed
 * to by the fifo_callback_data struct, and the callback has to do the
 * counting.
 */
void rrr_fifo_clear_with_callback (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_CLEAR_CALLBACK_ARGS),
		void *callback_data
) {
	struct rrr_fifo_entry *entry = buffer->gptr_first;
	int freed_counter = 0;
	while (entry != NULL) {
		struct rrr_fifo_entry *next = entry->next;
		RRR_DBG_4 ("buffer %p free entry %p with data %p order %" PRIu64 "\n", buffer, entry, entry->data, entry->order);

		int ret_tmp = 0;
		if (callback != NULL && (ret_tmp = callback(callback_data, &entry->data, entry->size)) != RRR_FIFO_OK) {
			RRR_BUG("Non-zero return from callback not allowed in fifo_clear_with_callback, return was %i\n", ret_tmp);
		}

		__rrr_fifo_entry_destroy(buffer, entry);

		freed_counter++;
		entry = next;
	}

	RRR_DBG_4 ("buffer %p freed %i entries\n", buffer, freed_counter);

	buffer->gptr_first = NULL;
	buffer->gptr_last = NULL;
	buffer->entry_count = 0;
}

void rrr_fifo_clear (
		struct rrr_fifo *buffer
) {
	rrr_fifo_clear_with_callback(buffer, NULL, NULL);
}

// TODO : Use this in the search function
int rrr_fifo_search_return_value_process (
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
		RRR_BUG("BUG: Unknown return values to rrr_fifo_search_return_value_process\n");
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
int rrr_fifo_search (
		struct rrr_fifo *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
) {
	int ret = 0;

	if (rrr_fifo_get_entry_count(buffer) == 0) {
		goto out;
	}

	rrr_length cleared_entries = 0;

	struct rrr_fifo_entry *entry;
	struct rrr_fifo_entry *next;
	struct rrr_fifo_entry *prev = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = next) {
		RRR_DBG_4("buffer %p search loop entry %p next %p prev %p\n", buffer, entry, entry->next, prev);
		next = entry->next;

		int did_something = 0;
		int actions = 0;

		actions = callback(callback_data, entry->data, entry->size);

		if (actions == RRR_FIFO_SEARCH_KEEP) { // Just a 0
			goto keep;
		}
		if ((actions & RRR_FIFO_CALLBACK_ERR) != 0) {
			ret = RRR_FIFO_CALLBACK_ERR;
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

			rrr_length_inc_bug(&cleared_entries);

			// If we are not asked to free, zero out the pointer to stop it from being
			// destroyed by entry destroy functions
			if ((actions & RRR_FIFO_SEARCH_FREE) == 0) {
				entry->data = NULL;
			}

			__rrr_fifo_entry_destroy(buffer, entry);

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

	rrr_length_sub_bug (&buffer->entry_count, cleared_entries);

	out:
	return ret;
}

static int __rrr_fifo_write_callback_return_check (
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
			RRR_BUG("BUG: Callback return WRITE_ORDERED along with other illegal return values %i in __rrr_fifo_write_callback_return_check\n", ret_to_check);
		}
		*do_ordered_write = 1;
	}

	if ((ret_to_check & RRR_FIFO_WRITE_AGAIN) == RRR_FIFO_WRITE_AGAIN) {
		if ((ret_to_check & ~(RRR_FIFO_WRITE_AGAIN|RRR_FIFO_WRITE_ORDERED|RRR_FIFO_WRITE_DROP)) != 0) {
			RRR_BUG("BUG: Callback return WRITE_AGAIN along with other illegal return values %i in __rrr_fifo_write_callback_return_check\n", ret_to_check);
		}
		*write_again = 1;
	}

	if ((ret_to_check & RRR_FIFO_GLOBAL_ERR) == RRR_FIFO_GLOBAL_ERR) {
		if ((ret_to_check & ~(RRR_FIFO_GLOBAL_ERR)) != 0) {
			RRR_BUG("BUG: Callback returned GLOBAL_ERR along with return values %i in __rrr_fifo_write_callback_return_check\n", ret_to_check);
		}
		ret = 1;
		goto out;
	}

	if ((ret_to_check & RRR_FIFO_WRITE_DROP) == RRR_FIFO_WRITE_DROP) {
		if ((ret_to_check &= ~(RRR_FIFO_WRITE_DROP|RRR_FIFO_WRITE_AGAIN)) != 0) {
			RRR_BUG("BUG: Callback returned WRITE_DROP along with return values %i in __rrr_fifo_write_callback_return_check\n", ret_to_check);
		}
		*do_drop = 1;
		goto out;
	}

	ret_to_check &= ~(RRR_FIFO_WRITE_AGAIN|RRR_FIFO_WRITE_ORDERED|RRR_FIFO_WRITE_DROP);

	if (ret_to_check != 0) {
		RRR_BUG("Unknown return values %i from callback in __rrr_fifo_write_callback_return_check\n", ret_to_check);
	}

	out:
	return ret;
}

static void __rrr_fifo_write_update_pointers (
		struct rrr_fifo *buffer,
		struct rrr_fifo_entry *entry,
		uint64_t order,
		int do_ordered_write
) {
	struct rrr_fifo_entry *pos = buffer->gptr_first;

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
			struct rrr_fifo_entry *prev = NULL;
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

static int __rrr_fifo_search_and_replace_call_again (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_fifo_entry *entry = NULL;

	int do_loop = 1;

	while (ret == 0 && do_loop) {
		if ((__rrr_fifo_entry_new(&entry)) != 0) {
			RRR_MSG_0("Could not allocate entry in __rrr_fifo_search_and_replace_call_again\n");
			ret = 1;
			goto out;
		}

		int do_drop = 0;

		pthread_cleanup_push(__rrr_fifo_entry_destroy_simple_void, entry);

		uint64_t order = 0;

		ret = callback(&entry->data, &entry->size, &order, callback_arg);

		int do_ordered_write = 0;

		if ((ret = __rrr_fifo_write_callback_return_check(&do_ordered_write, &do_loop, &do_drop, ret)) != 0) {
			do_drop = 1;
			goto loop_out;
		}

		if (!do_drop) {
			if (entry->data == NULL) {
				RRR_BUG("Data from callback was NULL in rrr_fifo_write, must return DROP\n");
			}
			__rrr_fifo_write_update_pointers(buffer, entry, order, 0);
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
 * function.
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
int rrr_fifo_search_and_replace (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_WRITE_CALLBACK_ARGS),
		void *callback_arg,
		int call_again_after_looping
) {
	int ret = 0;

	if (rrr_fifo_get_entry_count(buffer) == 0) {
		goto out;
	}

	rrr_length cleared_entries = 0;
	rrr_length new_entries = 0;

	struct rrr_fifo_entry *entry;
	struct rrr_fifo_entry *next;
	struct rrr_fifo_entry *prev = NULL;
	for (entry = buffer->gptr_first; entry != NULL; entry = next) {
		RRR_DBG_4("buffer %p search_and_replace loop entry %p data %p next %p prev %p\n",
				buffer, entry, entry->data, entry->next, prev);
		next = entry->next;

		int did_something = 0;
		int actions = 0;

		char *data = entry->data;
		unsigned long int size = entry->size;
		uint64_t order = entry->order;

		actions = callback(&data, &size, &order, callback_arg);

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
					RRR_BUG("BUG: Both GIVE and REPLACE returned to fifo_search_and_replace\n");
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

				__rrr_fifo_entry_destroy(buffer, entry);
				rrr_length_inc_bug(&cleared_entries);
			}
			else {
				if (entry->data == data) {
					RRR_BUG("BUG: Callback of fifo_search_and_replace tells us to replace, but the data pointer did not change\n");
				}

				__rrr_fifo_entry_destroy_data(buffer, entry);

				entry->data = data;
				entry->size = size;
				entry->order = order;

				rrr_length_inc_bug(&cleared_entries);
				if ((ret = rrr_length_inc_err (&new_entries)) != 0) {
					break;
				}
			}

			entry = prev;
			did_something = 1;
		}
		if ((actions & RRR_FIFO_SEARCH_STOP) != 0) {
			break;
		}
		else if (did_something == 0) {
			RRR_BUG ("Bug: Unknown return value %i to fifo_search_and_replace\n", actions);
		}

		keep:
		prev = entry;
	}

	if (ret == RRR_FIFO_OK && call_again_after_looping) {
		ret = __rrr_fifo_search_and_replace_call_again(buffer, callback, callback_arg);
	}

	rrr_length_sub_bug (&buffer->entry_count, cleared_entries);
	if ((ret = rrr_length_add_err (&buffer->entry_count, new_entries)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_fifo_read_clear_forward_all (
		struct rrr_fifo *buffer,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data
) {
	int ret = RRR_FIFO_OK;

	if (rrr_fifo_get_entry_count(buffer) == 0) {
		goto out;
	}

	struct rrr_fifo_entry *last_element = NULL;
	struct rrr_fifo_entry *current = NULL;

	last_element = buffer->gptr_last;
	current = buffer->gptr_first;

	// Take all entries
	buffer->gptr_first = NULL;
	buffer->gptr_last = NULL;

	rrr_length processed_entries = 0;
	while (current != NULL) {
		struct rrr_fifo_entry *next = NULL;

		int ret_tmp = 0;

		next = current->next;
		ret_tmp = callback(callback_data, current->data, current->size);

		rrr_length_inc_bug(&processed_entries);

		if (ret_tmp != 0) {
			{
				if ((ret_tmp & RRR_FIFO_SEARCH_FREE) != 0) {
					// Callback wants us to free memory
					ret_tmp = ret_tmp & ~(RRR_FIFO_SEARCH_FREE);
					__rrr_fifo_entry_destroy_data(buffer, current);
				}
				else {
					__rrr_fifo_entry_release_data(current);
				}
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
					struct rrr_fifo_entry *new_first = next;

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

					__rrr_fifo_entry_destroy(buffer, current);
				}

				break;
			}
			ret_tmp &= ~(RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE|RRR_FIFO_SEARCH_STOP|RRR_FIFO_CALLBACK_ERR|RRR_FIFO_GLOBAL_ERR);
			if (ret_tmp != 0) {
				RRR_BUG("Unknown flags %i returned to fifo_read_clear_forward\n", ret_tmp);
			}
		}

		{
			// Don't free data
			__rrr_fifo_entry_release_data(current);
			__rrr_fifo_entry_destroy(buffer, current);
		}

		current = next;
	}

	rrr_length_sub_bug (&buffer->entry_count, processed_entries);

	out:
	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time. The callback function must not free the data or store it's pointer.
 * This function does not check FIFO_MAX_READS.
 */
int rrr_fifo_read (
		struct rrr_fifo *buffer,
		int (*callback)(RRR_FIFO_READ_CALLBACK_ARGS),
		void *callback_data
) {
	int ret = RRR_FIFO_OK;

	if (rrr_fifo_get_entry_count(buffer) == 0) {
		goto out;
	}

	struct rrr_fifo_entry *first = buffer->gptr_first;
	while (first != NULL) {
		int ret_tmp = 0;

		ret_tmp = callback(callback_data, first->data, first->size);

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

	out:
	return ret;
}

/*
 * This reading method blocks writers but allow other readers to traverse at the
 * same time. The callback function must not free the data or store it's pointer.
 * Only elements with an order value higher than minimum_order are read. If the
 * callback function produces an error, we stop.
 */

int rrr_fifo_read_minimum (
		struct rrr_fifo *buffer,
		struct rrr_fifo_entry *last_element,
		int (*callback)(void *callback_data, char *data, unsigned long int size),
		void *callback_data,
		uint64_t minimum_order
) {
	int ret = RRR_FIFO_OK;

	if (rrr_fifo_get_entry_count(buffer) == 0) {
		goto out;
	}

	struct rrr_fifo_entry *first = buffer->gptr_first;

	int processed_entries = 0;
	while (first != NULL) {
		if (first->order > minimum_order) {
			int res_ = 0;

			res_ = callback(callback_data, first->data, first->size);

			if (++processed_entries == RRR_FIFO_MAX_READS || first == last_element) {
				break;
			}
			if (res_ == RRR_FIFO_OK) {
				// Do nothing
			}
			else if ((res_ & RRR_FIFO_SEARCH_STOP) != 0) {
				ret = res_ & ~(RRR_FIFO_SEARCH_STOP);
				break;
			}
			else if ((res_ & (RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE)) != 0) {
				RRR_BUG("Bug: FIFO_SEARCH_GIVE or FIFO_SEARCH_FREE returned to fifo_read_minimum\n");
			}
			else {
				ret = res_;
				break;
			}
		}

		first = first->next;
	}

	out:
	return ret;
}

/*
 * This writing method holds the lock for a minimum amount of time, only to
 * update the pointers to the end. To provide memory fence, the data should be
 * allocated and written to inside the callback.
 */
int rrr_fifo_write (
		struct rrr_fifo *buffer,
		int (*callback)(char **data, unsigned long int *size, uint64_t *order, void *arg),
		void *callback_arg
) {
	int ret = 0;

	int write_again = 0;

	rrr_length entry_count_before = buffer->entry_count;
	rrr_length entry_count_after = 0;

	do {
		struct rrr_fifo_entry *entry = NULL;
		int do_free_entry = 0;

		ret = __rrr_fifo_entry_new(&entry);

		if (ret != 0) {
			RRR_MSG_0("Could not allocate entry in rrr_fifo_write\n");
			ret = 1;
			break;
		}

		pthread_cleanup_push(__rrr_fifo_entry_destroy_simple_void, entry);

		uint64_t order = 0;

		ret = callback(&entry->data, &entry->size, &order, callback_arg);

		int do_ordered_write = 0;
		int do_drop = 0;

		if ((ret = __rrr_fifo_write_callback_return_check(&do_ordered_write, &write_again, &do_drop, ret)) != 0) {
			goto loop_out_drop;
		}

		if (do_drop) {
			goto loop_out_drop;
		}

		if (entry->data == NULL) {
			RRR_BUG("Data from callback was NULL in rrr_fifo_write, must return DROP\n");
		}

		__rrr_fifo_write_update_pointers (buffer, entry, order, do_ordered_write);
		entry = NULL;

		if ((ret = rrr_length_inc_err (&buffer->entry_count)) != 0) {
			goto loop_out_no_drop;
		}
		entry_count_after = buffer->entry_count;

		do_free_entry = 0;

		goto loop_out_no_drop;
		loop_out_drop:
			do_free_entry = 1;
		loop_out_no_drop:
			pthread_cleanup_pop(do_free_entry);
	} while (write_again);

	if (entry_count_before != 0 || entry_count_after != 0) {
		RRR_DBG_4("buffer %p write loop complete, %i entries before %i after writing (some might have been removed)\n",
				buffer, entry_count_before, entry_count_after);
	}

	return ret;
}
