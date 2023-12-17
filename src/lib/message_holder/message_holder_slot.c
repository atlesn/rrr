/*

Read Route Record

Copyright (C) 2021-2023 Atle Solbakken atle@goliathdns.no

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

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "../log.h"
#include "../allocator.h"
#include "message_holder_slot.h"
#include "message_holder.h"
#include "message_holder_util.h"
#include "message_holder_struct.h"
#include "message_holder_collection.h"
#include "../rrr_strerror.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"

struct rrr_msg_holder_slot {
	int lives_max;

	struct rrr_msg_holder *entry;

	pthread_cond_t cond;
	pthread_mutex_t lock;

	rrr_length reader_count;
	const void **readers;
	uint8_t *reader_has_read;

	uint64_t total_entries_deleted;
	uint64_t total_entries_written;
};

int rrr_msg_holder_slot_new (
		struct rrr_msg_holder_slot **target
) {
	int ret = 0;

	*target = NULL;

	struct rrr_msg_holder_slot *slot = rrr_allocate(sizeof(*slot));
	if (slot == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_msg_holder_slot_new\n");
		ret = 1;
		goto out;
	}

	memset(slot, '\0', sizeof(*slot));

	if (rrr_posix_mutex_init (&slot->lock, 0)) {
		ret = 1;
		goto out_free;
	}

	if (rrr_posix_cond_init (&slot->cond, 0)) {
		ret = 1;
		goto out_destroy_mutex;
	}

	*target = slot;

	goto out;
//	out_destroy_cond:
//		pthread_cond_destroy(&slot->cond);
	out_destroy_mutex:
		pthread_mutex_destroy(&slot->lock);
	out_free:
		rrr_free(slot);
	out:
		return ret;
}

int rrr_msg_holder_slot_reader_count_set (
		struct rrr_msg_holder_slot *slot,
		rrr_length reader_count
) {
	int ret = 0;

	pthread_mutex_lock(&slot->lock);

	RRR_FREE_IF_NOT_NULL(slot->readers);
	RRR_FREE_IF_NOT_NULL(slot->reader_has_read);

	if (reader_count > 0) {
		if ((slot->readers = rrr_allocate(sizeof(slot->readers[0]) * reader_count)) == NULL) {
			ret = 1;
			goto out;
		}
		memset(slot->readers, '\0', sizeof(slot->readers[0]) * reader_count);

		if ((slot->reader_has_read = rrr_allocate(sizeof(slot->reader_has_read[0]) * reader_count)) == NULL) {
			ret = 1;
			goto out_free_readers;
		}
		memset(slot->reader_has_read, '\0', sizeof(slot->reader_has_read[0]) * reader_count);
	}

	slot->reader_count = reader_count;

	goto out;
	out_free_readers:
		rrr_free(slot->readers);
	out:
		pthread_mutex_unlock(&slot->lock);
		return ret;
}

void rrr_msg_holder_slot_destroy (
		struct rrr_msg_holder_slot *slot
) {
	pthread_mutex_lock(&slot->lock);
	if (slot->entry != NULL) {
		rrr_msg_holder_decref(slot->entry);
	}
	pthread_mutex_unlock(&slot->lock);

	pthread_mutex_destroy(&slot->lock);
	pthread_cond_destroy(&slot->cond);
	RRR_FREE_IF_NOT_NULL(slot->readers);
	RRR_FREE_IF_NOT_NULL(slot->reader_has_read);
	rrr_free(slot);
}

void rrr_msg_holder_slot_get_stats (
		uint64_t *entries_deleted,
		uint64_t *entries_written,
		struct rrr_msg_holder_slot *slot
) {
	pthread_mutex_lock(&slot->lock);
	*entries_deleted = slot->total_entries_deleted;
	*entries_written = slot->total_entries_written;
	pthread_mutex_unlock(&slot->lock);
}

unsigned int rrr_msg_holder_slot_count (
		struct rrr_msg_holder_slot *slot
) {
	unsigned int count = 0;

	pthread_mutex_lock(&slot->lock);

	if (slot->entry == NULL) {
		goto out;
	}

	count++;

	for (rrr_length i = 0; i < slot->reader_count; i++) {
		if (slot->reader_has_read[i] == 0) {
			count++;
		}
	}

	out:
	pthread_mutex_unlock(&slot->lock);
	return count;
}

static rrr_slength __rrr_msg_holder_slot_reader_index_get_unlocked (
		struct rrr_msg_holder_slot *slot,
		const void *self
) {
	if (slot->reader_count == 0) {
		return -1;
	}

	rrr_slength self_index = -1;

	for (rrr_length i = 0; i < slot->reader_count; i++) {
		if (slot->readers[i] == (void *) self) {
			self_index = i;
			break;
		}
		else if (slot->readers[i] == 0) {
			slot->readers[i] = self;
			self_index = i;
			break;
		}
	}

	if (self_index == -1) {
		RRR_BUG("BUG: Too many readers in __rrr_msg_holder_slot_reader_index_get, slot has been under-allocated\n");
	}

	return self_index;
}

int rrr_msg_holder_slot_read (
		struct rrr_msg_holder_slot *slot,
		void *self,
		int (*callback)(int *do_keep, struct rrr_msg_holder *entry, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_msg_holder *entry_new = NULL;

	pthread_mutex_lock(&slot->lock);

	if (slot->entry == NULL) {
		goto out;
	}

	rrr_slength self_index = __rrr_msg_holder_slot_reader_index_get_unlocked(slot, self);
	if (self_index >= 0 && slot->reader_has_read[self_index]) {
		goto out;
	}

	rrr_msg_holder_lock(slot->entry);
	ret = rrr_msg_holder_util_clone_no_locking(&entry_new, slot->entry);
	rrr_msg_holder_unlock(slot->entry);

	if (ret != 0) {
		RRR_MSG_0("Failed to clone entry in rrr_msg_holder_slot_read\n");
		goto out;
	}

	// Use double lock to make sure we can decref immediately when
	// function exits if a module forwards the entry to antoher thread
	// which then tries to lock it just after the callback has returned.
	rrr_msg_holder_lock_double(entry_new);

	int do_keep = 0;

	{
		// Callback must unlock entry
		ret = callback(&do_keep, entry_new, callback_arg);

		if (ret != 0) {
			goto out_decref_and_unlock;
		}
	}

	if (!do_keep) {
		rrr_length done_count = 0;

		if (self_index >= 0) {
			slot->reader_has_read[self_index] = 1;
			for (rrr_length i = 0; i < slot->reader_count; i++) {
				if (slot->reader_has_read[i]) {
					done_count++;
				}
			}
		}

		if (done_count >= slot->reader_count) {
			slot->total_entries_deleted++;
			rrr_msg_holder_decref(slot->entry);
			slot->entry = NULL;
		}

		// Signal writers and other readers
		if ((ret = pthread_cond_broadcast(&slot->cond)) != 0) {
			RRR_MSG_0("Failed while signalling condition in rrr_msg_holder_slot_write: %s\n", rrr_strerror(ret));
			ret = 1;
			goto out_decref_and_unlock;
		}
	}
	
	out_decref_and_unlock:
		rrr_msg_holder_decref_while_locked_and_unlock(entry_new);
	out:
		pthread_mutex_unlock(&slot->lock);
		return ret;
}

static int __rrr_msg_holder_slot_discard_callback (
		int *do_keep,
		struct rrr_msg_holder *entry,
		void *arg
) {
	int *did_discard = arg;

	*do_keep = 0;
	*did_discard = 1;

	rrr_msg_holder_unlock(entry);
	return 0;
}

int rrr_msg_holder_slot_discard (
		int *did_discard,
		struct rrr_msg_holder_slot *slot,
		void *self
) {
	*did_discard = 0;

	return rrr_msg_holder_slot_read (slot, self, __rrr_msg_holder_slot_discard_callback, did_discard);
}

static void __rrr_msg_holder_slot_holder_destroy_double_ptr (
		void *arg
) {
	struct rrr_msg_holder **entry = arg;

	if (*entry != NULL) {
		rrr_msg_holder_decref(*entry);
	}
}

static int __rrr_msg_holder_slot_write_wait (
		struct rrr_msg_holder_slot *slot,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	while (slot->entry != NULL) {
		struct timespec wakeup_time;
		rrr_time_gettimeofday_timespec(&wakeup_time, 500 * 1000); /* 500 ms */
		if ((ret = pthread_cond_timedwait(&slot->cond, &slot->lock, &wakeup_time)) != 0) {
			if (ret != ETIMEDOUT) {
				RRR_MSG_0("Failed while waiting on condition in __rrr_msg_holder_slot_write_wait: %s\n", rrr_strerror(ret));
				ret = 1;
				goto out;
			}
			ret = 0;
		}
		if (check_cancel_callback != NULL && (ret = check_cancel_callback(check_cancel_callback_arg)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static void __rrr_msg_holder_slot_unlock_void (void *arg) {
	struct rrr_msg_holder_slot *slot = arg;
	pthread_mutex_unlock(&slot->lock);	
}

#define LOCK_AND_WAIT()                                                                                                        \
    pthread_mutex_lock(&slot->lock);                                                                                           \
    pthread_cleanup_push(__rrr_msg_holder_slot_unlock_void, slot);                                                             \
    do {if ((ret = __rrr_msg_holder_slot_write_wait(slot, check_cancel_callback, check_cancel_callback_arg)) != 0) goto out; } while (0)

#define WRITE_AND_RESET()                                                                                                      \
    do {for (rrr_length i = 0; i < slot->reader_count; i++) {                                                                  \
        slot->reader_has_read[i] = 0;                                                                                          \
    }                                                                                                                          \
    slot->entry = entry_new;                                                                                                   \
    entry_new = NULL;                                                                                                          \
    slot->total_entries_written++;                                                                                             \
    if ((ret = pthread_cond_broadcast(&slot->cond)) != 0) { /* Signal a reader */                                              \
        RRR_MSG_0("Failed while signalling condition while writing in rrr_msg_holder_slot: %s\n", rrr_strerror(ret));          \
        ret = 1;                                                                                                               \
        goto out;                                                                                                              \
    }} while(0)

#define UNLOCK() \
	pthread_cleanup_pop(1)

int rrr_msg_holder_slot_write (
		struct rrr_msg_holder_slot *slot,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol,
		int (*callback)(int *do_drop, struct rrr_msg_holder *entry, void *arg),
		void *callback_arg,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg

) {
	int ret = 0;

	struct rrr_msg_holder *entry_new = NULL;

	pthread_cleanup_push(__rrr_msg_holder_slot_holder_destroy_double_ptr, &entry_new);

	int do_drop = 0;

	if (entry_new == NULL && (ret = rrr_msg_holder_new(&entry_new, 0, addr, addr_len, protocol, NULL)) != 0) {
		goto out_no_unlock;
	}

	LOCK_AND_WAIT();

	// Callback must always unlock entry. If the callback is possibly slow
	// and has cancellation points, it must wrap unlock in pthread_cleanup_push.
	rrr_msg_holder_lock(entry_new);
	if ((ret = callback(&do_drop, entry_new, callback_arg)) != 0) {
		goto out;
	}

	if (!do_drop) {
		WRITE_AND_RESET();
	}

	out:
		UNLOCK();
	out_no_unlock:
		pthread_cleanup_pop(1);
		return ret;
}

int rrr_msg_holder_slot_write_clone (
		struct rrr_msg_holder_slot *slot,
		const struct rrr_msg_holder *source,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg,
		void (*after_clone_callback)(struct rrr_msg_holder *entry, void *arg),
		void *after_clone_callback_arg
) {
	int ret = 0;

	struct rrr_msg_holder *entry_new = NULL;

	if ((ret = rrr_msg_holder_util_clone_no_locking(&entry_new, source)) != 0) {
		goto out_no_unlock;
	}

	if (after_clone_callback) {
		after_clone_callback(entry_new, after_clone_callback_arg);
	}

	LOCK_AND_WAIT();
	WRITE_AND_RESET();

	out:
		UNLOCK();
	out_no_unlock:
		if (entry_new != NULL) {
			rrr_msg_holder_decref(entry_new);
		}
		return ret;
}

static int __rrr_msg_holder_slot_write (
		struct rrr_msg_holder_slot *slot,
		struct rrr_msg_holder *entry_new,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	LOCK_AND_WAIT();
	WRITE_AND_RESET();

	out:
	UNLOCK();
	return ret;
}

int rrr_msg_holder_slot_write_incref (
		struct rrr_msg_holder_slot *slot,
		struct rrr_msg_holder *entry_new,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	if ((ret = __rrr_msg_holder_slot_write(slot, entry_new, check_cancel_callback, check_cancel_callback_arg)) != 0) {
		goto out;
	}

	rrr_msg_holder_incref(entry_new);

	out:
	return ret;
}

int rrr_msg_holder_slot_write_from_collection (
		struct rrr_msg_holder_slot *slot,
		struct rrr_msg_holder_collection *collection,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
) {
	int ret = 0;

	while (RRR_LL_COUNT(collection) > 0) {
		struct rrr_msg_holder *entry = RRR_LL_FIRST(collection);
		if ((ret = __rrr_msg_holder_slot_write (slot, entry, check_cancel_callback, check_cancel_callback_arg)) != 0) {
			goto out;
		}
		(void)RRR_LL_SHIFT(collection);
	}

	out:
	return ret;
}

int rrr_msg_holder_slot_with_lock_do (
		struct rrr_msg_holder_slot *slot,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
) {
	int ret = 0;

	pthread_mutex_lock(&slot->lock);

	if ((ret = callback(callback_arg_1, callback_arg_2)) != 0) {
		goto out;
	}

	out:
	pthread_mutex_unlock(&slot->lock);
	return ret;
}
