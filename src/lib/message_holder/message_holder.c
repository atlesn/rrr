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
#include <string.h>
#include <sys/types.h>

#include "../log.h"
#include "../allocator.h"
#include "message_holder.h"
#include "message_holder_struct.h"
#include "../allocator.h"
#include "../mqtt/mqtt_topic.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"
#include "../util/linked_list.h"

// This lock protects the lock member of all ip buffer entries
// and must be held when accessing the locks
pthread_mutex_t rrr_msg_holder_master_lock = PTHREAD_MUTEX_INITIALIZER;

static int __rrr_msg_holder_lock_init (
		struct rrr_msg_holder *entry
) {
	int ret = 0;
	pthread_mutex_lock(&rrr_msg_holder_master_lock);
	ret = rrr_posix_mutex_init(&entry->lock, RRR_POSIX_MUTEX_IS_RECURSIVE);
	pthread_mutex_unlock(&rrr_msg_holder_master_lock);
	return ret;
}

static void __rrr_msg_holder_util_lock_destroy (
		struct rrr_msg_holder *entry
) {
	pthread_mutex_lock(&rrr_msg_holder_master_lock);
	pthread_mutex_destroy(&entry->lock);
	pthread_mutex_unlock(&rrr_msg_holder_master_lock);
}

void rrr_msg_holder_lock (
		struct rrr_msg_holder *entry
) {
	if (entry->usercount <= 0) {
		RRR_BUG("BUG: Entry was destroyed in rrr_msg_holder_lock\n");
	}
	pthread_mutex_lock(&rrr_msg_holder_master_lock);
	while (pthread_mutex_trylock(&entry->lock) != 0) {
		pthread_mutex_unlock(&rrr_msg_holder_master_lock);
		pthread_testcancel();
		sched_yield();
		pthread_mutex_lock(&rrr_msg_holder_master_lock);
	}
	pthread_mutex_unlock(&rrr_msg_holder_master_lock);
#ifdef RRR_MESSAGE_HOLDER_DEBUG_LOCK_RECURSION
	entry->lock_recursion_count++;
#endif
}

void rrr_msg_holder_lock_double (
		struct rrr_msg_holder *entry
) {
	rrr_msg_holder_lock(entry);
	pthread_mutex_lock(&rrr_msg_holder_master_lock);
	pthread_mutex_lock(&entry->lock);
	pthread_mutex_unlock(&rrr_msg_holder_master_lock);
#ifdef RRR_MESSAGE_HOLDER_DEBUG_LOCK_RECURSION
	entry->lock_recursion_count++;
#endif
}

void rrr_msg_holder_unlock (
		struct rrr_msg_holder *entry
) {
	if (entry->usercount <= 0) {
		RRR_BUG("BUG: Entry was destroyed in rrr_msg_holder_unlock_\n");
	}
	pthread_mutex_lock(&rrr_msg_holder_master_lock);
	pthread_mutex_unlock(&entry->lock);
#ifdef RRR_MESSAGE_HOLDER_DEBUG_LOCK_RECURSION
	entry->lock_recursion_count--;
	if (entry->lock_recursion_count < 0) {
		RRR_BUG("BUG: Double unlock in rrr_msg_holder_unlock\n");
	}
#endif
	pthread_mutex_unlock(&rrr_msg_holder_master_lock);
}

void rrr_msg_holder_unlock_void (
		void *entry
) {
	rrr_msg_holder_unlock(entry);
}

void rrr_msg_holder_private_data_clear (
		struct rrr_msg_holder *entry
) {
	if (entry->private_data && entry->private_data_destroy) {
		entry->private_data_destroy(entry->private_data);
	}

	entry->private_data = NULL;
	entry->private_data_destroy = NULL;
}

void rrr_msg_holder_private_data_set (
		struct rrr_msg_holder *entry,
		void *private_data,
		void (*private_data_destroy)(void *private_data)
) {
	rrr_msg_holder_private_data_clear(entry);

	entry->private_data = private_data;
	entry->private_data_destroy = private_data_destroy;
}

void rrr_msg_holder_decref_while_locked_and_unlock (
		struct rrr_msg_holder *entry
) {
#ifdef RRR_MESSAGE_HOLDER_DEBUG_REFCOUNT
	printf ("ip buffer entry decref %p while locked from %i\n", entry, entry->usercount);
#endif
	if (entry->usercount <= 0) {
		RRR_BUG("BUG: ip buffer entry double destroy\n");
	}
	else if (--(entry->usercount) == 0) {
		RRR_FREE_IF_NOT_NULL(entry->message);
		rrr_msg_holder_private_data_clear(entry);
		rrr_instance_friend_collection_clear(&entry->nexthops);
		entry->usercount = 1; // Avoid bug trap
		rrr_msg_holder_unlock(entry);
		__rrr_msg_holder_util_lock_destroy(entry);
		entry->usercount = -1; // Lets us know that destroy has been called
		rrr_free(entry);
	}
	else {
		rrr_msg_holder_unlock(entry);
	}
}

void rrr_msg_holder_decref_while_locked_and_unlock_void (
		void *entry
) {
	rrr_msg_holder_decref_while_locked_and_unlock(entry);
}

void rrr_msg_holder_incref_while_locked (
		struct rrr_msg_holder *entry
) {
	if (entry->usercount <= 0) {
		RRR_BUG("BUG: ip buffer entry was destroyed while increfing\n");
	}
#ifdef RRR_MESSAGE_HOLDER_DEBUG_LOCK_RECURSION
	if (entry->lock_recursion_count == 0) {
		RRR_BUG("Entry was not locked in rrr_msg_holder_incref_while_locked\n");
	}
#endif
	(entry->usercount)++;
#ifdef RRR_MESSAGE_HOLDER_DEBUG_REFCOUNT
	printf ("ip buffer entry incref %p to %i\n", entry, entry->usercount);
#endif
}

void rrr_msg_holder_incref_while_locked_void (
		void *entry
) {
	rrr_msg_holder_incref_while_locked(entry);
}

void rrr_msg_holder_incref (
		struct rrr_msg_holder *entry
) {
	rrr_msg_holder_lock(entry);
	rrr_msg_holder_incref_while_locked (entry);
	rrr_msg_holder_unlock(entry);
}

void rrr_msg_holder_decref (
		struct rrr_msg_holder *entry
) {
	rrr_msg_holder_lock(entry);
#ifdef RRR_MESSAGE_HOLDER_DEBUG_REFCOUNT
	printf ("ip buffer entry decref %p from %i\n", entry, entry->usercount);
#endif
	rrr_msg_holder_decref_while_locked_and_unlock(entry);
}

void rrr_msg_holder_decref_void (
		void *entry
) {
#ifdef RRR_MESSAGE_HOLDER_DEBUG_REFCOUNT
	printf ("ip buffer entry decref %p void\n", entry);
#endif
	rrr_msg_holder_decref(entry);
}

int rrr_msg_holder_new (
		struct rrr_msg_holder **result,
		rrr_biglength data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol,
		void *message
) {
	int ret = 0;

	*result = NULL;

	struct rrr_msg_holder *entry = rrr_allocate_group(sizeof(*entry), RRR_ALLOCATOR_GROUP_MSG_HOLDER);
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_msg_holder_new\n");
		ret = 1;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));

	if (__rrr_msg_holder_lock_init(entry) != 0) {
		RRR_MSG_0("Could not initialize lock in rrr_msg_holder_new\n");
		ret = 1;
		goto out_free;
	}

	// Avoid usercount bug trap, initialize usercount once again later while holding the lock
	entry->usercount = 99999;

	rrr_msg_holder_lock(entry);

	// Ensure all fields are written to while lock is held
	RRR_MESSAGE_HOLDER_ZERO_ALL(entry);

	if (addr == NULL) {
		memset(&entry->addr, '\0', sizeof(entry->addr));
	}
	else if (addr_len > sizeof(entry->addr)) {
		RRR_BUG("Address too long (%llu > %llu) in rrr_msg_holder_new\n",
			(unsigned long long) addr_len, (unsigned long long) sizeof(entry->addr));
	}
	else {
		memcpy(&entry->addr, addr, addr_len);
	}

	if (addr_len > sizeof(entry->addr)) {
		RRR_BUG("addr_len too long in message_holder_new\n");
	}
	entry->addr_len = addr_len;

	entry->send_time = 0;
	entry->message = message;
	entry->data_length = data_length;
	entry->protocol = protocol;
	entry->usercount = 1;

	rrr_msg_holder_unlock(entry);

#ifdef RRR_MESSAGE_HOLDER_DEBUG_REFCOUNT
	printf ("ip buffer entry new %p usercount %i\n", entry, entry->usercount);
#endif

	*result = entry;
	goto out;
	out_free:
		rrr_free(entry);
	out:
		return ret;
}

int rrr_msg_holder_clone_no_data (
		struct rrr_msg_holder **result,
		const struct rrr_msg_holder *source
) {
	int ret = 0;

	*result = NULL;

	struct rrr_msg_holder *entry = NULL;

	if ((ret = rrr_msg_holder_new (
			&entry,
			0,
			(struct sockaddr *) &source->addr,
			source->addr_len,
			source->protocol,
			NULL
	)) != 0) {
		goto out;
	}

	rrr_msg_holder_lock(entry);

	entry->buffer_time = source->buffer_time;
	entry->send_time = source->send_time;

	ret = rrr_instance_friend_collection_append_from (&entry->nexthops, &source->nexthops);

	rrr_msg_holder_unlock(entry);

	if (ret != 0) {
		RRR_MSG_0("Failed to clone nexthops list in %s\n", __func__);
		goto out;
	}

	*result = entry;
	entry = NULL;

	out:
	if (entry != NULL) {
		rrr_msg_holder_decref(entry);
	}
	return ret;
}

void rrr_msg_holder_nexthops_reset (
		struct rrr_msg_holder *entry
) {
	rrr_instance_friend_collection_clear (&entry->nexthops);
}

int rrr_msg_holder_nexthops_set (
		struct rrr_msg_holder *entry,
		const struct rrr_instance_friend_collection *hops
) {
	rrr_msg_holder_nexthops_reset(entry);

	if (hops == NULL || RRR_LL_COUNT(hops) == 0) {
		return 0;
	}

	return rrr_instance_friend_collection_append_from (&entry->nexthops, hops);
}

int rrr_msg_holder_nexthop_ok (
		const struct rrr_msg_holder *entry,
		const struct rrr_instance *instance
) {
	return rrr_instance_friend_collection_check_empty (&entry->nexthops) ||
	       rrr_instance_friend_collection_check_exists (&entry->nexthops, instance);
}

void rrr_msg_holder_set_data_unlocked (
		struct rrr_msg_holder *target,
		void *message,
		rrr_biglength message_data_length
) {
	RRR_FREE_IF_NOT_NULL(target->message);
	target->message = message;
	target->data_length = message_data_length;
}

void rrr_msg_holder_set_unlocked (
		struct rrr_msg_holder *target,
		void *message,
		rrr_biglength message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol
) {
	rrr_msg_holder_set_data_unlocked (target, message, message_data_length);
	memcpy(&target->addr, addr, addr_len);
	target->addr_len = addr_len;
	target->protocol = protocol;
}

int rrr_msg_holder_address_matches (
		const struct rrr_msg_holder *a,
		const struct rrr_msg_holder *b
) {
	if (	 a->addr_len == b->addr_len &&
			(a->addr_len == 0 || memcmp(&a->addr, &b->addr, a->addr_len) == 0) &&
			 a->protocol == b->protocol
	) {
		return 1;
	}
	return 0;
}
