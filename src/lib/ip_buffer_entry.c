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
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "ip_buffer_entry.h"
#include "messages.h"
#include "linked_list.h"

//#define RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG

// This lock protects the lock member of all ip buffer entries
// and must be held when accessing the locks
pthread_mutex_t rrr_ip_buffer_master_lock = PTHREAD_MUTEX_INITIALIZER;

static int __rrr_ip_buffer_entry_lock_init (struct rrr_ip_buffer_entry *entry) {
	int ret = 0;
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	ret = pthread_mutex_init(&entry->lock, NULL);
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
	return ret;
}

static void __rrr_ip_buffer_entry_lock_destroy (struct rrr_ip_buffer_entry *entry) {
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	pthread_mutex_destroy(&entry->lock);
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
}

void rrr_ip_buffer_entry_lock (struct rrr_ip_buffer_entry *entry) {
	if (entry->usercount <= 0) {
		RRR_BUG("Bug: Entry was destroyed in rrr_ip_buffer_entry_lock_\n");
	}
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	while (pthread_mutex_trylock(&entry->lock) != 0) {
		pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
		pthread_testcancel();
		usleep(10);
		pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	}
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
}

void rrr_ip_buffer_entry_unlock (struct rrr_ip_buffer_entry *entry) {
	if (entry->usercount <= 0) {
		RRR_BUG("Bug: Entry was destroyed in rrr_ip_buffer_entry_unlock_\n");
	}
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	pthread_mutex_unlock(&entry->lock);
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
}

void rrr_ip_buffer_entry_decref_while_locked_and_unlock (
		struct rrr_ip_buffer_entry *entry
) {
#ifdef RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG
	printf ("ip buffer entry decref %p while locked from %i\n", entry, entry->usercount);
#endif
	if (entry->usercount <= 0) {
		RRR_BUG("BUG: ip buffer entry double destroy\n");
	}
	else if (--(entry->usercount) == 0) {
		RRR_FREE_IF_NOT_NULL(entry->message);
		entry->usercount = 1; // Avoid bug trap
		rrr_ip_buffer_entry_unlock(entry);
		__rrr_ip_buffer_entry_lock_destroy(entry);
		entry->usercount = -1; // Lets us know that destroy has been called
		free(entry);
	}
	else {
		rrr_ip_buffer_entry_unlock(entry);
	}
}

void rrr_ip_buffer_entry_incref_while_locked (
		struct rrr_ip_buffer_entry *entry
) {
	if (entry->usercount <= 0) {
		RRR_BUG("BUG: ip buffer entry was destroyed while increfing\n");
	}
	if (pthread_mutex_trylock(&entry->lock) == 0) {
		RRR_BUG("Entry was not locked in rrr_ip_buffer_entry_incref_while_locked\n");
	}
	(entry->usercount)++;
#ifdef RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG
	printf ("ip buffer entry incref %p to %i\n", entry, entry->usercount);
#endif
}

void rrr_ip_buffer_entry_decref (
		struct rrr_ip_buffer_entry *entry
) {
	rrr_ip_buffer_entry_lock(entry);
#ifdef RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG
	printf ("ip buffer entry decref %p from %i\n", entry, entry->usercount);
#endif
	rrr_ip_buffer_entry_decref_while_locked_and_unlock(entry);
}

void rrr_ip_buffer_entry_decref_void (
		void *entry
) {
#ifdef RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG
	printf ("ip buffer entry decref %p void\n", entry);
#endif
	rrr_ip_buffer_entry_decref(entry);
}

void rrr_ip_buffer_entry_collection_clear (
		struct rrr_ip_buffer_entry_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_ip_buffer_entry, rrr_ip_buffer_entry_decref(node));
}

void rrr_ip_buffer_entry_collection_clear_void (
		void *arg
) {
	rrr_ip_buffer_entry_collection_clear(arg);
}

void rrr_ip_buffer_entry_collection_sort (
		struct rrr_ip_buffer_entry_collection *target,
		int (*compare)(void *message_a, void *message_b)
) {
	struct rrr_ip_buffer_entry_collection tmp = {0};

	while (RRR_LL_COUNT(target) != 0) {
		struct rrr_ip_buffer_entry *smallest = RRR_LL_FIRST(target);
		RRR_LL_ITERATE_BEGIN(target, struct rrr_ip_buffer_entry);
			if (compare(node->message, smallest->message) < 0) {
				smallest = node;
			}
		RRR_LL_ITERATE_END();

		RRR_LL_REMOVE_NODE_NO_FREE(target, smallest);
		RRR_LL_APPEND(&tmp, smallest);
	}

	*target = tmp;
}

int rrr_ip_buffer_entry_new (
		struct rrr_ip_buffer_entry **result,
		ssize_t data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		int protocol,
		void *message
) {
	int ret = 0;

	*result = NULL;

	struct rrr_ip_buffer_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_ERR("Could not allocate memory in ip_buffer_entry_new\n");
		ret = 1;
		goto out;
	}

	if (__rrr_ip_buffer_entry_lock_init(entry) != 0) {
		RRR_MSG_ERR("Could not initialize lock in rrr_ip_buffer_entry_new\n");
		ret = 1;
		goto out_free;
	}

	// Avoid usercount bug trap, write once again while holding the lock below
	entry->usercount = 99999;

	rrr_ip_buffer_entry_lock(entry);

	RRR_LL_NODE_INIT(entry);

	if (addr == NULL) {
		memset(&entry->addr, '\0', sizeof(entry->addr));
	}
	else if (addr_len > sizeof(entry->addr)) {
		RRR_BUG("Address too long (%u > %u) in rrr_ip_buffer_entry_new\n", addr_len, sizeof(entry->addr));
	}
	else {
		memcpy(&entry->addr, addr, addr_len);
	}

	if (addr_len > sizeof(entry->addr)) {
		RRR_BUG("addr_len too long in ip_buffer_entry_new\n");
	}
	entry->addr_len = addr_len;

	entry->send_time = 0;
	entry->message = message;
	entry->data_length = data_length;
	entry->protocol = protocol;
	entry->usercount = 1;

	rrr_ip_buffer_entry_unlock(entry);

#ifdef RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG
	printf ("ip buffer entry new %p usercount %i\n", entry, entry->usercount);
#endif

	*result = entry;
	goto out;
	out_free:
		free(entry);
	out:
		return ret;
}

int rrr_ip_buffer_entry_new_with_empty_message (
		struct rrr_ip_buffer_entry **result,
		ssize_t message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		int protocol
) {
	int ret = 0;

	struct rrr_ip_buffer_entry *entry = NULL;
	struct rrr_message *message = NULL;

	ssize_t message_size = sizeof(*message) - 1 + message_data_length;

	message = malloc(message_size);
	if (message == NULL) {
		RRR_MSG_ERR("Could not allocate message in ip_buffer_entry_new_with_message\n");
		goto out;
	}

	if (rrr_ip_buffer_entry_new (
			&entry,
			message_size,
			addr,
			addr_len,
			protocol,
			message
	) != 0) {
		RRR_MSG_ERR("Could not allocate ip buffer entry in ip_buffer_entry_new_with_message\n");
		ret = 1;
		goto out;
	}

	rrr_ip_buffer_entry_lock(entry);
	memset(message, '\0', message_size);
	rrr_ip_buffer_entry_unlock(entry);

	message = NULL;

	*result = entry;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int rrr_ip_buffer_entry_clone_no_locking (
		struct rrr_ip_buffer_entry **result,
		const struct rrr_ip_buffer_entry *source
) {
	int ret = rrr_ip_buffer_entry_new_with_empty_message (
			result,
			source->data_length,
			(struct sockaddr *) &source->addr,
			source->addr_len,
			source->protocol
	);

	if (ret == 0) {
		rrr_ip_buffer_entry_lock(*result);
		(*result)->send_time = source->send_time;
		memcpy((*result)->message, source->message, source->data_length);
		rrr_ip_buffer_entry_unlock(*result);
	}

	return ret;
}

void rrr_ip_buffer_entry_set_unlocked (
		struct rrr_ip_buffer_entry *target,
		void *message,
		ssize_t message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		int protocol
) {
	RRR_FREE_IF_NOT_NULL(target->message);

	target->message = message;
	target->data_length = message_data_length;
	memcpy(&target->addr, addr, addr_len);
	target->addr_len = addr_len;
	target->protocol = protocol;
}
