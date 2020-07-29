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

#include "posix.h"
#include "log.h"
#include "ip_buffer_entry.h"
#include "ip_buffer_entry_struct.h"
#include "linked_list.h"
#include "macro_utils.h"
#include "mqtt/mqtt_topic.h"

//#define RRR_IP_BUFFER_ENTRY_REFCOUNT_DEBUG

// This lock protects the lock member of all ip buffer entries
// and must be held when accessing the locks
pthread_mutex_t rrr_ip_buffer_master_lock = PTHREAD_MUTEX_INITIALIZER;

static int __rrr_ip_buffer_entry_lock_init (
		struct rrr_ip_buffer_entry *entry
) {
	int ret = 0;
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	ret = pthread_mutex_init(&entry->lock, NULL);
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
	return ret;
}

static void __rrr_ip_buffer_entry_util_lock_destroy (
		struct rrr_ip_buffer_entry *entry
) {
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	pthread_mutex_destroy(&entry->lock);
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
}

void rrr_ip_buffer_entry_lock (
		struct rrr_ip_buffer_entry *entry
) {
	if (entry->usercount <= 0) {
		RRR_BUG("Bug: Entry was destroyed in rrr_ip_buffer_entry_lock_\n");
	}
	pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	while (pthread_mutex_trylock(&entry->lock) != 0) {
		pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
		pthread_testcancel();
		rrr_posix_usleep(10);
		pthread_mutex_lock(&rrr_ip_buffer_master_lock);
	}
	pthread_mutex_unlock(&rrr_ip_buffer_master_lock);
}

void rrr_ip_buffer_entry_unlock (
		struct rrr_ip_buffer_entry *entry
) {
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
		__rrr_ip_buffer_entry_util_lock_destroy(entry);
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
		RRR_MSG_0("Could not allocate memory in ip_buffer_entry_new\n");
		ret = 1;
		goto out;
	}

	if (__rrr_ip_buffer_entry_lock_init(entry) != 0) {
		RRR_MSG_0("Could not initialize lock in rrr_ip_buffer_entry_new\n");
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
