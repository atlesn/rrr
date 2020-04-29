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

#include "../global.h"
#include "ip_buffer_entry.h"
#include "messages.h"
#include "linked_list.h"

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

void rrr_ip_buffer_entry_destroy_while_locked (
		struct rrr_ip_buffer_entry *entry
) {
	RRR_FREE_IF_NOT_NULL(entry->message);
	rrr_ip_buffer_entry_unlock(entry);
	__rrr_ip_buffer_entry_lock_destroy(entry);
	free(entry);
}

void rrr_ip_buffer_entry_destroy (
		struct rrr_ip_buffer_entry *entry
) {
	rrr_ip_buffer_entry_lock(entry);
	rrr_ip_buffer_entry_destroy_while_locked(entry);
}

void rrr_ip_buffer_entry_destroy_void (
		void *entry
) {
	rrr_ip_buffer_entry_destroy(entry);
}

void rrr_ip_buffer_entry_collection_clear (
		struct rrr_ip_buffer_entry_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_ip_buffer_entry, rrr_ip_buffer_entry_destroy(node));
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

	rrr_ip_buffer_entry_lock(entry);

	RRR_LL_NODE_INIT(entry);

	if (addr == NULL) {
		memset(&entry->addr, '\0', sizeof(entry->addr));
	}
	else {
		entry->addr = *((struct rrr_sockaddr *) addr);
	}

	if (addr_len > sizeof(entry->addr)) {
		RRR_BUG("addr_len too long in ip_buffer_entry_new\n");
	}
	entry->addr_len = addr_len;

	entry->send_time = 0;
	entry->message = message;
	entry->data_length = data_length;
	entry->protocol = protocol;

	rrr_ip_buffer_entry_unlock(entry);

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

int rrr_ip_buffer_entry_clone (
		struct rrr_ip_buffer_entry **result,
		const struct rrr_ip_buffer_entry *source
) {
	rrr_ip_buffer_entry_lock((struct rrr_ip_buffer_entry *) source);
	int ret = rrr_ip_buffer_entry_new_with_empty_message (
			result,
			source->data_length,
			(struct sockaddr *) &source->addr,
			source->addr_len,
			source->protocol
	);
	rrr_ip_buffer_entry_unlock((struct rrr_ip_buffer_entry *) source);

	if (ret == 0) {
		rrr_ip_buffer_entry_lock(*result);
		(*result)->send_time = source->send_time;
		memcpy((*result)->message, source->message, source->data_length);
		rrr_ip_buffer_entry_unlock(*result);
	}

	return ret;
}
