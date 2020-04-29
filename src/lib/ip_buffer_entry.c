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

void rrr_ip_buffer_entry_destroy (
		struct rrr_ip_buffer_entry *entry
) {
	RRR_FREE_IF_NOT_NULL(entry->message);
	free(entry);
}

void rrr_ip_buffer_entry_destroy_void (
		void *entry
) {
	rrr_ip_buffer_entry_destroy(entry);
}

void rrr_ip_buffer_entry_set_message_dangerous (
		struct rrr_ip_buffer_entry *entry,
		void *message,
		ssize_t data_length
) {
	entry->message = message;
	entry->data_length = data_length;
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

	*result = entry;

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

	memset(message, '\0', message_size);

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
	int ret = rrr_ip_buffer_entry_new_with_empty_message (
			result,
			source->data_length,
			(struct sockaddr *) &source->addr,
			source->addr_len,
			source->protocol
	);

	if (ret == 0) {
		(*result)->send_time = source->send_time;
		memcpy((*result)->message, source->message, source->data_length);
	}

	return ret;
}
