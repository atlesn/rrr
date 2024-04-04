/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include <stddef.h>
#include <assert.h>

#include "common.h"

#include "../allocator.h"
#include "../rrr_types.h"
#include "../messages/msg_msg.h"

struct rrr_raft_message_store {
	struct rrr_msg_msg **msgs;
	size_t count;
	size_t capacity;
	int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS);
};

static int __rrr_raft_message_store_expand (
		struct rrr_raft_message_store *store
) {
	int ret = 0;

	struct rrr_msg_msg **msgs_new;
	size_t capacity_new;

	assert(store->count <= store->capacity);

	if (store->count != store->capacity) {
		goto out;
	}

	capacity_new = store->capacity;

	rrr_size_t_add_bug(&capacity_new, 128);

	if ((msgs_new = rrr_reallocate(store->msgs, capacity_new * sizeof(*msgs_new))) == NULL) {
		RRR_MSG_0("Failed to allocate memory for pointers in %s\n", __func__);
		ret = 1;
		goto out;
	}

	store->msgs = msgs_new;
	store->capacity = capacity_new;

	out:
	return ret;
}

int rrr_raft_message_store_new (
		struct rrr_raft_message_store **result,
		int (*patch_cb)(RRR_RAFT_PATCH_CB_ARGS)
) {
	int ret = 0;

	struct rrr_raft_message_store *store;

	if ((store = rrr_allocate_zero(sizeof(*store))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	store->patch_cb = patch_cb;

	*result = store;

	out:
	return ret;
}

void rrr_raft_message_store_destroy (
		struct rrr_raft_message_store *store
) {
	for (size_t i = 0; i < store->count; i++) {
		RRR_FREE_IF_NOT_NULL(store->msgs[i]);
	}

	RRR_FREE_IF_NOT_NULL(store->msgs);

	rrr_free(store);
}

int rrr_raft_message_store_get (
		struct rrr_msg_msg **msg,
		const struct rrr_raft_message_store *store,
		const char *topic,
		size_t topic_length
) {
	int ret = 0;

	*msg = NULL;

	for (size_t i = 0; i < store->count; i++) {
		const struct rrr_msg_msg *msg_test = store->msgs[i];

		if (msg_test == NULL)
			continue;

		// TODO : How to support PATCH

		if (rrr_msg_msg_topic_equals_len(msg_test, topic, topic_length)) {
			assert(*msg == NULL);
			if ((*msg = rrr_msg_msg_duplicate(msg_test)) == NULL) {
				RRR_MSG_0("Failed to duplicate message in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
	}

	out:
	return ret;
}

int rrr_raft_message_store_push (
		int *was_found,
		struct rrr_raft_message_store *store,
		const struct rrr_msg_msg *msg_orig
) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	*was_found = 0;

	switch (MSG_TYPE(msg_orig)) {
		case MSG_TYPE_PUT: {
			if ((msg = rrr_msg_msg_duplicate(msg_orig)) == NULL) {
				RRR_MSG_0("Failed to duplicate message in %s\n", __func__);
				ret = 1;
				goto out;
			}
		} /* Fallthrough */
		case MSG_TYPE_PAT: {
			for (size_t i = 0; i < store->count; i++) {
				if (store->msgs[i] == NULL)
					continue;

				if (rrr_msg_msg_topic_equals_msg(msg_orig, store->msgs[i])) {
					rrr_u32 value_orig = store->msgs[i]->msg_value;

					if (MSG_IS_PUT(msg_orig)) {
						assert(msg != NULL);

						RRR_DBG_3("Raft replacing a message in message store %u->%u topic '%.*s'\n",
							value_orig, msg->msg_value, MSG_TOPIC_LENGTH(msg), MSG_TOPIC_PTR(msg));
					}
					else {
						assert(msg == NULL);

						if ((ret = store->patch_cb(&msg, store->msgs[i], msg_orig)) != 0) {
							RRR_MSG_0("Raft failed to patch a message in message store %u->%u topic '%.*s'\n",
								value_orig, msg->msg_value, MSG_TOPIC_LENGTH(msg), MSG_TOPIC_PTR(msg));
							goto out;
						}

						assert(MSG_IS_PUT(msg));

						RRR_DBG_3("Raft patching a message in message store %u->%u topic '%.*s'\n",
							value_orig, msg->msg_value, MSG_TOPIC_LENGTH(msg), MSG_TOPIC_PTR(msg));
					}

					rrr_free(store->msgs[i]);
					store->msgs[i] = msg;

					*was_found = 1;

					goto out_consumed;
				}
			}
		} break;
		default:
			RRR_BUG("BUG: Message type %s not implemented in %s\n", MSG_TYPE_NAME(msg), __func__);
	};

	switch (MSG_TYPE(msg_orig)) {
		case MSG_TYPE_PUT: {
			assert(msg != NULL);
		} break;
		case MSG_TYPE_PAT: {
			assert(msg == NULL);

			RRR_MSG_0("Raft could not patch topic '%.*s', message not found\n",
				MSG_TOPIC_LENGTH(msg_orig), MSG_TOPIC_PTR(msg_orig));

			goto out;
		} break;
		default:
			RRR_BUG("BUG: Message type %s not implemented in %s\n", MSG_TYPE_NAME(msg), __func__);
	};

	for (size_t i = 0; i < store->count; i++) {
		if (store->msgs[i] != NULL)
			continue;

		store->msgs[i] = msg;

		RRR_DBG_3("Raft inserted message into message store %u topic '%.*s' count is now %llu\n",
			msg->msg_value, MSG_TOPIC_LENGTH(msg), MSG_TOPIC_PTR(msg), (unsigned long long) store->count);

		goto out_consumed;
	}

	if ((ret = __rrr_raft_message_store_expand(store)) != 0) {
		goto out;
	}

	store->msgs[store->count++] = msg;

	RRR_DBG_3("Raft pushed message to message store %u topic '%.*s'\n",
		msg->msg_value, MSG_TOPIC_LENGTH(msg), MSG_TOPIC_PTR(msg));

	out_consumed:
		msg = NULL;
	out:
		RRR_FREE_IF_NOT_NULL(msg);
		return ret;
}

size_t rrr_raft_message_store_count (
		const struct rrr_raft_message_store *store
) {
	return store->count;
}

int rrr_raft_message_store_iterate (
		const struct rrr_raft_message_store *store,
		int (*callback)(const struct rrr_msg_msg *msg, void *arg),
		void *callback_arg
) {
	int ret = 0;

	size_t i;

	for (i = 0; i < store->count; i++) {
		if ((ret = callback(store->msgs[i], callback_arg)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}
