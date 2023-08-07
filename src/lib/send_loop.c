/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include "send_loop.h"

#include "message_holder/message_holder_struct.h"
#include "message_holder/message_holder_collection.h"
#include "message_holder/message_holder_util.h"

#include "log.h"
#include "allocator.h"
#include "util/rrr_time.h"
#include "util/posix.h"
#include "event/event.h"
#include "event/event_collection.h"
#include "event/event_collection_struct.h"

struct rrr_send_loop {
	struct rrr_event_queue *queue;
	char *debug_name;

	int do_preserve_order;

	uint64_t ttl_us;
	uint64_t timeout_us;
	enum rrr_send_loop_action timeout_action;

	int (*push_callback)(struct rrr_msg_holder *entry_locked, void *arg);
	int (*return_callback)(struct rrr_msg_holder *entry_locked, void *arg);
	void (*run_callback)(void *arg);
	void *callback_arg;

	struct rrr_event_collection events;
	rrr_event_handle event_run;
	rrr_event_handle event_periodic;

	struct rrr_msg_holder_collection send_entries;
	uint64_t entry_send_index_pos;
};

int rrr_send_loop_action_from_str (
		enum rrr_send_loop_action *action,
		const char *str
) {
	*action = 0;

	if (rrr_posix_strcasecmp(str, RRR_SEND_LOOP_ACTION_STR(RRR_SEND_LOOP_ACTION_RETRY)) == 0) {
		*action = RRR_SEND_LOOP_ACTION_RETRY;
	}
	else if (rrr_posix_strcasecmp(str, RRR_SEND_LOOP_ACTION_STR(RRR_SEND_LOOP_ACTION_DROP)) == 0) {
		*action = RRR_SEND_LOOP_ACTION_DROP;
	}
	else if (rrr_posix_strcasecmp(str, RRR_SEND_LOOP_ACTION_STR(RRR_SEND_LOOP_ACTION_RETURN)) == 0) {
		*action = RRR_SEND_LOOP_ACTION_RETURN;
	}
	else {
		RRR_MSG_0("Unknown action '%s'\n", str);
		return 1;
	}

	return 0;
}

void rrr_send_loop_set_parameters (
		struct rrr_send_loop *send_loop,
		int do_preserve_order,
		uint64_t ttl_us,
		uint64_t timeout_us,
		enum rrr_send_loop_action timeout_action
) {
	send_loop->do_preserve_order = do_preserve_order;
	send_loop->ttl_us = ttl_us;
	send_loop->timeout_us = timeout_us;
	send_loop->timeout_action = timeout_action;
}

void rrr_send_loop_destroy (
		struct rrr_send_loop *send_loop
) {
	rrr_free(send_loop->debug_name);
	rrr_msg_holder_collection_clear(&send_loop->send_entries);
	rrr_event_collection_clear(&send_loop->events);
	rrr_free(send_loop);
}

static void __rrr_send_loop_event_run (
		evutil_socket_t fd,
		short flags,
		void *arg
);

static void __rrr_send_loop_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
);

int rrr_send_loop_new (
		struct rrr_send_loop **result,
		struct rrr_event_queue *queue,
		const char *debug_name,
		int do_preserve_order,
		uint64_t ttl_us,
		uint64_t timeout_us,
		enum rrr_send_loop_action timeout_action,
		int (*push_callback)(struct rrr_msg_holder *entry_locked, void *arg),
		int (*return_callback)(struct rrr_msg_holder *entry_locked, void *arg),
		void (*run_callback)(void *arg),
		void *callback_arg
) {
	int ret = 0;

	*result = NULL;

	struct rrr_send_loop *send_loop;

	if ((send_loop = rrr_allocate_zero(sizeof(*send_loop))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((send_loop->debug_name = rrr_strdup(debug_name)) == NULL) {
		RRR_MSG_0("Failed to allocate debug name in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	rrr_event_collection_init(&send_loop->events, queue);

	if (rrr_event_collection_push_oneshot (
			&send_loop->event_run,
			&send_loop->events,
			__rrr_send_loop_event_run,
			send_loop
	) != 0) {
		RRR_MSG_0("Failed to create run event in %s\n", __func__);
		goto out_clear_event_collection;
	}

	if (rrr_event_collection_push_periodic (
			&send_loop->event_periodic,
			&send_loop->events,
			__rrr_send_loop_event_periodic,
			send_loop,
			250 * 1000 // 250 ms
	) != 0) {
		RRR_MSG_0("Failed to create periodic event in %s\n", __func__);
		goto out_clear_event_collection;
	}

	EVENT_ADD(send_loop->event_periodic);

	send_loop->queue = queue;
	rrr_send_loop_set_parameters (
			send_loop,
			do_preserve_order,
			ttl_us,
			timeout_us,
			timeout_action
	);
	send_loop->push_callback = push_callback;
	send_loop->return_callback = return_callback;
	send_loop->run_callback = run_callback;
	send_loop->callback_arg = callback_arg;

	*result = send_loop;

	goto out;
	out_clear_event_collection:
		rrr_event_collection_clear(&send_loop->events);
		rrr_free(send_loop->debug_name);
	out_free:
		rrr_free(send_loop);
	out:
		return ret;
}

void rrr_send_loop_entry_prepare (
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
) {
	// Used for sorting (preserve order)
	if ((entry_locked->send_index = ++(send_loop->entry_send_index_pos)) == 0) {
		RRR_MSG_0("Warning: Entry index counter wrapped in %s\n", send_loop->debug_name);
	}

	// Used for timeout checks
	entry_locked->send_time = rrr_time_get_64();
}

void __rrr_send_loop_entry_touch (struct rrr_msg_holder *entry) {
	entry->send_time = rrr_time_get_64();
}

void rrr_send_loop_entry_touch_related (
		struct rrr_send_loop *send_loop,
		const struct rrr_msg_holder *entry_locked,
		int (*cmp)(const struct rrr_msg_holder *entry, const struct rrr_msg_holder *entry_related, void *arg),
		void *callback_arg
) {
	RRR_LL_ITERATE_BEGIN(&send_loop->send_entries, struct rrr_msg_holder);
		if (node == entry_locked) {
			RRR_LL_ITERATE_NEXT();
		}

		rrr_msg_holder_lock(node);
		if (cmp(entry_locked, node, callback_arg) == 0) {
			__rrr_send_loop_entry_touch(node);
		}
		rrr_msg_holder_unlock(node);
	RRR_LL_ITERATE_END();
}

int rrr_send_loop_count (
		struct rrr_send_loop *send_loop
) {
	return RRR_LL_COUNT(&send_loop->send_entries);
}

void rrr_send_loop_push (
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
) {
	rrr_msg_holder_incref_while_locked (entry_locked);
	RRR_LL_APPEND(&send_loop->send_entries, entry_locked);
	EVENT_ACTIVATE(send_loop->event_run);
}

void rrr_send_loop_unshift (
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
) {
	rrr_msg_holder_incref_while_locked (entry_locked);
	RRR_LL_UNSHIFT(&send_loop->send_entries, entry_locked);
	EVENT_ACTIVATE(send_loop->event_run);
}

void rrr_send_loop_unshift_if_timed_out (
		int *did_unshift,
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
) {
	*did_unshift = 0;

	int ttl_reached = 0;
	int timeout_reached = 0;

	rrr_msg_holder_util_timeout_check(&ttl_reached, &timeout_reached, send_loop->ttl_us, send_loop->timeout_us, entry_locked);

	if (ttl_reached || timeout_reached) {
		rrr_send_loop_unshift(send_loop, entry_locked);
		*did_unshift = 1;
	}
}

void rrr_send_loop_clear (
		struct rrr_send_loop *send_loop
) {
	rrr_msg_holder_collection_clear(&send_loop->send_entries);
}

int rrr_send_loop_run (
		struct rrr_send_loop *send_loop
) {
	int ret = 0;

	if (send_loop->do_preserve_order) {
		rrr_msg_holder_collection_sort(&send_loop->send_entries, 1 /* Do lock */, rrr_msg_holder_util_index_compare);
	}

	int ttl_reached_count = 0;
	int timeout_count = 0;
	RRR_LL_ITERATE_BEGIN(&send_loop->send_entries, struct rrr_msg_holder);
		enum rrr_send_loop_action action = RRR_SEND_LOOP_ACTION_DROP;

		rrr_msg_holder_lock(node);

		int ttl_reached = 0;
		int timeout_reached = 0;

		rrr_msg_holder_util_timeout_check(&ttl_reached, &timeout_reached, send_loop->ttl_us, send_loop->timeout_us, node);

		if (ttl_reached) {
			ttl_reached_count++;
			RRR_DBG_3("TTL expired for a message after %" PRIrrrbl " seconds in %s, dropping it.\n",
					send_loop->ttl_us / 1000 / 1000, send_loop->debug_name);
			action = RRR_SEND_LOOP_ACTION_DROP;
		}
		else if (timeout_reached) {
			timeout_count++;
			RRR_DBG_3("Message timed out after %" PRIrrrbl " seconds in %s, performing timeout action %s.\n",
					send_loop->timeout_us / 1000 / 1000, send_loop->debug_name, RRR_SEND_LOOP_ACTION_STR(send_loop->timeout_action));

			// Timeout overrides retry. Note that the configuration parser should check that
			// default action is not retry while send_timeout is >0, would otherwise cause us
			// to spam timed out messages. We do not reset the send_time in the entry.
			action = send_loop->timeout_action;
		}
		else {
			if ((ret = send_loop->push_callback(node, send_loop->callback_arg)) != 0) {
				if (ret == RRR_SEND_LOOP_NOT_READY) {
					// Address possibly graylisted
					action = RRR_SEND_LOOP_ACTION_RETRY;
					ret = 0;
					if (send_loop->do_preserve_order) {
						// Must stop iteration to preserve order
						RRR_LL_ITERATE_LAST();
					}
				}
				else if (ret == RRR_SEND_LOOP_SOFT_ERROR) {
					RRR_DBG_3("Message dropped after soft error in %s\n",
							send_loop->debug_name);
					action = RRR_SEND_LOOP_ACTION_DROP;
					ret = 0;
				}
				else {
					RRR_MSG_0("Error %i from push callback while iterating send loop in %s\n", ret, send_loop->debug_name);
					action = RRR_SEND_LOOP_ACTION_DROP;
					RRR_LL_ITERATE_LAST();
				}
			}
		}

		// Make sure we always unlock, ether in ITERATE_END destroy or here if we
		// do not destroy
		if (action == RRR_SEND_LOOP_ACTION_RETRY) {
			rrr_msg_holder_unlock(node);
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();

			if (action == RRR_SEND_LOOP_ACTION_RETURN) {
				if ((ret = send_loop->return_callback (
						node,
						send_loop->callback_arg
				)) != 0) {
					RRR_MSG_0("Error %i from return callback while iterating send loop in %s\n",
							ret, send_loop->debug_name);
					RRR_LL_ITERATE_LAST(); // Destroy function must run and unlock, do not break
				}
			}
			else {
				// RRR_SEND_LOOP_ACTION_DROP, do nothing and just continue with destroy
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&send_loop->send_entries, 0; rrr_msg_holder_decref_while_locked_and_unlock(node));

	if (ret != 0) {
		RRR_MSG_0("Error in send loop in %s\n",
				send_loop->debug_name);
		goto out;
	}

	if (ttl_reached_count > 0) {
		RRR_MSG_0("TTL reached for %i messages in %s, they have been dropped.\n",
				ttl_reached_count, send_loop->debug_name);
	}
	if (timeout_count > 0) {
		RRR_MSG_0("Send timeout for %i messages in %s\n",
				timeout_count, send_loop->debug_name);
	}

	out:
	return ret;
}

int rrr_send_loop_event_pending (
		struct rrr_send_loop *send_loop
) {
	return EVENT_PENDING(send_loop->event_run);
}

void rrr_send_loop_event_remove (
		struct rrr_send_loop *send_loop
) {
	EVENT_REMOVE(send_loop->event_run);
}

void rrr_send_loop_event_add_or_remove (
		struct rrr_send_loop *send_loop
) {
	if (rrr_send_loop_count(send_loop) > 0) {
		EVENT_INTERVAL_SET(send_loop->event_run, 10 * 1000); // 10 ms
		EVENT_ADD(send_loop->event_run);
	}
	else {
		EVENT_REMOVE(send_loop->event_run);
	}
}

static void __rrr_send_loop_event_run (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_send_loop *send_loop = arg;

	(void)(fd);
	(void)(flags);

	if (rrr_send_loop_run(send_loop) != 0) {
		rrr_event_dispatch_break(send_loop->queue);
	}

	if (send_loop->run_callback != NULL) {
		send_loop->run_callback(send_loop->callback_arg);
	}

	rrr_send_loop_event_add_or_remove(send_loop);
}

static void __rrr_send_loop_event_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_send_loop *send_loop = arg;

	(void)(fd);
	(void)(flags);

	if (rrr_send_loop_count(send_loop) > 0) {
		EVENT_ACTIVATE(send_loop->event_run);
	}
}
