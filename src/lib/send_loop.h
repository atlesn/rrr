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

#ifndef RRR_SEND_LOOP_H
#define RRR_SEND_LOOP_H

#include "rrr_types.h"
#include "read_constants.h"

#define RRR_SEND_LOOP_OK           RRR_READ_OK
#define RRR_SEND_LOOP_HARD_ERROR   RRR_READ_HARD_ERROR
#define RRR_SEND_LOOP_SOFT_ERROR   RRR_READ_SOFT_ERROR
#define RRR_SEND_LOOP_NOT_READY    RRR_READ_INCOMPLETE

enum rrr_send_loop_action {
	RRR_SEND_LOOP_ACTION_RETRY,
	RRR_SEND_LOOP_ACTION_DROP,
	RRR_SEND_LOOP_ACTION_RETURN
};

struct rrr_event_queue;
struct rrr_msg_holder;
struct rrr_send_loop;

#define RRR_SEND_LOOP_ACTION_STR(action)               \
  (action == RRR_SEND_LOOP_ACTION_RETRY ? "RETRY" :    \
   action == RRR_SEND_LOOP_ACTION_DROP ? "DROP" :      \
   action == RRR_SEND_LOOP_ACTION_RETURN ? "RETURN" :  \
   "UNKNOWN")

int rrr_send_loop_action_from_str (
		enum rrr_send_loop_action *action,
		const char *str
);
void rrr_send_loop_set_parameters (
		struct rrr_send_loop *send_loop,
		int do_preserve_order,
		uint64_t ttl_us,
		uint64_t timeout_us,
		enum rrr_send_loop_action timeout_action
);
void rrr_send_loop_destroy (
		struct rrr_send_loop *send_loop
);
int rrr_send_loop_new (
		struct rrr_send_loop **result,
		struct rrr_event_queue *queue,
		const char *debug_name,
		int do_preserve_order,
		uint64_t ttl_us,
		uint64_t timeout_us,
		enum rrr_send_loop_action timeout_action,
		int (*push_callback)(struct rrr_msg_holder *entry, void *arg),
		int (*return_callback)(struct rrr_msg_holder *entry, void *arg),
		void (*run_callback)(void *arg),
		void *callback_arg
);
void rrr_send_loop_entry_prepare (
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
);
void rrr_send_loop_entry_touch_related (
		struct rrr_send_loop *send_loop,
		const struct rrr_msg_holder *entry_locked,
		int (*cmp)(const struct rrr_msg_holder *entry, const struct rrr_msg_holder *entry_related, void *arg),
		void *callback_arg
);
int rrr_send_loop_count (
		struct rrr_send_loop *send_loop
);
void rrr_send_loop_push (
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
);
void rrr_send_loop_unshift (
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
);
void rrr_send_loop_unshift_if_timed_out (
		int *did_unshift,
		struct rrr_send_loop *send_loop,
		struct rrr_msg_holder *entry_locked
);
void rrr_send_loop_clear (
		struct rrr_send_loop *send_loop
);
int rrr_send_loop_run (
		struct rrr_send_loop *send_loop
);
int rrr_send_loop_event_pending (
		struct rrr_send_loop *send_loop
);
void rrr_send_loop_event_remove (
		struct rrr_send_loop *send_loop
);
void rrr_send_loop_event_add_or_remove (
		struct rrr_send_loop *send_loop
);

#endif /* RRR_SEND_LOOP_H */
