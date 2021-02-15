/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MESSAGE_HOLDER_SLOT_H
#define RRR_MESSAGE_HOLDER_SLOT_H

#include <sys/socket.h>
#include <stdint.h>

struct rrr_msg_holder;
struct rrr_msg_holder_slot;
struct rrr_msg_holder_collection;

int rrr_msg_holder_slot_new (
		struct rrr_msg_holder_slot **target
);
int rrr_msg_holder_slot_reader_count_set (
		struct rrr_msg_holder_slot *slot,
		int reader_count
);
void rrr_msg_holder_slot_destroy (
		struct rrr_msg_holder_slot *slot
);
void rrr_msg_holder_slot_get_stats (
		uint64_t *entries_deleted,
		uint64_t *entries_written,
		struct rrr_msg_holder_slot *slot
);
int rrr_msg_holder_slot_count (
		struct rrr_msg_holder_slot *slot
);
int rrr_msg_holder_slot_read (
		struct rrr_msg_holder_slot *slot,
		void *self,
		int (*callback)(int *do_keep, struct rrr_msg_holder *entry, void *arg),
		void *callback_arg,
		unsigned int wait_ms
);
int rrr_msg_holder_slot_discard (
		int *did_discard,
		struct rrr_msg_holder_slot *slot,
		void *self
);
int rrr_msg_holder_slot_write (
		struct rrr_msg_holder_slot *slot,
		const struct sockaddr *addr,
		socklen_t addr_len,
		int protocol,
		int (*callback)(int *do_drop, int *do_again, struct rrr_msg_holder *entry, void *arg),
		void *callback_arg,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_msg_holder_slot_write_clone (
		struct rrr_msg_holder_slot *slot,
		const struct rrr_msg_holder *source,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_msg_holder_slot_write_incref (
		struct rrr_msg_holder_slot *slot,
		struct rrr_msg_holder *entry_new,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_msg_holder_slot_write_from_collection (
		struct rrr_msg_holder_slot *slot,
		struct rrr_msg_holder_collection *collection,
		int (*check_cancel_callback)(void *arg),
		void *check_cancel_callback_arg
);
int rrr_msg_holder_slot_with_lock_do (
		struct rrr_msg_holder_slot *slot,
		int (*callback)(void *callback_arg_1, void *callback_arg_2),
		void *callback_arg_1,
		void *callback_arg_2
);

#endif /* RRR_MESSAGE_HOLDER_SLOT_H */
