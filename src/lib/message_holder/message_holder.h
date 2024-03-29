/*

Read Route Record

Copyright (C) 2018-2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MESSAGE_HOLDER_H
#define RRR_MESSAGE_HOLDER_H

#include <sys/socket.h>

#include "../rrr_types.h"

struct rrr_msg_holder;
struct rrr_instance;
typedef struct rrr_instance_friend_collection rrr_msg_holder_nexthops;

void rrr_msg_holder_lock (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_lock_double (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_unlock (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_unlock_void (
		void *entry
);
void rrr_msg_holder_private_data_clear (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_private_data_set (
		struct rrr_msg_holder *entry,
		void *private_data,
		void (*private_data_destroy)(void *private_data)
);
uint64_t rrr_msg_holder_send_time (
		const struct rrr_msg_holder *entry
);
uint64_t rrr_msg_holder_send_index (
		const struct rrr_msg_holder *entry
);
int rrr_msg_holder_usercount (
		const struct rrr_msg_holder *entry
);
void rrr_msg_holder_incref_while_locked (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_incref_while_locked_void (
		void *entry
);
void rrr_msg_holder_incref (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_decref (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_decref_while_locked_and_unlock (
		struct rrr_msg_holder *entry
);
void rrr_msg_holder_decref_while_locked_and_unlock_void (
		void *entry
);
void rrr_msg_holder_decref_void (
		void *entry
);
int rrr_msg_holder_new (
		struct rrr_msg_holder **result,
		rrr_biglength data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol,
		void *message
);
int rrr_msg_holder_clone_no_data (
		struct rrr_msg_holder **result,
		const struct rrr_msg_holder *source
);
void rrr_msg_holder_nexthops_reset (
		struct rrr_msg_holder *entry
);
int rrr_msg_holder_nexthops_set (
		struct rrr_msg_holder *entry,
		const rrr_msg_holder_nexthops *hops
);
int rrr_msg_holder_nexthop_ok (
		const struct rrr_msg_holder *entry,
		const struct rrr_instance *instance
);
int rrr_msg_holder_nexthop_count (
		const struct rrr_msg_holder *entry
);
int rrr_msg_holder_nexthops_get (
		const struct rrr_msg_holder *entry,
		int (*callback)(const struct rrr_instance **instances, int count, void *arg),
		void *arg
);
void rrr_msg_holder_set_data_unlocked (
		struct rrr_msg_holder *target,
		void *message,
		rrr_biglength message_data_length
);
void rrr_msg_holder_set_unlocked (
		struct rrr_msg_holder *target,
		void *message,
		rrr_biglength message_data_length,
		const struct sockaddr *addr,
		socklen_t addr_len,
		uint8_t protocol
);
int rrr_msg_holder_address_matches (
		const struct rrr_msg_holder *a,
		const struct rrr_msg_holder *b
);
#endif /* RRR_MESSAGE_HOLDER_H */
