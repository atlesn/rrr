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

#ifndef RRR_MSGDB_HELPER_H
#define RRR_MSGDB_HELPER_H

#include "rrr_types.h"

struct rrr_msgdb_client_conn;
struct rrr_instance_runtime_data;
struct rrr_msg_msg;
struct rrr_instance_friend_collection;

int rrr_msgdb_helper_send_to_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_msg_msg *msg
);
int rrr_msgdb_helper_delete (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_msg_msg *msg
);
int rrr_msgdb_helper_get_from_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const char *topic,
		int (*callback)(struct rrr_msg_msg **msg, void *arg),
		void *callback_arg
);
int rrr_msgdb_helper_get_from_msgdb_to_broker (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const char *topic,
		const struct rrr_instance_friend_collection *nexthops,
		const char *debug_reason
);
int rrr_msgdb_helper_iterate_min_age (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		rrr_length min_age_s,
		uint64_t ttl_us,
		int (*callback)(struct rrr_msg_msg **msg, void *arg),
		void *callback_arg
);
int rrr_msgdb_helper_iterate_min_age_to_broker (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_instance_friend_collection *nexthops,
		const char *debug_reason,
		rrr_length min_age_s,
		uint64_t ttl_us
);
int rrr_msgdb_helper_tidy (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		rrr_length ttl_s
);

#endif /* RRR_MSGDB_HELPER_H */
