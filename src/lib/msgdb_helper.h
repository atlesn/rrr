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
#include "read_constants.h"
#include "msgdb/msgdb_client.h"

struct rrr_msg_msg;
struct rrr_instance_runtime_data;
struct rrr_instance_friend_collection;

int rrr_msgdb_helper_send_to_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_msg_msg *msg,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_helper_delete (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_msg_msg *msg,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_helper_get_from_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const char *topic,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_helper_iterate_min_age (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		rrr_length min_age_s,
		uint64_t ttl_us,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_helper_iterate (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);
int rrr_msgdb_helper_tidy (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		rrr_length ttl_s,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
);

#endif /* RRR_MSGDB_HELPER_H */
