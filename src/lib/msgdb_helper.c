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

#include "msgdb_helper.h"

#include "log.h"
#include "allocator.h"
#include "threads.h"
#include "instances.h"
#include "message_broker.h"
#include "array.h"
#include "util/macro_utils.h"
#include "msgdb/msgdb_client.h"
#include "messages/msg_msg.h"

struct rrr_msgdb_helper_send_to_msgdb_callback_final_data {
	struct rrr_instance_runtime_data *thread_data;
	const struct rrr_msg_msg *msg;
};

static int __rrr_msgdb_helper_send_to_msgdb_callback_final (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct rrr_msgdb_helper_send_to_msgdb_callback_final_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg_new = rrr_msg_msg_duplicate (callback_data->msg);
	if (msg_new == NULL) {
		RRR_MSG_0("Could not duplicate message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	MSG_SET_TYPE(msg_new,  MSG_TYPE_PUT);

	if ((ret = rrr_msgdb_client_send (
			conn,
			msg_new
	)) != 0) {
		RRR_DBG_7("Failed to send message to msgdb in %s, return from send was %i\n",
			__func__, ret);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_new);
	return ret;
}

int rrr_msgdb_helper_send_to_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_msg_msg *msg,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	int ret = 0;

	if (socket == NULL) {
		RRR_BUG("BUG: Socket was NULL in %s\n", __func__);
	}

	struct rrr_msgdb_helper_send_to_msgdb_callback_final_data callback_data = {
		thread_data,
		msg
	};

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_send_to_msgdb_callback_final,
			&callback_data,
			delivery_callback,
			delivery_callback_arg
	)) != 0) {
		RRR_MSG_0("Failed to send message to message DB in %s of instance %s\n",
			__func__, INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	return ret;
}

struct rrr_msgdb_helper_delete_callback_data {
	const struct rrr_msg_msg *msg;
};

static int __rrr_msgdb_helper_delete_callback (struct rrr_msgdb_client_conn *conn, void *callback_arg) {
	struct rrr_msgdb_helper_delete_callback_data *callback_data = callback_arg;

	int ret = 0;

	char *topic_tmp = NULL;

	if ((ret = rrr_msg_msg_topic_get(&topic_tmp, callback_data->msg)) != 0) {
		goto out;
	}

	ret = rrr_msgdb_client_cmd_del(conn, topic_tmp);

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	return ret;
}

int rrr_msgdb_helper_delete (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_msg_msg *msg,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	struct rrr_msgdb_helper_delete_callback_data callback_data = {
		msg
	};

	int ret = 0;

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_delete_callback,
			&callback_data,
			delivery_callback,
			delivery_callback_arg
	)) != 0) {
		RRR_MSG_0("Failed to delete message from message DB in %s of instance %s\n",
			__func__, INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	return ret;
}

struct rrr_msgdb_helper_get_from_msgdb_callback_data {
	const char *topic;
};

static int __rrr_msgdb_helper_get_from_msgdb_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct rrr_msgdb_helper_get_from_msgdb_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = rrr_msgdb_client_cmd_get(conn, callback_data->topic))) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

int rrr_msgdb_helper_get_from_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const char *topic,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	int ret = 0;

	struct rrr_msgdb_helper_get_from_msgdb_callback_data callback_data = {
		topic
	};

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_get_from_msgdb_callback,
			&callback_data,
			delivery_callback,
			delivery_callback_arg
	)) != 0) {
		RRR_MSG_0("Failed to get message from message DB in %s of instance %s\n",
			__func__, INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	return ret;
}


struct rrr_msgdb_helper_iterate_min_age_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	const rrr_length min_age_s;
	const uint64_t ttl_us;
};

static int __rrr_msgdb_helper_iterate_min_age_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct rrr_msgdb_helper_iterate_min_age_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_array files = {0};
	char *path_tmp = NULL;
	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = rrr_msgdb_client_cmd_idx (
			conn,
			rrr_length_from_biglength_bug_const(callback_data->min_age_s)
	)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	RRR_FREE_IF_NOT_NULL(path_tmp);
	rrr_array_clear(&files);
	return ret;
}

int rrr_msgdb_helper_iterate_min_age (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		rrr_length min_age_s,
		uint64_t ttl_us,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	struct rrr_msgdb_helper_iterate_min_age_callback_data callback_data = {
		thread_data,
		min_age_s,
		ttl_us
	};

	return rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_iterate_min_age_callback,
			&callback_data,
			delivery_callback,
			delivery_callback_arg
	);
}

int rrr_msgdb_helper_iterate (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	return rrr_msgdb_helper_iterate_min_age (
			conn,
			socket,
			thread_data,
			0,
			0,
			delivery_callback,
			delivery_callback_arg
	);
}

struct rrr_msgdb_helper_tidy_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	const rrr_length ttl_s;
};

static int __rrr_msgdb_helper_tidy_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct rrr_msgdb_helper_tidy_callback_data *callback_data = arg;

	return rrr_msgdb_client_cmd_tidy (
			conn,
			callback_data->ttl_s
	);
}

int rrr_msgdb_helper_tidy (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		rrr_length ttl_s,
		int (*delivery_callback)(RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS),
		void *delivery_callback_arg
) {
	struct rrr_msgdb_helper_tidy_callback_data callback_data = {
		thread_data,
		ttl_s
	};

	return rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_tidy_callback,
			&callback_data,
			delivery_callback,
			delivery_callback_arg
	);
}
