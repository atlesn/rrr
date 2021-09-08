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

static int __rrr_msgdb_helper_send_to_msgdb_wait_callback (
		void *arg
) {
	struct rrr_instance_runtime_data *thread_data = arg;
	sched_yield();
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(thread_data));
}

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

	if ((ret = rrr_msgdb_client_send(conn, msg_new, __rrr_msgdb_helper_send_to_msgdb_wait_callback, callback_data->thread_data)) != 0) {	
		RRR_DBG_7("Failed to send message to msgdb in %s, return from send was %i\n",
			__func__, ret);
		goto out;
	}

	int positive_ack = 0;
	if ((ret = rrr_msgdb_client_await_ack(&positive_ack, conn)) != 0) {
		RRR_DBG_7("Failed to send message to msgdb in %s, return from await ack was %i\n",
			__func__, ret);
		ret = 1;
		goto out;
	}

	if (!positive_ack) {
		// Ensure failure is returned upon negative ACK
		RRR_DBG_7("Failed to send message to msgdb in %s, negative ACK received\n", __func__);
		ret = 1;
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
		const struct rrr_msg_msg *msg
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
			&callback_data
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
		const struct rrr_msg_msg *msg
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
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed to delete message from message DB in %s of instance %s\n",
			__func__, INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	return ret;
}

struct __rrr_msgdb_helper_broker_callback_data {
	struct rrr_msg_msg **msg_ptr;
};

static int __rrr_msgdb_helper_broker_callback (struct rrr_msg_holder *new_entry, void *arg) {
	struct __rrr_msgdb_helper_broker_callback_data *callback_data = arg;

	rrr_msg_holder_set_data_unlocked(new_entry, *callback_data->msg_ptr, MSG_TOTAL_SIZE(*callback_data->msg_ptr));
	*callback_data->msg_ptr = NULL;

	rrr_msg_holder_unlock(new_entry);
	return 0;
}

struct rrr_msgdb_helper_get_from_msgdb_callback_data {
	const char *topic;
	int (*callback)(struct rrr_msg_msg **msg, void *arg);
	void *callback_arg;
};

static int __rrr_msgdb_helper_get_from_msgdb_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct rrr_msgdb_helper_get_from_msgdb_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = rrr_msgdb_client_cmd_get(&msg_tmp, conn, callback_data->topic))) {
		goto out;
	}

	ret = callback_data->callback(&msg_tmp, callback_data->callback_arg);

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

int rrr_msgdb_helper_get_from_msgdb (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const char *topic,
		int (*callback)(struct rrr_msg_msg **msg, void *arg),
		void *callback_arg
) {
	int ret = 0;

	struct rrr_msgdb_helper_get_from_msgdb_callback_data callback_data = {
		topic,
		callback,
		callback_arg
	};

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_get_from_msgdb_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed to get message from message DB in %s of instance %s\n",
			__func__, INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	return ret;
}

struct rrr_msgdb_helper_get_from_msgdb_to_broker_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	const struct rrr_instance_friend_collection *nexthops;
	const char *debug_reason;
};

static int __rrr_msgdb_helper_get_from_msgdb_to_broker_callback (
		struct rrr_msg_msg **msg,
		void *arg
) {
	struct rrr_msgdb_helper_get_from_msgdb_to_broker_callback_data *callback_data = arg;

	int ret = 0;

	if (*msg == NULL) {
		goto out;
	}

	RRR_DBG_2("Instance %s output message with timestamp %" PRIu64 " (%s) from message DB\n",
			INSTANCE_D_NAME(callback_data->thread_data),
			(*msg)->timestamp,
			callback_data->debug_reason
	);

	struct __rrr_msgdb_helper_broker_callback_data broker_callback_data = {
		msg
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->thread_data),
			NULL,
			0,
			0,
			callback_data->nexthops,
			__rrr_msgdb_helper_broker_callback,
			&broker_callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(callback_data->thread_data)
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int rrr_msgdb_helper_get_from_msgdb_to_broker (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const char *topic,
		const struct rrr_instance_friend_collection *nexthops,
		const char *debug_reason
) {
	struct rrr_msgdb_helper_get_from_msgdb_to_broker_callback_data callback_data = {
		thread_data,
		nexthops,
		debug_reason
	};

	return rrr_msgdb_helper_get_from_msgdb (
			conn,
			socket,
			thread_data,
			topic,
			__rrr_msgdb_helper_get_from_msgdb_to_broker_callback,
			&callback_data
	 );
}

static int __rrr_msgdb_helper_iterate_wait_callback (
		void *arg
) {
	struct rrr_instance_runtime_data *thread_data = arg;
	sched_yield();
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(thread_data));
}

struct rrr_msgdb_helper_iterate_min_age_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	const rrr_length min_age_s;
	const uint64_t ttl_us;
	int (*callback)(struct rrr_msg_msg **msg, void *arg);
	void *callback_arg;
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
			&files,
			conn,
			rrr_length_from_biglength_bug_const(callback_data->min_age_s),
			__rrr_msgdb_helper_iterate_wait_callback,
			callback_data->thread_data
	)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&files, struct rrr_type_value);
		RRR_FREE_IF_NOT_NULL(path_tmp);
		if ((ret = node->definition->to_str(&path_tmp, node)) != 0) {
			RRR_MSG_0("Failed to extract path in %s of instance %s\n", __func__, INSTANCE_D_NAME(callback_data->thread_data));
			goto out;
		}

	 	RRR_FREE_IF_NOT_NULL(msg_tmp);
		if ((ret = rrr_msgdb_client_cmd_get(&msg_tmp, conn, path_tmp)) != 0) {
			RRR_MSG_0("Failed to get message in %s of instance %s\n", __func__, INSTANCE_D_NAME(callback_data->thread_data));
			goto out;
		}

		if (msg_tmp == NULL) {
			// Message no longer exists
			RRR_LL_ITERATE_NEXT();
		}

		if (callback_data->ttl_us > 0 && !rrr_msg_msg_ttl_ok(msg_tmp, callback_data->ttl_us)) {
			// TTL expired
			RRR_LL_ITERATE_NEXT();
		}

		if ((ret = callback_data->callback (&msg_tmp, callback_data->callback_arg)) != 0) {
			goto out;
		}

		if ((ret = rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(callback_data->thread_data))) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

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
		int (*callback)(struct rrr_msg_msg **msg, void *arg),
		void *callback_arg
) {
	struct rrr_msgdb_helper_iterate_min_age_callback_data callback_data = {
		thread_data,
		min_age_s,
		ttl_us,
		callback,
		callback_arg
	};

	return rrr_msgdb_client_conn_ensure_with_callback (
			conn,
			socket,
			INSTANCE_D_EVENTS(thread_data),
			__rrr_msgdb_helper_iterate_min_age_callback,
			&callback_data
	);
}

int rrr_msgdb_helper_iterate_min_age_to_broker (
		struct rrr_msgdb_client_conn *conn,
		const char *socket,
		struct rrr_instance_runtime_data *thread_data,
		const struct rrr_instance_friend_collection *nexthops,
		const char *debug_reason,
		rrr_length min_age_s,
		uint64_t ttl_us
) {
	struct rrr_msgdb_helper_get_from_msgdb_to_broker_callback_data callback_data = {
		thread_data,
		nexthops,
		debug_reason
	};

	return rrr_msgdb_helper_iterate_min_age (
			conn,
			socket,
			thread_data,
			min_age_s,
			ttl_us,
			__rrr_msgdb_helper_get_from_msgdb_to_broker_callback,
			&callback_data
	);
}
