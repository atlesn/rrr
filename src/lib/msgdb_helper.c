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
	const char *topic;
	const struct rrr_msg_msg *msg;
	int do_delete;
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

	MSG_SET_TYPE(msg_new, callback_data->do_delete ? MSG_TYPE_DEL : MSG_TYPE_PUT);

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

	if (!callback_data->do_delete && !positive_ack) {
		// Ensure failure is returned upon negative ACK (only relevant for stores)
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
		struct rrr_instance_runtime_data *thread_data,
		const char *socket,
		const char *topic,
		const struct rrr_msg_msg *msg,
		int do_delete
) {
	int ret = 0;

	if (socket == NULL) {
		RRR_BUG("BUG: Socket was NULL in %s\n", __func__);
	}

	struct rrr_msgdb_helper_send_to_msgdb_callback_final_data callback_data = {
		thread_data,
		topic,
		msg,
		do_delete
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
