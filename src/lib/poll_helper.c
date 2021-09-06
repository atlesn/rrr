/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "allocator.h"
#include "poll_helper.h"
#include "instances.h"
#include "instance_config.h"
#include "fifo_protected.h"
#include "message_broker.h"
#include "message_holder/message_holder_struct.h"
#include "message_holder/message_holder.h"
#include "messages/msg_msg.h"

static int __rrr_poll_intermediate_callback_topic_filter (
		int *does_match,
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_msg_holder *entry
) {
	int ret = 0;

	*does_match = 0;

	if (MSG_TOPIC_LENGTH((const struct rrr_msg_msg *) entry->message) > 0 && rrr_msg_msg_topic_match (
			does_match,
			(const struct rrr_msg_msg *) entry->message,
			INSTANCE_D_TOPIC(thread_data)
	) != 0) {
		RRR_MSG_0("Error while matching topic against topic filter while polling in instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		char *topic_tmp = NULL;
		rrr_msg_msg_topic_get(&topic_tmp, (const struct rrr_msg_msg *) entry->message);
		RRR_DBG_3("Result of topic match while polling in instance %s with topic filter is '%s' topic is '%s': %s\n",
				INSTANCE_D_NAME(thread_data),
				INSTANCE_D_TOPIC_STR(thread_data),
				topic_tmp,
				(*does_match ? "MATCH" : "MISMATCH/DROPPED")
		);
		RRR_FREE_IF_NOT_NULL(topic_tmp);
	}

	out:
	return ret;
}

static void __rrr_poll_intermediate_callback_nexthop_check (
		int *nexthop_ok,
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_msg_holder *entry
) {
	*nexthop_ok = rrr_msg_holder_nexthop_ok(entry, INSTANCE_D_INSTANCE(thread_data));

	RRR_DBG_3("Result of nexthop check while polling in instance %s: %s\n",
		INSTANCE_D_NAME(thread_data),
		*nexthop_ok ? "OK" : "NOT OK/DROPPED"
	);
}

struct rrr_poll_intermediate_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE);
	void *arg;
};

static int __rrr_poll_intermediate_callback (
		RRR_MODULE_POLL_CALLBACK_SIGNATURE
) {
	struct rrr_poll_intermediate_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	int does_match = 1;
	int nexthop_ok = 1;

	if (callback_data->thread_data->init_data.topic_first_token != NULL) {
		if ((ret = __rrr_poll_intermediate_callback_topic_filter(&does_match, callback_data->thread_data, entry)) != 0) {
			goto out;
		}
	}

	__rrr_poll_intermediate_callback_nexthop_check(&nexthop_ok, callback_data->thread_data, entry);

	if (does_match && nexthop_ok) {
		// Callback unlocks
		return callback_data->callback(entry, callback_data->arg);
	}

	out:
		rrr_msg_holder_unlock(entry);
		return ret;
}

int rrr_poll_do_poll_delete_custom_arg (
		uint16_t *amount,
		struct rrr_instance_runtime_data *thread_data,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE),
		void *callback_arg
) {
	struct rrr_poll_intermediate_callback_data callback_data = {
		thread_data,
		callback,
		callback_arg
	};

	int message_broker_flags = 0;

	if (!(INSTANCE_D_INSTANCE(thread_data)->misc_flags & RRR_INSTANCE_MISC_OPTIONS_DISABLE_BACKSTOP)) {
		message_broker_flags |= RRR_MESSAGE_BROKER_POLL_F_CHECK_BACKSTOP;
	}

	return rrr_message_broker_poll_delete (
			amount,
			INSTANCE_D_HANDLE(thread_data),
			message_broker_flags,
			__rrr_poll_intermediate_callback,
			&callback_data
	);
}

int rrr_poll_do_poll_delete (
		uint16_t *amount,
		struct rrr_instance_runtime_data *thread_data,
		int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE)
) {
	return rrr_poll_do_poll_delete_custom_arg(amount, thread_data, callback, thread_data);
}
