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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/poll_helper.h"
#include "../lib/msgdb_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/instance_friends.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/event/event.h"
#include "../lib/event/event_collection.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/msgdb/msgdb_client.h"

struct cacher_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_event_collection events;

	struct rrr_msgdb_client_conn msgdb_conn;

	char *msgdb_socket;
	char *request_tag;

	rrr_setting_uint message_ttl_seconds;
	uint64_t message_ttl_us;

	rrr_setting_uint message_memory_ttl_seconds;
	uint64_t message_memory_ttl_us;

	rrr_setting_uint revive_age_seconds;
	rrr_setting_uint revive_interval_seconds;

	int do_forward_requests;
	int do_forward_data;
	int do_forward_other;
	int do_memory_consume_requests;
	int do_empty_is_delete;
	int do_no_update;

	struct rrr_msg_holder_collection memory_cache;

	struct rrr_instance_friend_collection receivers_data;
	struct rrr_instance_friend_collection receivers_requests;
	struct rrr_instance_friend_collection receivers_other;
	struct rrr_instance_friend_collection receivers_revive;
};

static void cacher_data_init(struct cacher_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));
}

static void cacher_data_cleanup(void *arg) {
	struct cacher_data *data = arg;

	rrr_event_collection_clear(&data->events);

	rrr_msgdb_client_close(&data->msgdb_conn);

	RRR_FREE_IF_NOT_NULL(data->msgdb_socket);
	RRR_FREE_IF_NOT_NULL(data->request_tag);

	RRR_DBG_1("Cacher instance %s: Memory cache count at cleanup is %i\n",
		INSTANCE_D_NAME(data->thread_data), RRR_LL_COUNT(&data->memory_cache));
	rrr_msg_holder_collection_clear(&data->memory_cache);

	rrr_instance_friend_collection_clear(&data->receivers_data);
	rrr_instance_friend_collection_clear(&data->receivers_requests);
	rrr_instance_friend_collection_clear(&data->receivers_other);
}

struct cacher_broker_callback_data {
	struct rrr_msg_msg **msg_ptr;
};

static int cacher_broker_callback (struct rrr_msg_holder *new_entry, void *arg) {
	struct cacher_broker_callback_data *callback_data = arg;

	rrr_msg_holder_set_data_unlocked(new_entry, *callback_data->msg_ptr, MSG_TOTAL_SIZE(*callback_data->msg_ptr));
	*callback_data->msg_ptr = NULL;

	rrr_msg_holder_unlock(new_entry);
	return 0;
}

struct cacher_get_from_msgdb_callback_data {
	struct cacher_data *data;
	const char *topic;
};

static int cacher_get_from_msgdb_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct cacher_get_from_msgdb_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = rrr_msgdb_client_cmd_get(&msg_tmp, conn, callback_data->topic))) {
		goto out;
	}

	if (msg_tmp != NULL) {
		RRR_DBG_2("cacher instance %s output message with timestamp %" PRIu64 " (requested) from message DB\n",
				INSTANCE_D_NAME(callback_data->data->thread_data),
				msg_tmp->timestamp
		);

		struct cacher_broker_callback_data broker_callback_data = {
			&msg_tmp
		};

		if ((ret = rrr_message_broker_write_entry (
				INSTANCE_D_BROKER_ARGS(callback_data->data->thread_data),
				NULL,
				0,
				0,
				&callback_data->data->receivers_data,
				cacher_broker_callback,
				&broker_callback_data,
				INSTANCE_D_CANCEL_CHECK_ARGS(callback_data->data->thread_data)
		)) != 0) {
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int cacher_get_from_msgdb (
		struct cacher_data *data,
		const char *topic
) {
	int ret = 0;

	struct cacher_get_from_msgdb_callback_data callback_data = {
		data,
		topic
	};

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			&data->msgdb_conn,
			data->msgdb_socket,
			INSTANCE_D_EVENTS(data->thread_data),
			cacher_get_from_msgdb_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed to get message from  message DB in cacher_get_id_from_msgdb\n");
		goto out;
	}

	out:
	return ret;
}

static int cacher_get_from_memory_cache (
		int *result_found,
		struct cacher_data *data,
		const char *topic
) {
	int ret = 0;

	*result_found = 0;

	RRR_LL_ITERATE_BEGIN(&data->memory_cache, struct rrr_msg_holder);
		rrr_msg_holder_lock(node);

		const struct rrr_msg_msg *msg = node->message;

		if (rrr_msg_msg_ttl_ok(msg, data->message_memory_ttl_us)) {
			// NULL topic is used for tidy operation
			if (topic != NULL && rrr_msg_msg_topic_equals(msg, topic)) {
				RRR_DBG_2("cacher instance %s output message with timestamp %" PRIu64 " (requested) from memory cache\n",
						INSTANCE_D_NAME(data->thread_data),
						msg->timestamp
				);

				if ((ret = rrr_message_broker_clone_and_write_entry (
						INSTANCE_D_BROKER_ARGS(data->thread_data),
						node,
						&data->receivers_data
				)) != 0) {
					RRR_MSG_0("Failed to write message from memory cache to output buffer in cacher instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
					// return value propagates, must unlock at loop out
				}

				*result_found = 1;
	
				RRR_LL_ITERATE_LAST();
			}
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
		}

		rrr_msg_holder_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->memory_cache, 0; rrr_msg_holder_decref(node));

	return ret;
}

static void cacher_tidy_memory_cache (
		int *deleted_entries,
		struct cacher_data *data
) {
	*deleted_entries = 0;

	int count_before = RRR_LL_COUNT(&data->memory_cache);

	int result_found_dummy = 0;
	cacher_get_from_memory_cache(&result_found_dummy, data, NULL);

	*deleted_entries = count_before - RRR_LL_COUNT(&data->memory_cache);
}

static int cacher_save_to_memory_cache (
		struct cacher_data *data,
		const char *topic,
		const struct rrr_msg_holder *entry,
		int do_delete
) {
	int ret = 0;

	struct rrr_msg_holder *entry_new = NULL;

	// Always delete to remove any duplicate
	RRR_LL_ITERATE_BEGIN(&data->memory_cache, struct rrr_msg_holder);
		rrr_msg_holder_lock(node);

		const struct rrr_msg_msg *msg = node->message;

		if (rrr_msg_msg_topic_equals(msg, topic)) {
			RRR_LL_ITERATE_LAST();
			RRR_LL_ITERATE_SET_DESTROY();
		}

		rrr_msg_holder_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->memory_cache, 0; rrr_msg_holder_decref(node));

	if (!do_delete) {
		if ((ret = rrr_msg_holder_util_clone_no_locking_no_metadata (
				&entry_new,
				entry
		)) != 0) {
			RRR_MSG_0("Failed to clone entry while adding to memory cache in cacher instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		rrr_msg_holder_lock(entry_new);
		RRR_LL_APPEND(&data->memory_cache, entry_new);
		rrr_msg_holder_unlock(entry_new);
		entry_new = NULL;
	}

	out:
	if (entry_new != NULL) {
		rrr_msg_holder_decref(entry_new);
	}
	return ret;
}

static int cacher_store (
		struct cacher_data *data,
		const char *topic,
		const struct rrr_msg_holder *entry,
		const struct rrr_msg_msg *msg,
		int do_delete
) {
	int ret = 0;

	if (data->msgdb_socket != NULL) {
		if (do_delete) {
			if ((ret = rrr_msgdb_helper_delete (
					&data->msgdb_conn,
					data->msgdb_socket,
					data->thread_data,
					msg
			)) != 0) {
				goto out;
			}
		}
		else {
			if ((ret = rrr_msgdb_helper_send_to_msgdb (
					&data->msgdb_conn,
					data->msgdb_socket,
					data->thread_data,
					msg
			)) != 0) {
				goto out;
			}
		}
	}

	if (data->message_memory_ttl_us > 0 && (ret = cacher_save_to_memory_cache (data, topic, entry, do_delete)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int cacher_process (
		const struct rrr_instance_friend_collection **do_forward_to,
		struct cacher_data *data,
		const struct rrr_msg_holder *entry
) {
	int ret = 0;

	*do_forward_to = NULL;

	const struct rrr_msg_msg *msg = entry->message;

	char *topic_tmp = NULL;

	if (data->message_ttl_us > 0 && !rrr_msg_msg_ttl_ok(msg, data->message_ttl_us)) {
		RRR_MSG_0("Warning: Received message in cacher instance %s with expired TTL, limit is set to %" PRIrrrbl " seconds. Dropping message.\n",
				INSTANCE_D_NAME(data->thread_data), data->message_ttl_seconds);
		goto out;
	}

	if (MSG_TOPIC_LENGTH(msg) == 0) {
		if (data->do_forward_other) {
			RRR_DBG_2("cacher instance %s forwarding other message with timestamp %" PRIu64 " without topic\n",
					INSTANCE_D_NAME(data->thread_data),
					msg->timestamp
			);
			*do_forward_to = &data->receivers_other;
		}
		else {
			RRR_MSG_0("Warning: Received a message in cacher instance %s without a topic, dropping it per configuration\n",
				INSTANCE_D_NAME(data->thread_data));
		}
		goto out;
	}

	if ((ret = rrr_msg_msg_topic_get(&topic_tmp, msg)) != 0) {
		RRR_MSG_0("Failed to get topic from message in cacher_process\n");
		goto out;
	}

	//////////////////////////
	// Request 
	/////////////////////

	if (data->request_tag != NULL && rrr_array_message_has_tag(msg, data->request_tag)) {
		RRR_DBG_2("cacher instance %s request message with timestamp %" PRIu64 " with topic '%s'\n",
				INSTANCE_D_NAME(data->thread_data),
				msg->timestamp,
				topic_tmp
		);

		if (data->message_memory_ttl_us > 0) {
			int result_found = 0;
			if ((ret = cacher_get_from_memory_cache(&result_found, data, topic_tmp)) != 0) {
				goto out;
			}
			if (result_found) {
				if (!data->do_memory_consume_requests && data->do_forward_requests) {
					*do_forward_to = &data->receivers_requests;
				}
	
				RRR_DBG_2("cacher instance %s request message with timestamp %" PRIu64 " with topic '%s' forward decition after memory result is %s\n",
						INSTANCE_D_NAME(data->thread_data),
						msg->timestamp,
						topic_tmp,
						*do_forward_to != NULL ? "'yes'" : "'no'"
				);

				goto out;
			}
		}

		if ((ret = cacher_get_from_msgdb(data, topic_tmp)) != 0) {
			RRR_MSG_0("Warning: Request to message DB failed in cacher instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
			ret = 0;
		}

		if (data->do_forward_requests) {
			*do_forward_to = &data->receivers_requests;
		}

		RRR_DBG_2("cacher instance %s request message with timestamp %" PRIu64 " with topic '%s' forward decition (default) is %s\n",
				INSTANCE_D_NAME(data->thread_data),
				msg->timestamp,
				topic_tmp,
				*do_forward_to != NULL ? "'yes'" : "'no'"
		);

		goto out;
	}

	//////////////////////////
	// Store or delete
	/////////////////////

	if (data->do_no_update) {
		if (data->do_forward_other) {
			RRR_DBG_2("cacher instance %s forwarding other message with timestamp %" PRIu64 " (updates are disabled)\n",
					INSTANCE_D_NAME(data->thread_data),
					msg->timestamp
			);
			*do_forward_to = &data->receivers_other;
		}
		else {
			RRR_MSG_0("Warning: Received a message in cacher instance %s which will be dropped without processing (updates and forwarding is disabled and message is not a reqest)\n",
				INSTANCE_D_NAME(data->thread_data));
		}
		goto out;
	}

	RRR_DBG_2("cacher instance %s %s with timestamp %" PRIu64 " with topic '%s'%s\n",
			INSTANCE_D_NAME(data->thread_data),
			MSG_DATA_LENGTH(msg) == 0 && data->do_empty_is_delete
				? "processing delete message"
				: "storing data message",
			msg->timestamp,
			topic_tmp,
			data->do_forward_data
				? " (and forwarding)"
				: ""
	);

	if ((ret = cacher_store (
			data,
			topic_tmp,
			entry,
			msg,
			MSG_DATA_LENGTH(msg) == 0 && data->do_empty_is_delete
				? 1 /* Delete command */
				: 0 /* Store command */
	)) != 0) {
		goto out;
	}

	if (data->do_forward_data) {
		*do_forward_to = &data->receivers_data;
	}

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	return ret;
}

static int cacher_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct cacher_data *data = thread_data->private_data;

	int ret = 0;

	// We check stuff with the watchdog in case we are slow to process messages
	if (rrr_thread_signal_encourage_stop_check(INSTANCE_D_THREAD(data->thread_data))) {
		ret = RRR_FIFO_PROTECTED_SEARCH_STOP;
		goto out;
	}
	rrr_thread_watchdog_time_update(INSTANCE_D_THREAD(data->thread_data));

	// Do not produce errors for message process failures, just drop them

	const struct rrr_instance_friend_collection *forward_to = NULL;

	if (cacher_process(&forward_to, data, entry) != 0) {
		RRR_MSG_0("Warning: Failed to process message in cacher instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (forward_to != NULL && (ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(data->thread_data), 
			entry,
			forward_to,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Failed to write entry in cacher_poll_callback of instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
		rrr_msg_holder_unlock(entry);
		return ret;
}

static int cacher_event_tidy_wait_callback (
		void *arg
) {
	struct cacher_data *data = arg;

	rrr_posix_usleep(5 * 1000); // 5 ms

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data));
}

static int cacher_event_tidy_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct cacher_data *data = arg;

	return rrr_msgdb_client_cmd_tidy_with_wait_callback (
			conn,
			rrr_length_from_biglength_bug_const(data->message_ttl_seconds),
			cacher_event_tidy_wait_callback,
			data
	);
}

static void cacher_event_tidy (
		int fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct cacher_data *data = thread_data->private_data;

	if (data->message_ttl_seconds == 0) {
		RRR_DBG_1("Peridoc tidy in cacher instance %s: No TTL set, not performing tidy\n", INSTANCE_D_NAME(thread_data));
	}
	else { 
		RRR_DBG_1("cacher instance %s tidy message database...\n", INSTANCE_D_NAME(data->thread_data));

		int ret_tmp = rrr_msgdb_client_conn_ensure_with_callback (
				&data->msgdb_conn,
				data->msgdb_socket,
				INSTANCE_D_EVENTS(data->thread_data),
				cacher_event_tidy_callback,
				data
		);

		RRR_DBG_1("cacher instance %s tidy message database completed with status %i\n",
				INSTANCE_D_NAME(data->thread_data), ret_tmp);
	}

	if (data->message_memory_ttl_seconds == 0) {
		RRR_DBG_1("Peridoc tidy in cacher instance %s: No memory TTL set, not performing tidy\n", INSTANCE_D_NAME(thread_data));
	}
	else {
		RRR_DBG_1("cacher instance %s tidy memory cache, entry count is %i...\n",
			INSTANCE_D_NAME(data->thread_data), RRR_LL_COUNT(&data->memory_cache));

		int deleted_entries = 0;
		cacher_tidy_memory_cache(&deleted_entries, data);

		RRR_DBG_1("cacher instance %s tidy memory cache completed, %i %s removed\n",
				INSTANCE_D_NAME(data->thread_data), deleted_entries, (deleted_entries == 1 ? "message" : "messages"));
	}

	// Check for encourage stop, return code does not always
	// propagate from msgdb client and we also cannot 
	// distinguish between socket EOF and encourage stop from
	// wait the callback.
	if (rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread) != 0) {
		RRR_DBG_1("cacher instance %s received encourage stop while tidying, exiting now.\n",
				INSTANCE_D_NAME(thread_data));
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(thread_data));
	}
}

static int cacher_event_revive_wait_callback (
		void *arg
) {
	struct cacher_data *data = arg;
	sched_yield();
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data));
}

static int cacher_event_revive_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct cacher_data *data = arg;

	int ret = 0;

	struct rrr_array files = {0};
	char *path_tmp = NULL;
	struct rrr_msg_msg *msg_tmp = NULL;

	if ((ret = rrr_msgdb_client_cmd_idx (
			&files,
			conn,
			rrr_length_from_biglength_bug_const(data->revive_age_seconds),
			cacher_event_revive_wait_callback,
			data
	)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(&files, struct rrr_type_value);
		RRR_FREE_IF_NOT_NULL(path_tmp);
		if ((ret = node->definition->to_str(&path_tmp, node)) != 0) {
			RRR_MSG_0("Failed to extract path in %s of cacher instance %s\n", __func__, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

	 	RRR_FREE_IF_NOT_NULL(msg_tmp);
		if ((ret = rrr_msgdb_client_cmd_get(&msg_tmp, conn, path_tmp)) != 0) {
			RRR_MSG_0("Failed to get message in %s of cacher instance %s\n", __func__, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (msg_tmp == NULL) {
			// Message no longer exists
			RRR_LL_ITERATE_NEXT();
		}

		if (data->message_ttl_us > 0 && !rrr_msg_msg_ttl_ok(msg_tmp, data->message_ttl_us)) {
			// TTL expired
			RRR_LL_ITERATE_NEXT();
		}

		RRR_DBG_2("cacher instance %s output message with timestamp %" PRIu64 " (revived) from message DB\n",
				INSTANCE_D_NAME(data->thread_data),
				msg_tmp->timestamp
		);

		struct cacher_broker_callback_data callback_data = {
			&msg_tmp
		};

		if ((ret = rrr_message_broker_write_entry (
				INSTANCE_D_BROKER_ARGS(data->thread_data),
				NULL,
				0,
				0,
				&data->receivers_revive,
				cacher_broker_callback,
				&callback_data,
				INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
		)) != 0) {
			goto out;
		}

		if ((ret = rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data))) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	RRR_FREE_IF_NOT_NULL(path_tmp);
	rrr_array_clear(&files);
	return ret;
}

static void cacher_event_revive (
		int fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct cacher_data *data = thread_data->private_data;

	int ret_tmp = rrr_msgdb_client_conn_ensure_with_callback (
			&data->msgdb_conn,
			data->msgdb_socket,
			INSTANCE_D_EVENTS(data->thread_data),
			cacher_event_revive_callback,
			data
	);

	if (ret_tmp == RRR_THREAD_STOP) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(thread_data));
	}
	else if (ret_tmp != 0) {
		RRR_MSG_0("Warning: Revive failed in cacher instance %s return was %i\n",
			INSTANCE_D_NAME(thread_data), ret_tmp);
	}
}

static int cacher_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	return rrr_poll_do_poll_delete (amount, thread_data, cacher_poll_callback);
}

static int cacher_event_periodic (void *arg) {
	struct rrr_thread *thread = arg;
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

static int cacher_parse_receivers (
		struct rrr_instance_friend_collection *target,
		struct cacher_data *data,
		struct rrr_instance_config_data *config,
		const char *setting
) {
	int ret = 0;

	if ((ret = rrr_instance_config_friend_collection_populate_from_config (
			target,
			INSTANCE_D_INSTANCES(data->thread_data),
			config,
			setting
	)) != 0) {
		RRR_MSG_0("Failed to add receivers from %s in cacher instance %s\n",
			setting, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(target, struct rrr_instance_friend);
		if (!rrr_instance_has_sender (node->instance, INSTANCE_D_INSTANCE(data->thread_data))) {
			RRR_MSG_0("Specified receiver %s in %s of cacher instance %s does not have this cacher instance specified as sender\n",
				INSTANCE_M_NAME(node->instance),
				setting,
				INSTANCE_D_NAME(data->thread_data)
			);
			ret = 1;
			goto out;
		}
	RRR_LL_ITERATE_END();
	
	out:
	return ret;
}

static int cacher_parse_config (struct cacher_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("cacher_msgdb_socket", msgdb_socket);
	if (data->msgdb_socket == NULL || *(data->msgdb_socket) == '\0') {
		RRR_MSG_0("Required aramenter cacher_msgdb_socket missing in cacher instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("cacher_request_tag", request_tag);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("cacher_forward_requests", do_forward_requests, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("cacher_forward_data", do_forward_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("cacher_forward_other", do_forward_other, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("cacher_memory_consume_requests", do_memory_consume_requests, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("cacher_empty_is_delete", do_empty_is_delete, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("cacher_no_update", do_no_update, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("cacher_ttl_seconds", message_ttl_seconds, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("cacher_memory_ttl_seconds", message_memory_ttl_seconds, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("cacher_revive_age_seconds", revive_age_seconds, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("cacher_revive_interval_seconds", revive_interval_seconds, 60 /* Default 1 minute */);

	if (data->message_ttl_seconds > UINT32_MAX) {
		RRR_MSG_0("Parameter message_ttl_seconds in cacher instance %s exceeds maximum value (%llu>%llu)\n",
			config->name,
			(unsigned long long int) data->message_ttl_seconds,
			(unsigned long long int) UINT32_MAX
		);
		ret = 1;
		goto out;
	}

	if (data->message_memory_ttl_seconds > UINT32_MAX) {
		RRR_MSG_0("Parameter message_memory_ttl_seconds in cacher instance %s exceeds maximum value (%llu>%llu)\n",
			config->name,
			(unsigned long long int) data->message_memory_ttl_seconds,
			(unsigned long long int) UINT32_MAX
		);
		ret = 1;
		goto out;
	}

	if (data->revive_age_seconds > UINT32_MAX) {
		RRR_MSG_0("Parameter revive_age_seconds in cacher instance %s exceeds maximum value (%llu>%llu)\n",
			config->name,
			(unsigned long long int) data->revive_age_seconds,
			(unsigned long long int) UINT32_MAX
		);
		ret = 1;
		goto out;
	}

	if (data->revive_interval_seconds > UINT32_MAX || data->revive_interval_seconds < 1) {
		RRR_MSG_0("Parameter revive_interval_seconds in cacher instance %s out of range (%llu>%llu or %llu<1)\n",
			config->name,
			(unsigned long long int) data->revive_interval_seconds,
			(unsigned long long int) UINT32_MAX,
			(unsigned long long int) data->revive_interval_seconds
		);
		ret = 1;
		goto out;
	}

	data->message_ttl_us = data->message_ttl_seconds * 1000 * 1000;
	data->message_memory_ttl_us = data->message_memory_ttl_seconds * 1000 * 1000;

	ret |= cacher_parse_receivers (&data->receivers_requests, data, config, "cacher_request_receivers");
	ret |= cacher_parse_receivers (&data->receivers_data, data, config, "cacher_data_receivers");
	ret |= cacher_parse_receivers (&data->receivers_other, data, config, "cacher_other_receivers");
	ret |= cacher_parse_receivers (&data->receivers_revive, data, config, "cacher_revive_receivers");

	if (ret != 0) {
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_cacher (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct cacher_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("cacher thread thread_data is %p\n", thread_data);

	cacher_data_init(data, thread_data);

	pthread_cleanup_push(cacher_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (cacher_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("cacher instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_handle tidy_event;
	if (rrr_event_collection_push_periodic (
			&tidy_event,
			&data->events,
			cacher_event_tidy,
			thread,
			300 * 1000 * 1000 /* 5 minutes */
	) != 0) {
		RRR_MSG_0("Failed to create tidy event in cacher instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}
	EVENT_ADD(tidy_event);

	if (data->revive_age_seconds > 0) {
		rrr_event_handle revive_event;
		if (rrr_event_collection_push_periodic (
				&revive_event,
				&data->events,
				cacher_event_revive,
				thread,
				data->revive_interval_seconds * 1000 * 1000
		) != 0) {
			RRR_MSG_0("Failed to create revive event in cacher instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		EVENT_ADD(revive_event);
	}

	// Run tidy once upon startup
	EVENT_ACTIVATE(tidy_event);

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000, // 1 s
			cacher_event_periodic,
			thread
	);

	out_message:
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread cacher %p exiting\n", thread);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_cacher,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "cacher";

__attribute__((constructor)) void load(void) {
}

static struct rrr_instance_event_functions event_functions = {
	cacher_event_broker_data_available
};

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy cacher module\n");
}

