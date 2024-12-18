/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdlib.h>

#include "../log.h"
#include "../allocator.h"

#include "cmodule_helper.h"
#include "cmodule_main.h"
#include "cmodule_worker.h"
#include "cmodule_channel.h"
#include "cmodule_struct.h"

#include "../fifo_protected.h"
#include "../modules.h"
#include "../messages/msg_addr.h"
#include "../messages/msg_log.h"
#include "../messages/msg_msg.h"
#include "../instances.h"
#include "../instance_config.h"
#include "../stats/stats_instance.h"
#include "../stats/stats_message.h"
#include "../message_broker.h"
#include "../poll_helper.h"
#include "../threads.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../event/event_functions.h"
#include "../message_holder/message_holder.h"
#include "../message_holder/message_holder_struct.h"
#include "../util/macro_utils.h"

#define WORKER_LOOP_BEGIN()                                               \
	do { for (int _i = 0; _i < cmodule->worker_count; _i++) {         \
		struct rrr_cmodule_worker *worker = &cmodule->workers[_i]

#define WORKER_LOOP_END()                                                 \
	}} while(0)

const struct rrr_cmodule_config_data *rrr_cmodule_helper_config_data_get (
		struct rrr_instance_runtime_data *thread_data
) {
	return &(INSTANCE_D_CMODULE(thread_data)->config_data);
}

struct rrr_cmodule_helper_read_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	const struct rrr_msg_msg *message;
	int count;
	struct rrr_msg_addr addr_message;
};

static int __rrr_cmodule_helper_read_final_callback (struct rrr_msg_holder *entry, void *arg) {
	struct rrr_cmodule_helper_read_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *message_new = rrr_msg_msg_duplicate(callback_data->message);
	if (message_new == NULL) {
		RRR_MSG_0("Could not duplicate message in %s for instance %s\n",
				__func__, INSTANCE_D_NAME(callback_data->thread_data));
		ret = 1;
		goto out;
	}

	rrr_msg_holder_set_unlocked (
			entry,
			message_new,
			MSG_TOTAL_SIZE(message_new),
			(struct sockaddr *) &callback_data->addr_message.addr,
			(socklen_t) RRR_MSG_ADDR_GET_ADDR_LEN(&callback_data->addr_message),
			callback_data->addr_message.protocol
	);
	message_new = NULL;

	callback_data->count++;

	out:
	RRR_FREE_IF_NOT_NULL(message_new);
	memset(&callback_data->addr_message, '\0', sizeof(callback_data->addr_message));
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int __rrr_cmodule_helper_read_callback (RRR_CMODULE_FINAL_CALLBACK_ARGS) {
	struct rrr_cmodule_helper_read_callback_data *callback_data = arg;

	callback_data->addr_message = *msg_addr;
	callback_data->message = msg;

	RRR_DBG_3("Received a message with timestamp %" PRIu64 " from worker fork in instance %s\n",
			msg->timestamp, INSTANCE_D_NAME(callback_data->thread_data));

	if (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->thread_data),
			NULL,
			0,
			0,
			NULL,
			__rrr_cmodule_helper_read_final_callback,
			callback_data,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			INSTANCE_D_THREAD(callback_data->thread_data)
	) != 0) {
		RRR_MSG_0("Could not write to output buffer in %s in instance %s\n",
				__func__, INSTANCE_D_NAME(callback_data->thread_data));
		return 1;
	}

	return 0;
}

static int __rrr_cmodule_helper_send_ping_worker (
		struct rrr_instance_runtime_data *thread_data,	
		struct rrr_cmodule_worker *worker
) {
	struct rrr_msg msg = {0};
	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PING, 0);

	// Don't set retry-timer, we have many opportunities to send pings anyway
	int ret_tmp = 0;
	if ((ret_tmp = rrr_cmodule_channel_send_message_simple (
			worker->channel_to_fork,
			worker->event_queue_worker,
			&msg,
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	)) != 0) {
		if (ret_tmp == RRR_THREAD_STOP) {
			return RRR_THREAD_STOP;
		}
		// Don't trigger error here. The reader thread will exit causing restart
		// if the fork fails (does not send any PONG back)
	}

	return 0;
}

static int __rrr_cmodule_helper_send_ping_all_workers (struct rrr_instance_runtime_data *thread_data) {
	int ret = 0;

	struct rrr_msg msg = {0};
	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PING, 0);

	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	WORKER_LOOP_BEGIN();
		if ((ret = __rrr_cmodule_helper_send_ping_worker(thread_data, worker)) != 0) {
			goto out;
		}
	WORKER_LOOP_END();

	out:
	return ret;
}

static int __rrr_cmodule_helper_send_message_to_fork (
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_cmodule_worker *worker,
		struct rrr_msg_holder *node
) {
	int ret = 0;

	struct rrr_msg_addr addr_msg;
	rrr_msg_addr_init(&addr_msg);

	if (node->addr_len > 0) {
		memcpy(&addr_msg.addr, &node->addr, sizeof(addr_msg.addr));
		RRR_MSG_ADDR_SET_ADDR_LEN(&addr_msg, node->addr_len);
		addr_msg.protocol = (uint8_t) node->protocol;
	}

	struct rrr_msg_msg *message = (struct rrr_msg_msg *) node->message;

	RRR_DBG_3("Transmission of message with timestamp %" PRIu64 " to worker fork '%s'\n",
			message->timestamp, worker->name);

	// Insert PING in between to make the child fork send PONGs back
	// while it processes messages
	if (worker->ping_counter++ % 8 == 0) {
		if ((ret = __rrr_cmodule_helper_send_ping_worker(thread_data, worker)) != 0) {
			goto out;
		}
	}

	rrr_time_us_t full_wait_time = RRR_US(0); // No waiting

	if ((ret = rrr_cmodule_channel_send_message_and_address (
			worker->channel_to_fork,
			worker->event_queue_worker,
			message,
			&addr_msg,
			full_wait_time,
			1, // 1 attempt
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	)) != 0) {
		if (ret == RRR_CMODULE_CHANNEL_FULL) {
			worker->to_fork_write_retry_counter += 1;
		}
		else {
			RRR_MSG_0("Error while sending message in %s\n", __func__);
		}
		goto out;
	}

	out:
	return ret;
}

static int __rrr_cmodule_helper_send_message_to_forks (
		struct rrr_instance_runtime_data *thread_data,
		struct rrr_msg_holder *entry_locked
) {
	int ret = 0;

	// Balanced algorithm

	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);
	struct rrr_cmodule_worker *preferred = &cmodule->workers[0];
	int preferred_count = 0;

	if ((ret = rrr_cmodule_channel_count(&preferred_count, preferred->channel_to_fork)) != 0) {
		goto out;
	}

 	WORKER_LOOP_BEGIN();
		int count = 0;
		if ((ret = rrr_cmodule_channel_count(&count, worker->channel_to_fork)) != 0) {
			goto out;
		}
		if (count < preferred_count) {
			preferred = worker;
			preferred_count = count;
		}
 	WORKER_LOOP_END();

 	// TODO : Upon retry, send to other worker

	if ((ret = __rrr_cmodule_helper_send_message_to_fork(thread_data, preferred, entry_locked)) != 0) {
		goto out;
	}

	out:
	return ret;
}

#include "../mmap_channel.h"

static int __rrr_cmodule_helper_input_buffer_process (
		struct rrr_instance_runtime_data *thread_data
) {
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	uint64_t time_limit = rrr_time_get_64() + 200 * 1000; // 200ms

	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&cmodule->input_queue, struct rrr_msg_holder);
		rrr_msg_holder_lock(node);

		if ((ret = __rrr_cmodule_helper_send_message_to_forks(thread_data, node)) != 0) {
			if (ret == RRR_CMODULE_CHANNEL_FULL) {
				// Putback
				ret = 0;
			}
			RRR_LL_ITERATE_LAST();
		}
		else {
			// Sent, remove from input queue
			RRR_LL_ITERATE_SET_DESTROY();
		}

		rrr_msg_holder_unlock(node);

		if (rrr_time_get_64() > time_limit) {
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&cmodule->input_queue, 0; rrr_msg_holder_decref(node));

	return ret;
}

static void __rrr_cmodule_helper_event_input_queue (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if (__rrr_cmodule_helper_input_buffer_process(thread_data) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(thread_data));
	}

	if (RRR_LL_COUNT(&cmodule->input_queue) == 0) {
		EVENT_REMOVE(cmodule->input_queue_event);
	}
}

struct rrr_cmodule_helper_event_app_periodic_callback_data {
	struct rrr_instance_runtime_data *thread_data;
	int (*app_periodic_callback)(RRR_CMODULE_HELPER_APP_PERIODIC_CALLBACK_ARGS);
};

static void __rrr_cmodule_helper_event_app_periodic_callback (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_cmodule_helper_event_app_periodic_callback_data *callback_data = arg;
	struct rrr_instance_runtime_data *thread_data = callback_data->thread_data;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	int ret_tmp;
	if ((ret_tmp = callback_data->app_periodic_callback(thread_data)) != 0) {
		RRR_MSG_0("Error %i from app periodic callback in %s in instance '%s'\n",
				ret_tmp, __func__, INSTANCE_D_NAME(thread_data));
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(thread_data));
	}
}

static int __rrr_cmodule_helper_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	RRR_DBG_2("Received a message in instance '%s' with timestamp %" PRIu64 ", transmitting to worker fork\n",
			INSTANCE_D_NAME(thread_data), ((struct rrr_msg_msg *) entry->message)->timestamp);

	RRR_LL_APPEND(&cmodule->input_queue, entry);
	rrr_msg_holder_incref_while_locked(entry);
	rrr_msg_holder_unlock(entry);

	if (__rrr_cmodule_helper_input_buffer_process(thread_data) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(thread_data));
	}

	return 0;
}

static int __rrr_cmodule_helper_event_message_broker_data_available (
		RRR_EVENT_FUNCTION_ARGS
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		return RRR_EVENT_EXIT;
	}

	EVENT_ADD(cmodule->input_queue_event);
	EVENT_ACTIVATE(cmodule->input_queue_event);

	RRR_POLL_HELPER_COUNTERS_UPDATE_BEFORE_POLL(thread_data);

	uint16_t amount_new = (uint16_t) (*amount > 32 ? 32 : *amount);
	*amount = (uint16_t) (*amount - amount_new);

	int ret = rrr_poll_do_poll_delete (
			&amount_new,
			thread_data,
			__rrr_cmodule_helper_poll_callback
	);

	*amount = (uint16_t) (*amount + amount_new);

	return ret;
}

static void __rrr_cmodule_helper_event_pause_check (RRR_EVENT_FUNCTION_PAUSE_ARGS) {
	struct rrr_instance_runtime_data *thread_data = callback_arg;
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	if (is_paused) {
		*do_pause = (RRR_LL_COUNT(&cmodule->input_queue) > (RRR_CMODULE_INPUT_QUEUE_MAX * 0.75));
	}
	else {
		*do_pause = (RRR_LL_COUNT(&cmodule->input_queue) > RRR_CMODULE_INPUT_QUEUE_MAX);
	}
}

struct rrr_instance_event_functions rrr_cmodule_helper_event_functions = {
	__rrr_cmodule_helper_event_message_broker_data_available
};

struct rrr_cmodule_read_from_fork_callback_data {
	struct rrr_cmodule_worker *worker;
	struct rrr_instance_runtime_data *thread_data;
	int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS);
	void *final_callback_arg;
	int read_count;
};

static int __rrr_cmodule_helper_read_from_fork_message_callback (
		const void *data,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	const struct rrr_msg_msg *msg = data;
	const struct rrr_msg_addr *msg_addr = data + MSG_TOTAL_SIZE(msg);

	if (MSG_TOTAL_SIZE(msg) + sizeof(*msg_addr) != data_size) {
		RRR_BUG("BUG: Size mismatch in %s for worker %s: %llu+%llu != %llu\n",
				__func__, callback_data->worker->name, (unsigned long long) MSG_TOTAL_SIZE(msg), (unsigned long long) sizeof(*msg_addr), (unsigned long long) data_size);
	}

	return callback_data->final_callback(msg, msg_addr, callback_data->final_callback_arg);
}

static int __rrr_cmodule_helper_read_from_fork_log_callback (
		const struct rrr_msg_log *msg_log,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	(void)(callback_data);

	if (!RRR_MSG_LOG_SIZE_OK(msg_log) || data_size != msg_log->msg_size) {
		RRR_BUG("BUG: Size error of message in %s\n", __func__);
	}

	// Messages are already printed to STDOUT or STDERR in the fork. Send to hooks
	// only (includes statistics engine)
	rrr_log_hooks_call_raw (
			msg_log->file,
			msg_log->line > INT_MAX ? 0 : (int) msg_log->line,
			msg_log->loglevel_translated,
			msg_log->loglevel_orig,
			msg_log->prefix_and_message,
			RRR_MSG_LOG_MSG_POS(msg_log)
	);

	return 0;
}

static int __rrr_cmodule_helper_read_from_fork_stats_callback (
		const struct rrr_msg_stats_packed *msg_packed,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	(void)(callback_data);

	int ret = 0;

	struct rrr_msg_stats msg;

	if ((rrr_msg_stats_unpack (
			&msg,
			msg_packed,
			rrr_length_from_size_t_bug_const(data_size)
	)) != 0) {
		RRR_MSG_0("Failed to unpack stats message in %s\n", __func__);
		goto out;
	};

	if (RRR_STATS_MESSAGE_FLAGS_IS_EVENT(&msg)) {
		if ((ret = rrr_stats_instance_push_stream_message (
				INSTANCE_D_STATS(callback_data->thread_data),
				&msg
		)) != 0) {
			RRR_MSG_0("Failed to push stats message in %s\n", __func__);
			goto out;
		}
	}
	else if (RRR_STATS_MESSAGE_FLAGS_IS_DEFAULT(&msg)) {
		if ((ret = rrr_stats_instance_post_message (
				INSTANCE_D_STATS(callback_data->thread_data),
				&msg
		)) != 0) {
			RRR_MSG_0("Failed to post stats message in %s\n", __func__);
			goto out;
		}
	}
	else {
		RRR_BUG("Received stats message of type %u from worker for, this is not implemented", msg.type);
	}

	out:
	return ret;
}

static int __rrr_cmodule_helper_read_from_fork_setting_callback (
		const struct rrr_setting_packed *setting_packed,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	(void)(data_size);

	rrr_instance_config_update_used (
			INSTANCE_D_CONFIG(callback_data->thread_data),
			setting_packed->name,
			setting_packed->was_used
	);

	return 0;
}

static int __rrr_cmodule_helper_read_from_fork_control_callback (
		const struct rrr_msg *msg,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	struct rrr_msg msg_copy = *msg;

	(void)(data_size);

	if (RRR_MSG_CTRL_F_HAS(&msg_copy, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE)) {
		RRR_DBG_8("Worker %s completed configuration\n", callback_data->worker->name);
		if (callback_data->worker->config_complete != 0) {
			RRR_BUG("Config complete was not 0 in %s\n", __func__);
		}
		callback_data->worker->config_complete = 1;
		RRR_MSG_CTRL_F_CLEAR(&msg_copy, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE);
	}

	if (RRR_MSG_CTRL_F_HAS(&msg_copy, RRR_MSG_CTRL_F_PONG)) {
		callback_data->worker->pong_receive_time = rrr_time_get_us();
		RRR_MSG_CTRL_F_CLEAR(&msg_copy, RRR_MSG_CTRL_F_PONG);
	}

	// CTRL type is returned by FLAGS() macro, clear it to
	// make sure no unknown flags are set
	RRR_MSG_CTRL_F_CLEAR(&msg_copy, RRR_MSG_TYPE_CTRL);

	if (RRR_MSG_CTRL_FLAGS(&msg_copy) != 0) {
		RRR_BUG("Unknown flags %u in control message from worker fork %s\n",
				RRR_MSG_CTRL_FLAGS(&msg_copy), callback_data->worker->name);
	}

	return 0;
}

static int __rrr_cmodule_helper_read_from_fork_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_read_from_fork_callback_data *callback_data = arg;

	const struct rrr_msg *msg = data;

	callback_data->read_count++;

	if (RRR_MSG_IS_RRR_MESSAGE(msg)) {
		return __rrr_cmodule_helper_read_from_fork_message_callback(data, data_size, callback_data);
	}
	else if (RRR_MSG_IS_RRR_MESSAGE_LOG(msg)) {
		return __rrr_cmodule_helper_read_from_fork_log_callback((const struct rrr_msg_log *) msg, data_size, callback_data);
	}
	else if (RRR_MSG_IS_STATS(msg)) {
		return __rrr_cmodule_helper_read_from_fork_stats_callback((const struct rrr_msg_stats_packed *) msg, data_size, callback_data);
	}
	else if (RRR_MSG_IS_SETTING(msg)) {
		return __rrr_cmodule_helper_read_from_fork_setting_callback((const struct rrr_setting_packed *) msg, data_size, callback_data);
	}
	else if (RRR_MSG_IS_CTRL(msg)) {
		return __rrr_cmodule_helper_read_from_fork_control_callback(msg, data_size, callback_data);
	}

	RRR_BUG("BUG: Unknown message type %u in %s\n", msg->msg_type, __func__);

	return 0;
}

static int __rrr_cmodule_helper_read_from_worker (
		uint16_t *amount,
		struct rrr_cmodule_worker *worker,
		struct rrr_instance_runtime_data *thread_data,
		int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	if (worker->pid == 0) {
		RRR_MSG_0("A worker fork '%s' had exited while attempting to read in %s\n",
				worker->name, __func__);
		ret = 1;
		goto out;
	}

	struct rrr_cmodule_read_from_fork_callback_data callback_data = {
			worker,
			thread_data,
			final_callback,
			final_callback_arg,
			0
	};

	if ((ret = rrr_cmodule_channel_receive_messages (
			amount,
			worker->channel_to_parent,
			__rrr_cmodule_helper_read_from_fork_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_CMODULE_CHANNEL_EMPTY) {
			ret = 0;
			goto out;
		}
		else if (ret == RRR_EVENT_EXIT) {
			// Propagate
			goto out;
		}
		else {
			RRR_MSG_0("Error %i while reading from worker fork %s\n",
					ret, worker->name);
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_cmodule_helper_event_mmap_channel_data_available (
		RRR_EVENT_FUNCTION_ARGS
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	int ret = 0;

	// Note : Bias here to read from the first worker

	int worker_i = 0;
	while ((ret = rrr_thread_signal_encourage_stop_check(thread)) == 0 && *amount > 0) {
		struct rrr_cmodule_worker *worker = &cmodule->workers[worker_i];

		struct rrr_cmodule_helper_read_callback_data callback_data = {0};
		callback_data.thread_data = thread_data;

		if ((ret = __rrr_cmodule_helper_read_from_worker (
				amount,
				worker,
				thread_data,
				__rrr_cmodule_helper_read_callback,
				&callback_data
		)) != 0) {
			goto out;
		}

		if (cmodule->config_check_complete_message_printed == 0) {
			int complete_count = 0;

			WORKER_LOOP_BEGIN();
				if (worker->config_complete) {
					complete_count++;
				}
			WORKER_LOOP_END();

			if (complete_count == cmodule->worker_count) {
				RRR_DBG_1("Instance %s child config function (if any) complete for all %u workers, checking for unused values\n",
						INSTANCE_D_NAME(thread_data), cmodule->worker_count);

				if (INSTANCE_D_CMODULE(thread_data)->config_data.do_require_all_settings_used) {
					rrr_instance_config_verify_all_settings_used(INSTANCE_D_CONFIG(thread_data));
				}
				else {
					rrr_instance_config_check_all_settings_used(INSTANCE_D_CONFIG(thread_data));
				}

				cmodule->config_check_complete_message_printed = 1;
				cmodule->config_check_complete = 1;
			}
		}

		if (++worker_i == cmodule->worker_count) {
			worker_i = 0;
		}
	}

	out:
	return ret;
}

static int __rrr_cmodule_helper_check_pong (
		struct rrr_instance_runtime_data *thread_data
) {
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	int ret = 0;

	rrr_time_us_t min_time = rrr_time_us_sub(rrr_time_get_us(), rrr_time_us_from_s(rrr_cmodule_worker_fork_pong_timeout));

	WORKER_LOOP_BEGIN();
		if (rrr_time_us_zero(worker->pong_receive_time)) {
			worker->pong_receive_time = rrr_time_get_us();
		}
		else if (rrr_time_us_lt(worker->pong_receive_time, min_time)) {
			RRR_MSG_0("PONG timeout after %ld seconds for worker fork %s pid %ld, possible hangup\n",
					(long) rrr_cmodule_worker_fork_pong_timeout.s, worker->name, (long) worker->pid);
			ret = 1;
		}
	WORKER_LOOP_END();

	return ret;
}

static int __rrr_cmodule_helper_event_periodic (
		RRR_EVENT_FUNCTION_PERIODIC_ARGS
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

/*
 * Enable to debug notification counts in the eventfd.
 * RRR_SOCKET_EVENTFD_DEBUG must be enabled to get any
 * useful numbers. Note that only worker idx 0 is checked.
	{

		uint64_t deferred_dummy;
		int64_t to_fork_count = 0;
		int64_t to_parent_count = 0;
		struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

		rrr_event_count(&to_fork_count, &deferred_dummy, cmodule->workers[0].event_queue_worker, RRR_EVENT_FUNCTION_MMAP_CHANNEL_DATA_AVAILABLE);
		rrr_event_count(&to_parent_count, &deferred_dummy, cmodule->workers[0].event_queue_parent, RRR_EVENT_FUNCTION_MMAP_CHANNEL_DATA_AVAILABLE);

		printf("To fork: %" PRIi64 ", to parent: %" PRIi64 "\n", to_fork_count, to_parent_count);

		// Adjust numbers to MMAP channel capacity
		if (to_fork_count > 1024 || to_fork_count < 0) {
			abort();
		}
	}
*/

	int ret_tmp;
	if ((ret_tmp = __rrr_cmodule_helper_send_ping_all_workers(thread_data)) != 0) {
		return ret_tmp;
	}

	if (__rrr_cmodule_helper_check_pong(thread_data) != 0) {
		return 1;
	}

	unsigned int output_buffer_count = 0;
	int output_buffer_ratelimit_active = 0;

	if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
			&output_buffer_count,
			&output_buffer_ratelimit_active,
			thread_data
	) != 0) {
		RRR_MSG_0("Error while setting ratelimit in instance %s\n",
			INSTANCE_D_NAME(thread_data));
		return 1;
	}

	{
		unsigned long long int count = 0;
		unsigned long long int write_full_counter = 0;

		rrr_cmodule_helper_get_mmap_channel_to_forks_stats (
				&count,
				&write_full_counter,
				INSTANCE_D_CMODULE(thread_data)
		);

		rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 1, "mmap_to_child_full_events", write_full_counter);
		rrr_stats_instance_post_unsigned_base10_text(INSTANCE_D_STATS(thread_data), "mmap_to_child_count", 0, count);
	}
	{
		unsigned long long int count = 0;
		unsigned long long int write_full_counter = 0;

		rrr_cmodule_helper_get_mmap_channel_to_parent_stats (
				&count,
				&write_full_counter,
				INSTANCE_D_CMODULE(thread_data)
		);

		rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 5, "mmap_to_parent_full_events", write_full_counter);
		rrr_stats_instance_post_unsigned_base10_text(INSTANCE_D_STATS(thread_data), "mmap_to_parent_count", 0, count);
	}
	{
		char buf_path[128];
		char buf_value[64];
		for (int i = 0; i < INSTANCE_D_CMODULE(thread_data)->worker_count; i++) {
			const struct rrr_cmodule_worker *worker = &INSTANCE_D_CMODULE(thread_data)->workers[i];

			snprintf(buf_path,  sizeof(buf_path),  "workers/%i/pid", i);
			rrr_stats_instance_post_base10_text(INSTANCE_D_STATS(thread_data), buf_path, 0, (long long int) worker->pid);

			snprintf(buf_path,  sizeof(buf_path),  "workers/%i/name", i);
			snprintf(buf_value, sizeof(buf_value), "%s", worker->name);
			rrr_stats_instance_post_text(INSTANCE_D_STATS(thread_data), buf_path, 0, buf_value);
		}
	}

	// TODO : Fix rate counter
	// rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 11, "input_counter", INSTANCE_D_COUNTERS(thread_data)->total_message_count);
	rrr_stats_instance_post_unsigned_base10_text(INSTANCE_D_STATS(thread_data), "output_buffer_count", 0, output_buffer_count);

	struct rrr_fifo_protected_stats fifo_stats;
	if (rrr_message_broker_get_fifo_stats (&fifo_stats, INSTANCE_D_BROKER_ARGS(thread_data)) != 0) {
		RRR_MSG_0("Could not get output buffer stats in perl5 instance %s\n", INSTANCE_D_NAME(thread_data));
		return 1;
	}

	rrr_stats_instance_post_unsigned_base10_text(INSTANCE_D_STATS(thread_data), "output_buffer_total", 0, fifo_stats.total_entries_written);

	rrr_cmodule_main_maintain(INSTANCE_D_CMODULE(thread_data));

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

int rrr_cmodule_helper_methods_iterate (
		struct rrr_instance_runtime_data *thread_data,
		int (*method_callback)(const char *stack_name, const char *method_name, void *arg),
		void *callback_arg
) {
	return rrr_discern_stack_collection_iterate_destination_names (
			INSTANCE_D_METHODS(thread_data),
			method_callback,
			callback_arg
	);
}

static void __rrr_cmodule_helper_loop (
		struct rrr_instance_runtime_data *thread_data,
		int (*app_periodic_callback)(RRR_CMODULE_HELPER_APP_PERIODIC_CALLBACK_ARGS)
) {
	struct rrr_cmodule *cmodule = INSTANCE_D_CMODULE(thread_data);

	struct rrr_event_collection events = {0};
	rrr_event_collection_init(&events, INSTANCE_D_EVENTS(thread_data));

	pthread_cleanup_push(rrr_event_collection_clear_void, &events);

	if (rrr_message_broker_senders_count (INSTANCE_D_BROKER_ARGS(thread_data)) == 0) {
		if (INSTANCE_D_CMODULE(thread_data)->config_data.process_mode != RRR_CMODULE_PROCESS_MODE_NONE) {
			RRR_MSG_0("Instance %s had no senders but a processor function is defined, this is an invalid configuration.\n",
				INSTANCE_D_NAME(thread_data));
			goto out;
		}
	}

	if (rrr_event_collection_push_periodic (
				&cmodule->input_queue_event,
				&events,
				__rrr_cmodule_helper_event_input_queue,
				thread_data,
				2000 // 2 ms
		) != 0) {
		RRR_MSG_0("Failed to create input queue event in %s\n", __func__);
		goto out;
	}

	if (app_periodic_callback) {
		struct rrr_cmodule_helper_event_app_periodic_callback_data callback_data = {
			thread_data,
			app_periodic_callback
		};

		if (rrr_event_collection_push_periodic (
					&cmodule->app_periodic_event,
					&events,
					__rrr_cmodule_helper_event_app_periodic_callback,
					&callback_data,
					1000 * 1000 // 1000 ms
		) != 0) {
			RRR_MSG_0("Failed to create app periodic callback event in %s\n", __func__);
			goto out;
		}

		EVENT_ADD(cmodule->app_periodic_event);
	}

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			__rrr_cmodule_helper_event_pause_check,
			thread_data
	);

	if (rrr_event_function_priority_set (
			INSTANCE_D_EVENTS(thread_data),
			RRR_EVENT_FUNCTION_MMAP_CHANNEL_DATA_AVAILABLE,
			RRR_EVENT_PRIORITY_HIGH
	)) {
		RRR_MSG_0("Failed to set mmap event priority in %s\n", __func__);
		goto out;
	}

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000, // 1 s
			__rrr_cmodule_helper_event_periodic,
			INSTANCE_D_THREAD(thread_data)
	);

	out:
	pthread_cleanup_pop(1);
	return;
}

void rrr_cmodule_helper_loop (
		struct rrr_instance_runtime_data *thread_data
) {
	__rrr_cmodule_helper_loop(thread_data, NULL);
}

void rrr_cmodule_helper_loop_with_periodic (
		struct rrr_instance_runtime_data *thread_data,
		int (*app_periodic_callback)(RRR_CMODULE_HELPER_APP_PERIODIC_CALLBACK_ARGS)
) {
	__rrr_cmodule_helper_loop(thread_data, app_periodic_callback);
}

int rrr_cmodule_helper_parse_config (
		struct rrr_instance_runtime_data *thread_data,
		const char *config_prefix,
		const char *config_suffix
) {
	struct rrr_cmodule_config_data *data = &(INSTANCE_D_CMODULE(thread_data)->config_data);
	struct rrr_instance_config_data *config = INSTANCE_D_CONFIG(thread_data);

	int ret = 0;

	// Prevent warning from being printed. Instances framework parses these
	// parameters whenever present.
	RRR_INSTANCE_CONFIG_SET_USED("methods");
	RRR_INSTANCE_CONFIG_SET_USED("methods_direct_dispatch");

	RRR_INSTANCE_CONFIG_PREFIX_BEGIN(config_prefix);

	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX("_config_", config_suffix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, config_method);

	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX("_source_", config_suffix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, source_method);

	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX("_process_", config_suffix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, process_method);

	if (INSTANCE_D_FLAGS(thread_data) & RRR_INSTANCE_MISC_OPTIONS_METHODS_DIRECT_DISPATCH) {
		assert(data->process_mode == RRR_CMODULE_PROCESS_MODE_NONE);
		data->process_mode = RRR_CMODULE_PROCESS_MODE_DIRECT_DISPATCH;
	}

	if (data->source_method != NULL && *(data->source_method) != '\0') {
		data->do_spawning = 1;
	}

	if (data->process_method != NULL && *(data->process_method) != '\0') {
		if (data->process_mode == RRR_CMODULE_PROCESS_MODE_DIRECT_DISPATCH) {
			if (!(INSTANCE_D_FLAGS(thread_data) & RRR_INSTANCE_MISC_OPTIONS_METHODS_DOUBLE_DELIVERY)) {
				RRR_MSG_0("A processor %s was set for instance %s while methods_direct_dispatch was yes. This is a configuration error, the processor %s will never be called.\n",
					config_suffix, INSTANCE_D_NAME(thread_data), config_suffix);
				ret = 1;
				goto out;
			}
			RRR_MSG_1("Instance %s is configured to use double method delivery in %s, ignoring the fact that processor function is defined while methods_direct_dispatch is yes.\n",
				INSTANCE_D_NAME(thread_data), __func__);
			data->process_mode = RRR_CMODULE_PROCESS_MODE_DIRECT_DISPATCH;
		}
		else {
			assert(data->process_mode == RRR_CMODULE_PROCESS_MODE_NONE);
			data->process_mode = RRR_CMODULE_PROCESS_MODE_DEFAULT;
		}
	}

	if (data->do_spawning == 0 && data->process_mode == RRR_CMODULE_PROCESS_MODE_NONE) {
		RRR_MSG_0("No process or source %s defined in configuration for instance %s and direct method dispatch is not active\n",
				config_suffix, config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_STRING_SET("_source_interval_ms");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_MS(config_string, worker_spawn_interval, rrr_cmodule_worker_default_spawn_interval);

	RRR_INSTANCE_CONFIG_STRING_SET("_workers");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(config_string, worker_count, RRR_CMODULE_WORKER_DEFAULT_WORKER_COUNT);

	if (data->worker_count < 1 || data->worker_count > RRR_CMODULE_WORKER_MAX_WORKER_COUNT) {
		RRR_MSG_0("Invalid value %llu for parameter %s of instance %s, must be >= 1 and <= %i\n",
				(long long unsigned) data->worker_count, config_string, config->name, RRR_CMODULE_WORKER_MAX_WORKER_COUNT);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_STRING_SET("_drop_on_error");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(config_string, do_drop_on_error, 0);

	RRR_INSTANCE_CONFIG_STRING_SET("_log_prefix");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, log_prefix);

	/* Undocumented parameter for test suite. Program will bug if settings are still unused after configuration */
	RRR_INSTANCE_CONFIG_STRING_SET("_require_all_settings_used");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(config_string, do_require_all_settings_used, 0);

	RRR_INSTANCE_CONFIG_PREFIX_END();

	return ret;
}

static int __rrr_cmodule_helper_worker_fork_start_intermediate (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		struct rrr_cmodule_worker_callbacks *callbacks
) {
	rrr_event_function_set (
			INSTANCE_D_EVENTS(thread_data),
			RRR_EVENT_FUNCTION_MMAP_CHANNEL_DATA_AVAILABLE,
			__rrr_cmodule_helper_event_mmap_channel_data_available,
			"mmap channel data available (helper)"
	);

	return rrr_cmodule_main_worker_fork_start (
			INSTANCE_D_CMODULE(thread_data),
			INSTANCE_D_NAME(thread_data),
			INSTANCE_D_SETTINGS(thread_data),
			INSTANCE_D_SETTINGS_USED(thread_data),
			INSTANCE_D_EVENTS(thread_data),
			INSTANCE_D_METHODS(thread_data),
			init_wrapper_callback,
			init_wrapper_callback_arg,
			callbacks
	);
}

int rrr_cmodule_helper_worker_forks_start_deferred_callback_set (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg
) {
	struct rrr_cmodule_worker_callbacks callbacks = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	for (rrr_setting_uint i = 0; i < INSTANCE_D_CMODULE(thread_data)->config_data.worker_count; i++) {
		if (__rrr_cmodule_helper_worker_fork_start_intermediate (
					thread_data,
					init_wrapper_callback,
					init_wrapper_callback_arg,
					&callbacks
		) != 0) {
			return 1;
		}
	}

	return 0;
}

int rrr_cmodule_helper_worker_forks_start_with_ping_callback (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*ping_callback)(RRR_CMODULE_PING_CALLBACK_ARGS),
		void *ping_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	struct rrr_cmodule_worker_callbacks callbacks = {
		ping_callback,
		ping_callback_arg,
		configuration_callback,
		configuration_callback_arg,
		process_callback,
		process_callback_arg,
		NULL,
		NULL,
		NULL,
		NULL
	};

	for (rrr_setting_uint i = 0; i < INSTANCE_D_CMODULE(thread_data)->config_data.worker_count; i++) {
		if (__rrr_cmodule_helper_worker_fork_start_intermediate (
					thread_data,
					init_wrapper_callback,
					init_wrapper_callback_arg,
					&callbacks
		) != 0) {
			return 1;
		}
	}

	return 0;
}

int rrr_cmodule_helper_worker_forks_start (
		struct rrr_instance_runtime_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	return rrr_cmodule_helper_worker_forks_start_with_ping_callback(
			thread_data,
			init_wrapper_callback,
			init_wrapper_callback_arg,
			NULL,
			NULL,
			configuration_callback,
			configuration_callback_arg,
			process_callback,
			process_callback_arg
	);
}

int rrr_cmodule_helper_worker_custom_fork_start (
		struct rrr_instance_runtime_data *thread_data,
		rrr_time_us_t tick_interval,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),
		void *custom_tick_callback_arg
) {
	INSTANCE_D_CMODULE(thread_data)->config_data.worker_spawn_interval = tick_interval;

	struct rrr_cmodule_worker_callbacks callbacks = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		custom_tick_callback,
		custom_tick_callback_arg,
		NULL,
		NULL
	};

	return __rrr_cmodule_helper_worker_fork_start_intermediate (
			thread_data,
			init_wrapper_callback,
			init_wrapper_callback_arg,
			&callbacks
	);
}

static void __rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule *cmodule,
		int is_to_parent
) {
	*write_full_counter = 0;

	for (int i = 0; i < cmodule->worker_count; i++) {
		unsigned long long int tmp_count = 0;
		unsigned long long int tmp_write_full_counter = 0;

		if (is_to_parent) {
			rrr_cmodule_worker_get_mmap_channel_to_parent_stats (
					&tmp_count,
					&tmp_write_full_counter,
					&cmodule->workers[i]
			);
		}
		else {
			rrr_cmodule_worker_get_mmap_channel_to_fork_stats (
					&tmp_count,
					&tmp_write_full_counter,
					&cmodule->workers[i]
			);
		}

		*count += tmp_count;
		*write_full_counter += tmp_write_full_counter;

		cmodule->workers[i].to_fork_write_retry_counter = 0;
	}
}

void rrr_cmodule_helper_get_mmap_channel_to_forks_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule *cmodule
) {
	__rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
			count,
			write_full_counter,
			cmodule,
			0 // <-- 0 = is not to parent, but to fork
	);
}

void rrr_cmodule_helper_get_mmap_channel_to_parent_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule *cmodule
) {
	__rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
			count,
			write_full_counter,
			cmodule,
			1 // <-- 1 = is to parent
	);
}
