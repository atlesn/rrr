/*

Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

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
#include <signal.h>
#include <string.h>
#include <poll.h>

#include "../log.h"
#include "../allocator.h"

#include "cmodule_worker.h"
#include "cmodule_channel.h"
#include "cmodule_struct.h"

#include "../fork.h"
#include "../mmap_channel.h"
#include "../discern_stack.h"
#include "../discern_stack_helper.h"
#include "../common.h"
#include "../read_constants.h"
#include "../rrr_shm.h"
#include "../profiling.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../event/event_functions.h"
#include "../messages/msg_addr.h"
#include "../messages/msg_log.h"
#include "../messages/msg_msg.h"
#include "../util/gnu.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"
#include "../stats/stats_message.h"

#define ALLOCATE_TMP_NAME(target, name1, name2)                              \
    if (rrr_asprintf(&target, "%s-%s", name1, name2) <= 0) {                 \
        RRR_MSG_0("Could not allocate temporary string for name\n");         \
        ret = 1;                                                             \
        goto out;                                                            \
    }

static int __rrr_cmodule_worker_check_cancel_callback (
		void *arg
) {
	struct rrr_cmodule_worker *worker = arg;
	if (worker->received_stop_signal) {
		RRR_DBG_1("child worker fork named %s pid %ld received stop signal while waiting to write to mmap channel\n",
				worker->name, (long) getpid());
		return RRR_EVENT_EXIT;
	}
	return 0;
}

int rrr_cmodule_worker_send_message_and_address_to_parent (
		struct rrr_cmodule_worker *worker,
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
) {
	int ret;

	RRR_DBG_3("Transmission of message with timestamp %" PRIu64 " from worker fork '%s'\n",
			message->timestamp, worker->name);

	retry:
	ret = rrr_cmodule_channel_send_message_and_address (
			worker->channel_to_parent,
			worker->event_queue_parent,
			message,
			message_addr,
			rrr_cmodule_channel_wait_time,
			RRR_CMODULE_CHANNEL_WAIT_RETRIES,
			__rrr_cmodule_worker_check_cancel_callback,
			worker
	);

	if (ret == 0) {
		worker->total_msg_processed += 1;
		worker->total_msg_mmap_to_parent++;
	}
	else if (ret == RRR_CMODULE_CHANNEL_FULL) {
		rrr_posix_usleep(1); // Schedule
		worker->to_parent_write_retry_counter += 1;
		goto retry;
	}

	// Other errors propagate

	return ret;
}

void rrr_cmodule_worker_get_mmap_channel_to_fork_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_get_counters_and_reset (
			count,
			write_full_counter,
			worker->channel_to_fork
	);
}

void rrr_cmodule_worker_get_mmap_channel_to_parent_stats (
		unsigned long long int *count,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_get_counters_and_reset (
			count,
			write_full_counter,
			worker->channel_to_parent
	);
}

static int __rrr_cmodule_worker_signal_handler (int signal, void *private_arg) {
	struct rrr_cmodule_worker *worker = private_arg;

	if (signal == SIGUSR1 || signal == SIGINT || signal == SIGTERM) {
		RRR_DBG_SIGNAL("cmodule worker %s pid %i received SIGUSR1, SIGTERM or SIGINT, stopping\n",
				worker->name, getpid());
		worker->received_stop_signal = 1;
	}

	if (signal == SIGUSR2) {
		worker->received_sigusr2_signal = 1;
	}

	return 0;
}

static int __rrr_cmodule_worker_hook_write (
		struct rrr_cmodule_worker *worker,
		const void *msg,
		rrr_length msg_size
) {
	int ret = 0;

	int max = RRR_CMODULE_CHANNEL_WAIT_RETRIES;
	while (max--) {
		ret = rrr_mmap_channel_write (
				worker->channel_to_parent,
				worker->event_queue_parent,
				msg,
				msg_size,
				__rrr_cmodule_worker_check_cancel_callback,
				worker
		);

		if (ret == 0) {
			break;
		}
		else if (ret == RRR_MMAP_CHANNEL_FULL) {
			// OK, try again
		}
		else if (ret == RRR_EVENT_EXIT) {
			// OK, wait for some other function to detect exit
			break;
		}
		else {
			RRR_MSG_0("Error %i while writing to mmap channel in %s for worker %s in hook\n",
				ret, __func__, worker->name);
			break;
		}

		rrr_posix_sleep_us(rrr_cmodule_channel_wait_time);
	}

	if (ret == RRR_MMAP_CHANNEL_FULL) {
		RRR_MSG_0("Warning: mmap channel was full in %s for worker %s in hook\n",
			__func__, worker->name);
		ret = 0;
	}

	return ret;
}

static void __rrr_cmodule_worker_event_hook(RRR_EVENT_HOOK_ARGS) {
	struct rrr_cmodule_worker *worker = arg;

	char text[256];
	char worker_text[32];
	struct rrr_msg_stats msg;
	struct rrr_msg_stats_packed msg_packed;
	rrr_length msg_packed_size;
	ssize_t text_length;

	snprintf(worker_text, sizeof(worker_text), " worker: %s", worker->name);

	text_length = rrr_event_hook_string_format(text, sizeof(text), source_func, fd, flags, worker_text);

	assert(text_length > 0);

	if (rrr_msg_stats_init_event (
			&msg,
			text,
			text_length + 1
	) != 0) {
		RRR_MSG_0("Failed to initialize stats message in %s\n", __func__);
		goto out_failure;
	}

	rrr_msg_stats_pack (
			&msg_packed,
			&msg_packed_size,
			&msg
	);

	rrr_msg_populate_head (
			(struct rrr_msg *) &msg_packed,
			RRR_MSG_TYPE_STATS,
			msg_packed_size,
			(rrr_u32) (rrr_time_get_64() / 1000 / 1000)
	);

	if (__rrr_cmodule_worker_hook_write (
			worker,
			&msg_packed,
			msg_packed_size
	)) {
		RRR_MSG_0("Failed to write stats message in %s\n", __func__);
		goto out_failure;
	}

	return;

	out_failure:
	worker->received_stop_signal = 1;
}

static void __rrr_cmodule_worker_log_hook (RRR_LOG_HOOK_ARGS) {
	struct rrr_cmodule_worker *worker = private_arg;

	struct rrr_msg_log *message_log = NULL;

	// Some debug messages are generated by mmap channel, don't
	// send these as it causes error message about full channel
	if (loglevel_orig == RRR_MMAP_DEBUGLEVEL) {
		goto out;
	}

	if (rrr_msg_msg_log_new (
			&message_log,
			file,
			line,
			loglevel_translated,
			loglevel_orig,
			prefix,
			message
	) != 0) {
		RRR_MSG_0("Failed to create log message in %s\n", __func__);
		goto out_failure;
	}

	if (__rrr_cmodule_worker_hook_write (
			worker,
			message_log,
			message_log->msg_size
	)) {
		RRR_MSG_0("Failed to write log message in %s\n", __func__);
		goto out_failure;
	}

	goto out;
	out_failure:
		worker->received_stop_signal = 1;
	out:
		RRR_FREE_IF_NOT_NULL(message_log);
}

static int __rrr_cmodule_worker_send_setting_to_parent (
		struct rrr_setting_packed *setting,
		void *arg
) {
	struct rrr_cmodule_worker *worker = arg;

	int ret = 0;

	RRR_DBG_5("cmodule worker %s notification to parent about used setting '%s'\n",
			worker->name, setting->name);

	if ((ret = rrr_mmap_channel_write (
			worker->channel_to_parent,
			worker->event_queue_parent,
			setting,
			sizeof(*setting),
			__rrr_cmodule_worker_check_cancel_callback,
			worker
	)) != 0) {
		if (ret == RRR_EVENT_EXIT) {
			// OK, propagate
		}
		else {
			RRR_MSG_0("Error while writing settings to mmap channel in %s\n", __func__);
			ret = 1;
		}
		goto out;
	}

	out:
	return ret;
}

static int __rrr_cmodule_worker_loop_process (
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg,
		struct rrr_cmodule_worker *worker,
		const struct rrr_msg_msg *msg_msg,
		const struct rrr_msg_addr *msg_addr,
		const char *method
) {
	return process_callback (
			worker,
			msg_msg,
			msg_addr,
			0, // <-- Not in spawn context
			method,
			process_callback_arg
	);
}

struct rrr_cmodule_process_method_callback_data {
	int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS);
	void *process_callback_arg;
        struct rrr_cmodule_worker *worker;
        const struct rrr_msg_msg *message;
        const struct rrr_msg_addr *message_addr;
	int run_count;
};

static int __rrr_cmodule_worker_loop_discern_apply_true_cb (RRR_DISCERN_STACK_APPLY_CB_ARGS) {
	struct rrr_cmodule_process_method_callback_data *callback_data = arg;

	int ret = 0;

	RRR_DBG_3("+ Apply method %s result RUN in worker %s\n",
			destination, callback_data->worker->name);

	if ((ret = __rrr_cmodule_worker_loop_process (
			callback_data->process_callback,
			callback_data->process_callback_arg,
			callback_data->worker,
			callback_data->message,
			callback_data->message_addr,
			destination
	)) != 0) {
		goto out;
	}

	callback_data->run_count++;

	out:
	return ret;
}

struct rrr_cmodule_process_callback_data {
	struct rrr_cmodule_worker *worker;
	int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS);
	void *process_callback_arg;
	unsigned int total_count;
};

static int __rrr_cmodule_worker_loop_read_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_process_callback_data *callback_data = arg;
	struct rrr_cmodule_worker *worker = callback_data->worker;

	int ret = 0;

	const struct rrr_msg_msg *msg = data;

	callback_data->total_count++;

	if (RRR_MSG_IS_CTRL(msg)) {
		RRR_DBG_5("cmodule worker %s received control message\n", worker->name);
		if (RRR_MSG_CTRL_F_HAS(msg, RRR_MSG_CTRL_F_PING)) {
			worker->ping_received = 1;
		}
		else {
			RRR_MSG_0("Warning: cmodule worker %s pid %ld received unknown control message %u\n",
					worker->name, (long) getpid(), RRR_MSG_CTRL_FLAGS(msg));
		}
	}
	else if (worker->process_mode == RRR_CMODULE_PROCESS_MODE_NONE) {
		RRR_MSG_0("Warning: Received a message in worker %s but no processor function is defined in configuration, dropping message\n",
				worker->name);
	}
	else if (callback_data->process_callback == NULL) {
		RRR_BUG("BUG: Received a message in cmodule worker while no process callback was set\n");
	}
	else {
		const struct rrr_msg_msg *msg_msg = data;
		const struct rrr_msg_addr *msg_addr = data + MSG_TOTAL_SIZE(msg_msg);

		if (MSG_TOTAL_SIZE(msg_msg) + sizeof(*msg_addr) != data_size) {
			RRR_BUG("BUG: Size mismatch in %s %llu+%llu != %llu\n",
					__func__, (unsigned long long) MSG_TOTAL_SIZE(msg_msg), (unsigned long long) sizeof(*msg_addr), (unsigned long long) data_size);
		}

		worker->total_msg_mmap_to_fork++;

		RRR_DBG_3("Received a message with timestamp %" PRIu64 " in worker fork '%s'\n",
				msg->timestamp, worker->name);
		RRR_DBG_5("cmodule worker %s received message of size %" PRIrrrl ", calling processor function\n",
				worker->name, MSG_TOTAL_SIZE(msg_msg));

		if (RRR_LL_COUNT(worker->methods) > 0) {
			RRR_DBG_3("Performing method discern in worker fork '%s'\n", worker->name);

			struct rrr_discern_stack_helper_callback_data resolve_callback_data = {
				msg_msg,
				0
			};

			struct rrr_cmodule_process_method_callback_data apply_callback_data = {
				callback_data->process_callback,
				callback_data->process_callback_arg,
				worker,
				msg_msg,
				msg_addr,
				0
			};

			struct rrr_discern_stack_callbacks callbacks = {
					rrr_discern_stack_helper_topic_filter_resolve_cb,
					rrr_discern_stack_helper_array_tag_resolve_cb,
					&resolve_callback_data,
					NULL,
					__rrr_cmodule_worker_loop_discern_apply_true_cb,
					&apply_callback_data
			};

			enum rrr_discern_stack_fault fault;
			if ((ret = rrr_discern_stack_collection_execute (
					&fault,
					worker->methods,
					&callbacks
			)) != 0) {
				RRR_MSG_0("Fault code from discern stack: %u\n", fault);
				goto report;
			}
			
			RRR_DBG_3("= %i methods were executed in worker %s\n", apply_callback_data.run_count, worker->name);
		}
		else {
			ret = __rrr_cmodule_worker_loop_process (
					callback_data->process_callback,
					callback_data->process_callback_arg,
					worker,
					msg_msg,
					msg_addr,
					NULL
			);
		}

		report:
		if (ret != 0) {
			RRR_MSG_0("Error %i from worker process function in worker %s\n", ret, worker->name);
			if (worker->do_drop_on_error) {
				RRR_MSG_0("Dropping message per configuration in worker %s\n", worker->name);
				ret = 0;
			}
		}
	}

	return ret;
}

struct rrr_cmodule_worker_event_callback_data {
	struct rrr_cmodule_worker *worker;
	int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS);
	void *custom_tick_callback_arg;
	int (*ping_callback)(RRR_CMODULE_PING_CALLBACK_ARGS);
	void *ping_callback_arg;
	int (*periodic_callback)(RRR_CMODULE_PERIODIC_CALLBACK_ARGS);
	void *periodic_callback_arg;
	struct rrr_cmodule_process_callback_data read_callback_data;
};

static int __rrr_cmodule_worker_event_mmap_channel_data_available (
		RRR_EVENT_FUNCTION_ARGS
) {
	struct rrr_cmodule_worker_event_callback_data *callback_data = arg;
	struct rrr_cmodule_worker *worker = callback_data->worker;

	callback_data->read_callback_data.total_count = 0;

	retry:
	if (worker->received_stop_signal) {
		RRR_DBG_1("child worker fork named %s pid %ld received stop signal while reading from mmap channel\n",
				worker->name, (long) getpid());
		return RRR_EVENT_EXIT;
	}

	int ret_tmp;
	if ((ret_tmp = rrr_cmodule_channel_receive_messages (
			amount,
			worker->channel_to_fork,
			__rrr_cmodule_worker_loop_read_callback,
			&callback_data->read_callback_data
	)) != 0) {
		if (ret_tmp != RRR_CMODULE_CHANNEL_EMPTY) {
			RRR_MSG_0("Error from mmap read function in worker fork named %s pid %ld\n",
					worker->name, (long) getpid());
			return 1;
		}
		rrr_posix_usleep(1);
		goto retry;
	}

	return 0;
}

static int __rrr_cmodule_worker_spawn_message (
		struct rrr_cmodule_worker *worker,
		int (*process_callback)(RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	struct rrr_msg_msg *message = NULL;

	if (rrr_msg_msg_new_empty (
			&message,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			0,
			0
	) != 0) {
		RRR_MSG_0("Could not initialize message in %s of worker %s\n",
				__func__, worker->name);
		ret = 1;
		goto out;
	}

	struct rrr_msg_addr message_addr;
	rrr_msg_addr_init(&message_addr);

	if ((ret = process_callback (
			worker,
			message,
			&message_addr,
			1, // <-- is spawn context
			NULL,
			process_callback_arg
	)) != 0) {
		RRR_MSG_0("Error %i from spawn callback in %s %s\n", ret, __func__, worker->name);
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int __rrr_cmodule_worker_send_pong (
		struct rrr_cmodule_worker *worker
) {
	int ret = 0;

	struct rrr_msg msg = {0};
	rrr_msg_populate_control_msg(&msg, RRR_MSG_CTRL_F_PONG, 0);

	ret = rrr_cmodule_channel_send_message_simple (
			worker->channel_to_parent,
			worker->event_queue_parent,
			&msg,
			__rrr_cmodule_worker_check_cancel_callback,
			worker
	);

	if (ret == 0) {
		worker->total_msg_mmap_to_parent++;
	}

	// Errors propagate

	return ret;
}

static void __rrr_cmodule_worker_event_spawn (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_cmodule_worker_event_callback_data *callback_data = arg;
	struct rrr_cmodule_worker *worker = callback_data->worker;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	if (worker->do_spawning) {
		RRR_DBG_5("cmodule worker %s spawning\n", worker->name);
		if (__rrr_cmodule_worker_spawn_message (
				worker,
				callback_data->read_callback_data.process_callback,
				callback_data->read_callback_data.process_callback_arg
		) != 0) {
			rrr_event_dispatch_break(worker->event_queue_worker);
		}
	}

	if (callback_data->custom_tick_callback == NULL) {
		return;
	}

	int custom_tick_something_happened = 1;
	int retries = 100;
	while (--retries && custom_tick_something_happened) {
		if (callback_data->custom_tick_callback (
				&custom_tick_something_happened,
				worker,
				callback_data->custom_tick_callback_arg
		) != 0) {
			RRR_MSG_0("Error from custom tick function in worker fork named %s pid %ld\n",
					worker->name, (long) getpid());
			rrr_event_dispatch_break(worker->event_queue_worker);
		}
	}

}

static int __rrr_cmodule_worker_event_periodic (
		RRR_EVENT_FUNCTION_PERIODIC_ARGS
) {
	struct rrr_cmodule_worker_event_callback_data *callback_data = arg;
	struct rrr_cmodule_worker *worker = callback_data->worker;

	if (worker->received_stop_signal) {
		return RRR_EVENT_EXIT;
	}

	if (worker->received_sigusr2_signal) {
		rrr_profiling_dump();
		worker->received_sigusr2_signal = 0;
	}

	int ret_tmp = 0;

	if (worker->ping_received) {
		RRR_DBG_5("cmodule worker %s ping received, sending pong\n", worker->name);
		if ((ret_tmp = __rrr_cmodule_worker_send_pong(worker)) != 0) {
			if (ret_tmp == RRR_EVENT_EXIT) {
				return ret_tmp;
			}
			RRR_MSG_0("Warning: Failed to send PONG message in worker fork named %s pid %ld return was %i\n",
					worker->name, (long) getpid(), ret_tmp);
		}
		if (callback_data->ping_callback != NULL) {
			if ((ret_tmp = callback_data->ping_callback(worker, callback_data->ping_callback_arg)) != 0)  {
				if (ret_tmp == RRR_EVENT_EXIT) {
					return ret_tmp;
				}
				RRR_MSG_0("Error from PING callback in worker %s pid %i return was %i\n",
						worker->name, (long) getpid(), ret_tmp);
			}
		}
		// Always set to 0, maybe this fork should be killed if PONG messages
		// are not received by parent.
		worker->ping_received = 0;
	}

	return 0;
}

static void __rrr_cmodule_worker_event_app_periodic (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_cmodule_worker_event_callback_data *callback_data = arg;
	struct rrr_cmodule_worker *worker = callback_data->worker;

	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	assert(callback_data->periodic_callback && "Periodic event should not run when there is no callback set");

	int ret_tmp;
	if ((ret_tmp = callback_data->periodic_callback(worker, callback_data->periodic_callback_arg)) != 0) {
		RRR_MSG_0("Error from app periodic callback in worker fork named %s pid %ld return was %i\n",
			worker->name, (long) getpid(), ret_tmp);
		rrr_event_dispatch_break(worker->event_queue_worker);
	}
}

static int __rrr_cmodule_worker_loop (
		struct rrr_cmodule_worker *worker,
		const struct rrr_cmodule_worker_callbacks *callbacks
) {
	int ret_tmp;

	if ( worker->do_spawning == 0 &&
	     worker->process_mode == RRR_CMODULE_PROCESS_MODE_NONE &&
	     callbacks->custom_tick_callback == NULL
	) {
		RRR_BUG("BUG: No spawning or processing mode set and no custom tick callback in %s\n", __func__);
	}

	RRR_DBG_5("cmodule worker %s starting loop\n", worker->name);

	struct rrr_event_collection events = {0};
	rrr_event_handle event_spawn = RRR_EVENT_HANDLE_STRUCT_INITIALIZER;
	rrr_event_handle event_periodic = RRR_EVENT_HANDLE_STRUCT_INITIALIZER;

	rrr_event_collection_init(&events, worker->event_queue_worker);

	struct rrr_cmodule_worker_event_callback_data callback_data = {
		worker,
		callbacks->custom_tick_callback,
		callbacks->custom_tick_callback_arg,
		callbacks->ping_callback,
		callbacks->ping_callback_arg,
		callbacks->periodic_callback,
		callbacks->periodic_callback_arg,
		{
			worker,
			callbacks->process_callback,
			callbacks->process_callback_arg,
			0
		}
	};

	if (rrr_event_collection_push_periodic_new (
			&event_spawn,
			&events,
			__rrr_cmodule_worker_event_spawn,
			&callback_data,
			worker->spawn_interval
	) != 0) {
		RRR_MSG_0("Failed to create spawn event in  %s\n", __func__);
		goto out_cleanup_events;
	}
	EVENT_ADD(event_spawn);

	if (callbacks->periodic_callback) {
		if (rrr_event_collection_push_periodic (
				&event_periodic,
				&events,
				__rrr_cmodule_worker_event_app_periodic,
				&callback_data,
				1000 * 1000 // 1000 ms
		) != 0) {
			RRR_MSG_0("Failed to create periodic event in  %s\n", __func__);
			goto out_cleanup_events;
		}
		EVENT_ADD(event_periodic);
	}

	ret_tmp = rrr_event_dispatch (
			worker->event_queue_worker,
			100 * 1000, // 100 ms
			__rrr_cmodule_worker_event_periodic,
			&callback_data
	);

	RRR_DBG_1("child worker loop %s complete, received_stop_signal is %i ret is %i\n",
			worker->name,
			worker->received_stop_signal,
			ret_tmp
	);

	out_cleanup_events:
	rrr_event_collection_clear(&events);
	return 0;
}

int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		const struct rrr_cmodule_worker_callbacks *callbacks
) {
	int ret = 0;

	/* Send a PONG when we start in case something is very slow */
	if ((ret = __rrr_cmodule_worker_send_pong(worker)) != 0) {
		if (ret == RRR_EVENT_EXIT) {
			goto out;
		}
		RRR_MSG_0("Warning: Failed to send initial PONG message in worker fork named %s pid %ld return was %i\n",
				worker->name, (long) getpid(), ret);
	}

	RRR_DBG_5("cmodule worker %s running configure function\n",
			worker->name);

	if (callbacks->configuration_callback != NULL) {
		if ((ret = callbacks->configuration_callback(worker, callbacks->configuration_callback_arg)) != 0) {
			RRR_MSG_0("Error from configuration in %s\n", __func__);
			goto out;
		}

		if ((ret = rrr_settings_iterate_packed(worker->settings, __rrr_cmodule_worker_send_setting_to_parent, worker)) != 0) {
			goto out;
		}

		RRR_DBG_5("cmodule worker %s configuration complete, notification to parent\n",
				worker->name);
	}
	else {
		RRR_DBG_5("cmodule worker %s no configuration callback set, notification to parent\n",
				worker->name);
	}

	struct rrr_msg control_msg = {0};
	rrr_msg_populate_control_msg(&control_msg, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE, 1);

	if (rrr_mmap_channel_write (
			worker->channel_to_parent,
			worker->event_queue_parent,
			&control_msg,
			sizeof(control_msg),
			__rrr_cmodule_worker_check_cancel_callback,
			worker
	) != 0) {
		if (ret == RRR_EVENT_EXIT) {
			goto out;
		}
		RRR_MSG_0("Error %i while writing config complete control message to mmap channel in %s\n", ret, __func__);
		goto out;
	}

	if ((ret = __rrr_cmodule_worker_loop (
			worker,
			callbacks
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

/* Use as template when making init wrappers */
int rrr_cmodule_worker_loop_init_wrapper_default (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
) {
	int ret = 0;

	(void)(private_arg);

	// Copy function and put module-specific initialization here

	// if ((ret = my_init_1()) != 0) { RRR_MSG_0("my_error_1"); goto out; }
	// pthread_cleanup_push(my_cleanup_1);
	// if ((ret = my_init_2()) != 0) { RRR_MSG_0("my_error_1"); goto out_cleanup_1; }
	// pthread_cleanup_push(my_cleanup_2);

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			callbacks
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		// Don't goto out, run cleanup functions
	}

	// Copy function and put module-specific cleanup here

	// pthread_cleanup_pop(1);
	// out_cleanup_1:
	// pthread_cleanup_pop(1);

	return ret;
}

int rrr_cmodule_worker_main (
		struct rrr_cmodule_worker *worker,
		const char *log_prefix,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_arg,
		struct rrr_cmodule_worker_callbacks *callbacks
) {
	int ret = 0;

	int event_fds[RRR_EVENT_QUEUE_FD_MAX * 2];
	size_t event_fds_count = 0;
	int log_hook_handle;

	rrr_log_hook_unregister_all_after_fork();

	memset(event_fds, '\0', sizeof(event_fds));

	// We need to preserve the open event signal sockets, any other FDs are closed
	rrr_event_queue_fds_get(event_fds, &event_fds_count, worker->event_queue_parent);
	rrr_event_queue_fds_get(event_fds + event_fds_count, &event_fds_count, worker->event_queue_worker);
	rrr_socket_close_all_except_array_no_unlink(event_fds, sizeof(event_fds)/sizeof(event_fds[0]));

	rrr_event_hook_set(__rrr_cmodule_worker_event_hook, worker);
	rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_worker_log_hook, worker, NULL);

	if ((ret = rrr_event_queue_reinit(worker->event_queue_worker)) != 0) {
		RRR_MSG_0("Re-init of event queue failed in %s\n", __func__);
		goto out;
	}

	{
		// There is no guarantee for whether signals are active or not at this point. Disable
		// signals while working with the handler list, then always set ACTIVE afterwards.
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

		// Preserve fork signal andler in case child makes any forks
		int was_found = 0;
		rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
		if (was_found == 0) {
			RRR_BUG("BUG: rrr_fork_signal_handler was not registered in %s, should have been added in main()\n", __func__);
		}

		rrr_signal_handler_push(__rrr_cmodule_worker_signal_handler, worker);

		rrr_signal_handler_set_active(RRR_SIGNALS_ACTIVE);
	}

	// It's safe to use the char * from cmodule_data. It will never
	// get freed by the fork, instances framework does that when the thread is exiting.
	if (log_prefix != NULL && *(log_prefix) != '\0') {
		rrr_config_set_log_prefix(log_prefix);
	}

	ret = init_wrapper_callback (
			worker,
			callbacks,
			init_wrapper_arg
	);

	rrr_log_hook_unregister(log_hook_handle);

	// Clear blocks allocated by us to avoid warnings in parent
	rrr_mmap_channel_writer_free_blocks(worker->channel_to_parent);

	// Unregister any SHM created by the fork. They should be cleaned
	// up by the parent.
	rrr_mmap_channel_fork_unregister(worker->channel_to_parent);

	// Cleanup SHMs and print warnings about any which was has not been cleaned up
	rrr_shm_holders_cleanup();

	out:
	RRR_DBG_1("cmodule %s pid %i exit\n", worker->name, getpid());
	return ret;
}

struct rrr_event_queue *rrr_cmodule_worker_get_event_queue (
		struct rrr_cmodule_worker *worker
) {
	return worker->event_queue_worker;
}

struct rrr_instance_settings *rrr_cmodule_worker_get_settings (
		struct rrr_cmodule_worker *worker
) {
	return worker->settings;
}

int rrr_cmodule_worker_init (
		struct rrr_cmodule_worker *worker,
		const char *name,
		struct rrr_instance_settings *settings,
		struct rrr_event_queue *event_queue_parent,
		struct rrr_event_queue *event_queue_worker,
		struct rrr_fork_handler *fork_handler,
		const struct rrr_discern_stack_collection *methods,
		rrr_time_us_t spawn_interval,
		enum rrr_cmodule_process_mode process_mode,
		int do_spawning,
		int do_drop_on_error
) {
	int ret = 0;

	char *to_fork_name = NULL;
	char *to_parent_name = NULL;

	ALLOCATE_TMP_NAME(to_fork_name, name, "ch-to-fork");
	ALLOCATE_TMP_NAME(to_parent_name, name, "ch-to-parent");

	if ((ret = rrr_mmap_channel_new(&worker->channel_to_fork, to_fork_name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in %s\n", __func__);
		goto out_free;
	}

	if ((ret = rrr_mmap_channel_new(&worker->channel_to_parent, to_parent_name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in %s\n", __func__);
		goto out_destroy_channel_to_fork;
	}

	if ((worker->name = rrr_strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate name in %s\n", __func__);
		ret = 1;
		goto out_destroy_channel_to_parent;
	}

	if ((rrr_posix_mutex_init(&worker->pid_lock, 0)) != 0) {
		RRR_MSG_0("Could not initialize lock in %s\n", __func__);
		ret = 1;
		goto out_free_name;
	}

	rrr_event_function_set (
			event_queue_worker,
			RRR_EVENT_FUNCTION_MMAP_CHANNEL_DATA_AVAILABLE,
			__rrr_cmodule_worker_event_mmap_channel_data_available,
			"mmap channel data available (worker)"
	);


	worker->event_queue_worker = event_queue_worker;
	worker->settings = settings;
	worker->event_queue_parent = event_queue_parent;
	worker->fork_handler = fork_handler;
	worker->methods = methods;
	worker->spawn_interval = spawn_interval;
	worker->process_mode = process_mode;
	worker->do_spawning = do_spawning;
	worker->do_drop_on_error = do_drop_on_error;

	pthread_mutex_lock(&worker->pid_lock);
	worker->pid = 0;
	pthread_mutex_unlock(&worker->pid_lock);

	worker = NULL;

	goto out;
//	out_destroy_pid_lock:
//		pthread_mutex_destroy(&worker->pid_lock);
	out_free_name:
		rrr_free(worker->name);
	out_destroy_channel_to_parent:
		rrr_mmap_channel_destroy(worker->channel_to_parent);
	out_destroy_channel_to_fork:
		rrr_mmap_channel_destroy(worker->channel_to_fork);
	out_free:
		rrr_free(worker);
	out:
		RRR_FREE_IF_NOT_NULL(to_fork_name);
		RRR_FREE_IF_NOT_NULL(to_parent_name);
		return ret;
}

// Child MUST NOT call this when exiting
void rrr_cmodule_worker_cleanup (
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_destroy(worker->channel_to_fork);
	rrr_mmap_channel_destroy(worker->channel_to_parent);

	RRR_FREE_IF_NOT_NULL(worker->name);
}
