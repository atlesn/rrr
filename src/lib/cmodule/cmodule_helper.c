/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include "cmodule_helper.h"
#include "cmodule_main.h"
#include "cmodule_channel.h"

#include "../buffer.h"
#include "../modules.h"
#include "../ip_buffer_entry.h"
#include "../message_addr.h"
#include "../message_log.h"
#include "../messages.h"
#include "../instances.h"
#include "../instance_config.h"
#include "../stats/stats_instance.h"
#include "../message_broker.h"
#include "../poll_helper.h"
#include "../threads.h"
#include "../log.h"
#include "../macro_utils.h"

struct rrr_cmodule_helper_read_callback_data {
	struct rrr_instance_thread_data *thread_data;
	const struct rrr_message *message;
	int count;
	struct rrr_message_addr addr_message;
};

static int __rrr_cmodule_helper_read_final_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct rrr_cmodule_helper_read_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_message *message_new = rrr_message_duplicate(callback_data->message);
	if (message_new == NULL) {
		RRR_MSG_0("Could not duplicate message in  __rrr_message_broker_cmodule_read_final_callback for instance %s\n",
				INSTANCE_D_NAME(callback_data->thread_data));
		ret = 1;
		goto out;
	}

//	printf ("read_from_child_callback_msg addr len: %" PRIu64 "\n", data->latest_message_addr.addr_len);

	rrr_ip_buffer_entry_set_unlocked (
			entry,
			message_new,
			MSG_TOTAL_SIZE(message_new),
			(struct sockaddr *) &callback_data->addr_message,
			RRR_MSG_ADDR_GET_ADDR_LEN(&callback_data->addr_message),
			callback_data->addr_message.protocol
	);
	message_new = NULL;

	callback_data->count++;

	out:
	RRR_FREE_IF_NOT_NULL(message_new);
	memset(&callback_data->addr_message, '\0', sizeof(callback_data->addr_message));
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static int __rrr_cmodule_helper_read_callback (RRR_CMODULE_FINAL_CALLBACK_ARGS) {
	struct rrr_cmodule_helper_read_callback_data *callback_data = arg;

	callback_data->addr_message = *msg_addr;
	callback_data->message = msg;

	if (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->thread_data),
			NULL,
			0,
			0,
			__rrr_cmodule_helper_read_final_callback,
			callback_data
	) != 0) {
		RRR_MSG_0("Could to write to output buffer in rrr_message_broker_cmodule_read_callback for instance %s\n",
				INSTANCE_D_NAME(callback_data->thread_data));
		return 1;
	}

	return 0;
}

// Will always free the message also upon errors
static int __rrr_cmodule_helper_send_message_to_fork (
		int *sent_total,
		struct rrr_cmodule *cmodule,
		pid_t worker_handle_pid,
		struct rrr_message *msg,
		const struct rrr_message_addr *msg_addr
) {
	int ret = 0;
	int pid_was_found = 0;

	RRR_LL_ITERATE_BEGIN(cmodule, struct rrr_cmodule_worker);
		if (node->pid == worker_handle_pid) {
			pid_was_found = 1;

			int retries = 0;

			// Will always free the message also upon errors
			if ((ret = rrr_cmodule_channel_send_message (
					sent_total,
					&retries,
					node->channel_to_fork,
					&node->deferred_to_fork,
					msg,
					msg_addr,
					RRR_CMODULE_CHANNEL_WAIT_TIME_US
			)) != 0) {
				RRR_MSG_0("Error while sending message in rrr_cmodule_send_to_fork\n");
				ret = 1;
				goto out;
			}

			node->to_fork_write_retry_counter += retries;

			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	if (pid_was_found == 0) {
		free(msg);
		RRR_MSG_0("Pid %i to rrr_cmodule_send_to_fork not found\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_cmodule_helper_send_entry_to_fork_nolock (
		int *count,
		struct rrr_instance_thread_data *thread_data,
		pid_t fork_pid,
		struct rrr_ip_buffer_entry *entry
) {
	struct rrr_message *message = (struct rrr_message *) entry->message;

	struct rrr_message_addr addr_msg;
	int ret = 0;

	RRR_ASSERT(sizeof(addr_msg.addr) == sizeof(entry->addr), message_addr_and_ip_buffer_entry_addr_differ);

	// cmodule send will always free or take care of message memory
	entry->message = NULL;

//	printf ("perl5_input_callback: message %p\n", message);

	rrr_message_addr_init(&addr_msg);
	if (entry->addr_len > 0) {
		memcpy(&addr_msg.addr, &entry->addr, sizeof(addr_msg.addr));
		RRR_MSG_ADDR_SET_ADDR_LEN(&addr_msg, entry->addr_len);
	}

	if ((ret = __rrr_cmodule_helper_send_message_to_fork (
			count,
			thread_data->cmodule,
			fork_pid,
			message,
			&addr_msg
	)) != 0) {
		RRR_MSG_0("Passing message to instance %s fork using memory map failed.\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
		return ret;
}

struct rrr_cmodule_helper_poll_callback_data {
	pid_t pid;
	int count;
	int max_count;
};

static int __rrr_cmodule_helper_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	int ret = 0;

	struct rrr_instance_thread_data *thread_data = arg;
	struct rrr_cmodule_helper_poll_callback_data *callback_data = thread_data->cmodule->callback_data_tmp;

	int input_count = 0;

	ret = __rrr_cmodule_helper_send_entry_to_fork_nolock (
			&input_count,
			thread_data,
			callback_data->pid,
			entry
	);

	callback_data->count += input_count;

	if (ret != 0) {
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out;
	}

	if (callback_data->count > callback_data->max_count) {
		ret = RRR_FIFO_SEARCH_STOP;
	}

	out:
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static int __rrr_cmodule_helper_poll_delete (
		int *count,
		struct rrr_instance_thread_data *thread_data,
		struct rrr_poll_collection *poll,
		pid_t target_pid,
		int wait_ms,
		int max_count
) {
	int ret = 0;

	*count = 0;

	struct rrr_cmodule_helper_poll_callback_data callback_data = {
		target_pid,
		0,
		max_count
	};

	thread_data->cmodule->callback_data_tmp = &callback_data;

	if (rrr_poll_do_poll_delete (thread_data, poll, __rrr_cmodule_helper_poll_callback, wait_ms) != 0) {
		RRR_MSG_ERR("Error while polling in instance %s\n",
			INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	*count = callback_data.count;
	return ret;
}

struct rrr_cmodule_helper_reader_thread_data {
	struct rrr_thread_collection *thread_collection;

	struct rrr_instance_thread_data *parent_thread_data;
	struct rrr_stats_instance *stats;

	int thread_became_ghost;
};


struct rrr_cmodule_read_from_fork_callback_data {
		struct rrr_cmodule_worker *worker;
		int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS);
		void *final_callback_arg;
};

static int __rrr_cmodule_helper_read_from_fork_message_callback (
		const void *data,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	const struct rrr_message *msg = data;
	const struct rrr_message_addr *msg_addr = data + MSG_TOTAL_SIZE(msg);

	if (MSG_TOTAL_SIZE(msg) + sizeof(*msg_addr) != data_size) {
		RRR_BUG("BUG: Size mismatch in __rrr_cmodule_read_from_fork_message_callback for worker %s: %i+%lu != %lu\n",
				callback_data->worker->name, MSG_TOTAL_SIZE(msg), sizeof(*msg_addr), data_size);
	}

	return callback_data->final_callback(msg, msg_addr, callback_data->final_callback_arg);
}

int __rrr_cmodule_helper_from_fork_log_callback (
		const struct rrr_message_log *msg_log,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	(void)(callback_data);

	if (!RRR_MSG_LOG_SIZE_OK(msg_log) || data_size != msg_log->msg_size) {
		RRR_BUG("BUG: Size error of message in __rrr_cmodule_read_from_fork_log_callback\n");
	}

//	printf("worker %s in log msg read - %s\n", callback_data->worker->name, RRR_MSG_LOG_MSG_POS(msg_log));

	// Messages are already printed to STDOUT or STDERR in the fork. Send to hooks
	// only (includes statistics engine)
	rrr_log_hooks_call_raw(msg_log->loglevel, msg_log->prefix_and_message, RRR_MSG_LOG_MSG_POS(msg_log));

	return 0;
}

int __rrr_cmodule_helper_read_from_fork_setting_callback (
		const struct rrr_setting_packed *setting_packed,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	int ret = 0;

	(void)(data_size);

	rrr_settings_update_used (
			callback_data->worker->settings,
			setting_packed->name,
			(setting_packed->was_used != 0 ? 1 : 0),
			rrr_settings_iterate_nolock
	);

	return ret;
}

static int __rrr_cmodule_helper_read_from_fork_control_callback (
		const struct rrr_socket_msg *msg,
		size_t data_size,
		struct rrr_cmodule_read_from_fork_callback_data *callback_data
) {
	struct rrr_socket_msg msg_copy = *msg;

	(void)(data_size);

	if (RRR_SOCKET_MSG_CTRL_F_HAS(&msg_copy, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE)) {
		if (callback_data->worker->config_complete != 0) {
			RRR_BUG("Config complete was not 0 in __rrr_cmodule_read_from_fork_control_callback\n");
		}
		callback_data->worker->config_complete = 1;
		RRR_SOCKET_MSG_CTRL_F_CLEAR(&msg_copy, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE);
	}

	// CTRL type is returned by FLAGS() macro, clear it to
	// make sure no unknown flags are set
	RRR_SOCKET_MSG_CTRL_F_CLEAR(&msg_copy, RRR_SOCKET_MSG_TYPE_CTRL);

	if (RRR_SOCKET_MSG_CTRL_FLAGS(&msg_copy) != 0) {
		RRR_BUG("Unknown flags %u in control message from worker fork %s\n",
				RRR_SOCKET_MSG_CTRL_FLAGS(&msg_copy), callback_data->worker->name);
	}

	return 0;
}

static int __rrr_cmodule_helper_read_from_fork_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_read_from_fork_callback_data *callback_data = arg;

	const struct rrr_socket_msg *msg = data;

	if (RRR_SOCKET_MSG_IS_RRR_MESSAGE(msg)) {
		return __rrr_cmodule_helper_read_from_fork_message_callback(data, data_size, callback_data);
	}
	else if (RRR_SOCKET_MSG_IS_RRR_MESSAGE_LOG(msg)) {
		return __rrr_cmodule_helper_from_fork_log_callback((const struct rrr_message_log *) msg, data_size, callback_data);
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(msg)) {
		return __rrr_cmodule_helper_read_from_fork_setting_callback((const struct rrr_setting_packed *) msg, data_size, callback_data);
	}
	else if (RRR_SOCKET_MSG_IS_CTRL(msg)) {
		return __rrr_cmodule_helper_read_from_fork_control_callback(msg, data_size, callback_data);
	}

	RRR_BUG("BUG: Unknown message type %u in __rrr_cmodule_read_from_fork_callback\n", msg->msg_type);

	return 0;
}

static int __rrr_cmodule_helper_read_from_forks (
		int *config_complete,
		struct rrr_cmodule *cmodule,
		int read_max,
		int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	// Set to 1 first, and if any worker has config_complete set to zero, set it to zero
	*config_complete = 1;

	RRR_LL_ITERATE_BEGIN(cmodule, struct rrr_cmodule_worker);
		int read_max_tmp = read_max;

		if (node->config_complete == 0) {
			*config_complete = 0;
		}

		if (node->pid == 0) {
			RRR_MSG_0("A worker fork '%s' had exited while attempting to read in rrr_cmodule_read_from_forks\n",
					node->name);
			ret = 1;
			goto out;
		}

		struct rrr_cmodule_read_from_fork_callback_data callback_data = {
				node,
				final_callback,
				final_callback_arg
		};

		read_again:
		if ((ret = rrr_cmodule_channel_receive_messages (
				node->channel_to_parent,
				RRR_CMODULE_CHANNEL_WAIT_TIME_US,
				__rrr_cmodule_helper_read_from_fork_callback,
				&callback_data
		)) != 0) {
			if (ret == RRR_CMODULE_CHANNEL_EMPTY) {
				ret = 0;
				break;
			}
			else {
				RRR_MSG_0("Error while reading from worker fork %s\n",
						node->name);
				ret = 1;
				goto out;
			}
		}
		else {
			if (--read_max_tmp > 0) {
				goto read_again;
			}
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

static int __rrr_cmodule_helper_read_thread_read_from_forks (
		int *read_count,
		int *config_complete,
		struct rrr_instance_thread_data *parent_thread_data,
		int read_max
) {
	int ret = 0;

	*read_count = 0;

	struct rrr_cmodule_helper_read_callback_data callback_data = {0};

	callback_data.thread_data = parent_thread_data;

	ret = __rrr_cmodule_helper_read_from_forks (
			config_complete,
			INSTANCE_D_CMODULE(parent_thread_data),
			read_max,
			__rrr_cmodule_helper_read_callback,
			&callback_data
	);

	*read_count = callback_data.count;

	return ret;
}

static void *__rrr_cmodule_helper_reader_thread_entry (struct rrr_thread *thread) {
	struct rrr_cmodule_helper_reader_thread_data *data = thread->private_data;

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	int config_check_complete = 0;
	int config_check_complete_message_printed = 0;

	int read_count = 0;
	int usleep_count = 0;

	// Let it overflow, DO NOT use signed
	unsigned int consecutive_nothing_happened = 0;

	uint64_t start_time = rrr_time_get_64();
	int tick = 0;
	while (rrr_thread_check_encourage_stop(thread) == 0) {
		rrr_thread_update_watchdog_time(thread);

		int read_count_tmp = 0;
		int config_complete_tmp = 0;

		if (__rrr_cmodule_helper_read_thread_read_from_forks (
				&read_count_tmp,
				&config_complete_tmp,
				data->parent_thread_data,
				50
		) != 0) {
			break;
		}

		read_count += read_count_tmp;

//		printf ("reader tick %i - %i\n", tick, read_count_tmp);

		if (config_complete_tmp == 1 && config_check_complete_message_printed == 0) {
			RRR_DBG_1("Instance %s child config function (if any) complete, checking for unused values\n",
					INSTANCE_D_NAME(data->parent_thread_data));
			rrr_instance_config_check_all_settings_used(INSTANCE_D_CONFIG(data->parent_thread_data));
			config_check_complete_message_printed = 1;
			config_check_complete = 1;
		}

		if (read_count_tmp == 0) {
			consecutive_nothing_happened++;
		}
		else {
			consecutive_nothing_happened = 0;
		}

//		printf("Tick: %i, read_count: %i\n", tick, read_count);

		if (consecutive_nothing_happened > 250) {
			usleep_count += 1000;
			rrr_posix_usleep(100000); // 100 ms
		}
		else if (consecutive_nothing_happened > 100) {
			usleep_count++;
			rrr_posix_usleep(100); // 100 us
		}

		uint64_t now_time = rrr_time_get_64();
		if (now_time - start_time > 1000000) {
			RRR_DBG_1("Instance %s read thread '%s' messages per second: %i\n",
					INSTANCE_D_NAME(data->parent_thread_data), thread->name, read_count);

			// When adding more stats parameters, check rate counter numbers with main thread to
			// avoid collisions
			rrr_stats_instance_update_rate(data->stats, 15, "from_fork_read_counter", read_count);
			rrr_stats_instance_update_rate(data->stats, 16, "from_fork_ticks", tick);
			rrr_stats_instance_update_rate(data->stats, 17, "from_fork_usleeps", usleep_count);

			usleep_count = 0;
			read_count = 0;
			tick = 0;

			start_time = rrr_time_get_64();
		}

		tick++;
	}

	if (config_check_complete == 0) {
		RRR_MSG_0("Warning: Instance %s never completed configuration function\n",
				INSTANCE_D_NAME(data->parent_thread_data));
	}

	pthread_exit(0);
}

// Memory in input variables must be available throughout the lifetime of the thread
static int __rrr_cmodule_helper_threads_start (
		struct rrr_cmodule_helper_reader_thread_data *data,
		struct rrr_instance_thread_data *parent_thread_data,
		struct rrr_stats_instance *stats
) {
	int ret = 0;

	char name[128];
	const char *name_template = "%s reader thread";

	struct rrr_thread_collection *thread_collection = NULL;
	struct rrr_thread *thread = NULL;

	memset(data, '\0', sizeof(*data));

	if (strlen(INSTANCE_D_NAME(parent_thread_data)) > sizeof(name) - strlen(name_template)) {
		RRR_BUG("thread name was too long in  __rrr_cmodule_helper_threads_start\n");
	}

	sprintf(name, name_template, INSTANCE_D_NAME(parent_thread_data));

	if ((ret = rrr_thread_new_collection(&thread_collection)) != 0) {
		RRR_MSG_0("Could not create thread collection in __rrr_cmodule_helper_threads_start in instance %s\n",
				INSTANCE_D_NAME(parent_thread_data));
		goto out;
	}

	// Data members must be set now for the new thread to use
	data->thread_collection = thread_collection;
	data->parent_thread_data = parent_thread_data;
	data->stats = stats;

	if ((thread = rrr_thread_preload_and_register (
			thread_collection,
			__rrr_cmodule_helper_reader_thread_entry,
			NULL,
			NULL,
			NULL,
			NULL, // We don't call cleanup_ghost_data, so this can be NULL
			RRR_THREAD_START_PRIORITY_NORMAL,
			data,
			name
	)) == NULL) {
		RRR_MSG_0("Could not preload thread '%s' in  instance %s\n",
				name, INSTANCE_D_NAME(parent_thread_data));
		ret = 1;
		goto out_destroy_collection;
	}

	if ((ret = rrr_thread_start(thread)) != 0) {
		RRR_MSG_0("Could not start read thread in __rrr_cmodule_helper_threads_start in instance %s, can't continue.\n",
				INSTANCE_D_NAME(parent_thread_data));
		goto out_destroy_collection;
	}

	if ((ret = rrr_thread_start_all_after_initialized(data->thread_collection, NULL, NULL)) != 0) {
		RRR_MSG_0("Error while waiting for read thread to initialize in __rrr_cmodule_helper_threads_start in instance %s, can't continue.\n",
				INSTANCE_D_NAME(parent_thread_data));
		ret = 1;
		goto out_destroy_collection;
	}

	goto out;
	out_destroy_collection:
		rrr_thread_destroy_collection(thread_collection, 0);
		// Set everything to zero to avoid confusing cleanup functions
		memset(data, '\0', sizeof(*data));

	out:
		return ret;
}

// We shouldn't really end up here, but...
static void __rrr_cmodule_helper_ghost_handler (struct rrr_thread *thread) {
	struct rrr_cmodule_helper_reader_thread_data *data = thread->private_data;

	// See threads_cleanup()-function
	data->thread_became_ghost = 1;
}

static void __rrr_cmodule_helper_threads_cleanup(void *arg) {
	struct rrr_cmodule_helper_reader_thread_data *data = arg;

	if (data->thread_collection != NULL) {
		rrr_thread_stop_and_join_all(data->thread_collection, __rrr_cmodule_helper_ghost_handler);
		rrr_thread_destroy_collection(data->thread_collection, 0);
		data->thread_collection = NULL;
	}

	// Since the reader threads might continue to use our memory after they
	// begin to run again, we cannot proceed.
	if (data->thread_became_ghost != 0) {
		RRR_MSG_0("Could not stop reader threads in cmodule instance %s. Can't continue.",
				INSTANCE_D_NAME(data->parent_thread_data));
		exit(EXIT_FAILURE);
	}
}

void rrr_cmodule_helper_loop (
		struct rrr_instance_thread_data *thread_data,
		struct rrr_stats_instance *stats,
		struct rrr_poll_collection *poll,
		pid_t fork_pid
) {
	int no_polling = 0;

	if (rrr_poll_collection_count(poll) == 0) {
		if (INSTANCE_D_CMODULE(thread_data)->config_data.do_processing != 0) {
			RRR_MSG_0("Instance %s had no senders but a processor function is defined, this is an invalid configuration.\n");
			return;
		}
		no_polling = 1;
	}

	struct rrr_cmodule_helper_reader_thread_data reader_thread_data = {0};

	// Reader threads MUST be stopped before we clean up other data
	pthread_cleanup_push(__rrr_cmodule_helper_threads_cleanup, &reader_thread_data);

	if (__rrr_cmodule_helper_threads_start(&reader_thread_data, thread_data, stats) != 0) {
		goto cleanup;
	}

	int from_senders_counter = 0;

//	int current_poll_wait_ms = 0;
	int tick = 0;

	// Let it overflow, DO NOT use signed
	unsigned int consecutive_nothing_happened = 0;

	uint64_t next_stats_time = 0;
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1 && fork_pid != 0) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		int from_senders_count_tmp = 0;

//		printf ("From fork: %i\n", from_child_count_tmp);

		if (no_polling == 0) {
			if (__rrr_cmodule_helper_poll_delete (
					&from_senders_count_tmp,
					thread_data,
					poll,
					fork_pid,
					50, // 50 ms
					250
			) != 0) {
				break;
			}
		}

		from_senders_counter += from_senders_count_tmp;

		if (from_senders_count_tmp == 0) {
			consecutive_nothing_happened++;
		}
		else {
			consecutive_nothing_happened = 0;
		}

		if (consecutive_nothing_happened > 250) {
			rrr_posix_usleep(100000); // 100 ms
		}
		else if (consecutive_nothing_happened > 100) {
			rrr_posix_usleep(100); // 100 us
		}

		uint64_t time_now = rrr_time_get_64();

		if (time_now > next_stats_time) {
			int output_buffer_count = 0;
			int output_buffer_ratelimit_active = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&output_buffer_count,
					&output_buffer_ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_ERR("Error while setting ratelimit in instance %s\n",
					INSTANCE_D_NAME(thread_data));
				break;
			}

			{
				unsigned long long int read_starvation_counter = 0;
				unsigned long long int write_full_counter = 0;
				unsigned long long int write_retry_counter = 0;
				unsigned long long int deferred_queue_entries = 0;

				rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
						&read_starvation_counter,
						&write_full_counter,
						&write_retry_counter,
						&deferred_queue_entries,
						INSTANCE_D_CMODULE(thread_data),
						fork_pid
				);

				rrr_stats_instance_update_rate(stats, 1, "mmap_to_child_full_events", write_full_counter);
				rrr_stats_instance_update_rate(stats, 2, "mmap_to_child_starvation_events", read_starvation_counter);
				rrr_stats_instance_update_rate(stats, 3, "mmap_to_child_write_retry_events", write_retry_counter);
				rrr_stats_instance_post_base10_text(stats, "mmap_to_child_deferred_queue_entries", 0, deferred_queue_entries);
			}
			{
				unsigned long long int read_starvation_counter = 0;
				unsigned long long int write_full_counter = 0;
				unsigned long long int write_retry_counter = 0;
				unsigned long long int deferred_queue_entries = 0;

				rrr_cmodule_helper_get_mmap_channel_to_parent_stats (
						&read_starvation_counter,
						&write_full_counter,
						&write_retry_counter,
						&deferred_queue_entries,
						INSTANCE_D_CMODULE(thread_data),
						fork_pid
				);

				rrr_stats_instance_update_rate(stats, 5, "mmap_to_parent_full_events", write_full_counter);
				rrr_stats_instance_update_rate(stats, 6, "mmap_to_parent_starvation_events", read_starvation_counter);
				rrr_stats_instance_update_rate(stats, 7, "mmap_to_parent_write_retry_events", write_retry_counter);
				rrr_stats_instance_post_base10_text(stats, "mmap_to_parent_deferred_queue_entries", 0, deferred_queue_entries);
			}

//			rrr_stats_instance_post_base10_text(stats, "current_poll_timeout", 0, current_poll_wait_ms);
			rrr_stats_instance_update_rate(stats, 10, "ticks", tick);
			rrr_stats_instance_update_rate(stats, 11, "input_counter", from_senders_counter);
			// Rate counter number 7 is used by read fork
			rrr_stats_instance_post_unsigned_base10_text(stats, "output_buffer_count", 0, output_buffer_count);

			struct rrr_fifo_buffer_stats fifo_stats;
			if (rrr_message_broker_get_fifo_stats (&fifo_stats, INSTANCE_D_BROKER_ARGS(thread_data)) != 0) {
				RRR_MSG_ERR("Could not get output buffer stats in perl5 instance %s\n", INSTANCE_D_NAME(thread_data));
				break;
			}

			rrr_stats_instance_post_unsigned_base10_text(stats, "output_buffer_total", 0, fifo_stats.total_entries_written);

			tick = from_senders_counter = 0;

			next_stats_time = time_now + 1000000;

			rrr_cmodule_maintain(INSTANCE_D_CMODULE(thread_data));
		}

		tick++;
	}

	cleanup:
	pthread_cleanup_pop(1);
}

int rrr_cmodule_helper_parse_config (
		struct rrr_instance_thread_data *thread_data,
		const char *config_prefix,
		const char *config_suffix
) {
	struct rrr_cmodule_config_data *data = &(INSTANCE_D_CMODULE(thread_data)->config_data);
	struct rrr_instance_config *config = INSTANCE_D_CONFIG(thread_data);

	int ret = 0;

	RRR_INSTANCE_CONFIG_PREFIX_BEGIN(config_prefix);

	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX("_config_", config_suffix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, config_function);

	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX("_source_", config_suffix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, source_function);

	RRR_INSTANCE_CONFIG_STRING_SET_WITH_SUFFIX("_process_", config_suffix);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, process_function);

	if (data->source_function != NULL && *(data->source_function) != '\0') {
		data->do_spawning = 1;
	}

	if (data->process_function != NULL && *(data->process_function) != '\0') {
		data->do_processing = 1;
	}

	if (data->do_spawning == 0 && data->do_processing == 0) {
		RRR_MSG_0("No process or source %s defined in configuration for instance %s\n",
				config_suffix, config->name);
		ret = 1;
		goto out;
	}

	// Input in ms, multiply by 1000
	RRR_INSTANCE_CONFIG_STRING_SET("_spawn_interval_ms");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(config_string, spawn_interval_us, RRR_CMODULE_WORKER_DEFAULT_SPAWN_INTERVAL_MS);
	data->spawn_interval_us *= 1000;

	// Input in ms, multiply by 1000
	RRR_INSTANCE_CONFIG_STRING_SET("_sleep_time_ms");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(config_string, sleep_time_us, RRR_CMODULE_WORKER_DEFAULT_SLEEP_TIME_MS);
	data->sleep_time_us *= 1000;

	RRR_INSTANCE_CONFIG_STRING_SET("_nothing_happened_limit");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(config_string, nothing_happened_limit, RRR_CMODULE_WORKER_DEFAULT_NOTHING_HAPPENED_LIMIT);
	if (data->nothing_happened_limit < 1) {
		RRR_MSG_0("Invalid value for nothing_happened_limit for instance %s, must be greater than zero.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_STRING_SET("_drop_on_error");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(config_string, do_drop_on_error, 0);

	RRR_INSTANCE_CONFIG_STRING_SET("_log_prefix");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, log_prefix);

	RRR_INSTANCE_CONFIG_PREFIX_END();

	return ret;
}

int rrr_cmodule_helper_start_worker_fork (
		pid_t *handle_pid,
		struct rrr_instance_thread_data *thread_data,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	return rrr_cmodule_worker_fork_start (
			handle_pid,
			INSTANCE_D_CMODULE(thread_data),
			INSTANCE_D_NAME(thread_data),
			INSTANCE_D_SETTINGS(thread_data),
			init_wrapper_callback,
			init_wrapper_callback_arg,
			configuration_callback,
			configuration_callback_arg,
			process_callback,
			process_callback_arg
	);
}

static void __rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		unsigned long long int *write_retry_counter,
		unsigned long long int *deferred_queue_entries,
		struct rrr_cmodule *cmodule,
		pid_t pid,
		int is_to_parent
) {
	*read_starvation_counter = 0;
	*write_full_counter = 0;
	*write_retry_counter = 0;
	*deferred_queue_entries = 0;

	RRR_LL_ITERATE_BEGIN(cmodule, struct rrr_cmodule_worker);
		if (node->pid == pid) {
			if (is_to_parent) {
				rrr_cmodule_worker_get_mmap_channel_to_parent_stats (
						read_starvation_counter,
						write_full_counter,
						node
				);
			}
			else {
				rrr_cmodule_worker_get_mmap_channel_to_fork_stats (
						read_starvation_counter,
						write_full_counter,
						node
				);
			}
			*deferred_queue_entries = RRR_LL_COUNT(&node->deferred_to_fork);
			*write_retry_counter = node->to_fork_write_retry_counter;
			node->to_fork_write_retry_counter = 0;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();
}

void rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		unsigned long long int *write_retry_counter,
		unsigned long long int *deferred_queue_entries,
		struct rrr_cmodule *cmodule,
		pid_t pid
) {
	__rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
			read_starvation_counter,
			write_full_counter,
			write_retry_counter,
			deferred_queue_entries,
			cmodule,
			pid,
			0 // <-- 0 = is not to parent, but to fork
	);
}

void rrr_cmodule_helper_get_mmap_channel_to_parent_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		unsigned long long int *write_retry_counter,
		unsigned long long int *deferred_queue_entries,
		struct rrr_cmodule *cmodule,
		pid_t pid
) {
	__rrr_cmodule_helper_get_mmap_channel_to_fork_stats (
			read_starvation_counter,
			write_full_counter,
			write_retry_counter,
			deferred_queue_entries,
			cmodule,
			pid,
			1 // <-- 1 = is to parent
	);
}
