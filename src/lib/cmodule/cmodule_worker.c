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

#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "../log.h"

#include "cmodule_worker.h"
#include "cmodule_channel.h"

#include "../fork.h"
#include "../mmap_channel.h"
#include "../common.h"
#include "../messages/msg_addr.h"
#include "../messages/msg_log.h"
#include "../messages/msg_msg.h"
#include "../util/gnu.h"
#include "../util/posix.h"
#include "../util/rrr_time.h"

#define ALLOCATE_TMP_NAME(target, name1, name2)							\
	if (rrr_asprintf(&target, "%s-%s", name1, name2) <= 0) {			\
		RRR_MSG_0("Could not allocate temporary string for name\n");	\
		ret = 1;														\
		goto out;														\
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
			message,
			message_addr
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

	return ret;
}

int rrr_cmodule_worker_new (
		struct rrr_cmodule_worker **result,
		const char *name,
		struct rrr_instance_settings *settings,
		struct rrr_fork_handler *fork_handler,
		struct rrr_mmap *mmap,
		rrr_setting_uint spawn_interval_us,
		rrr_setting_uint sleep_time_us,
		rrr_setting_uint nothing_happened_limit,
		int do_spawning,
		int do_processing,
		int do_drop_on_error
) {
	int ret = 0;

	struct rrr_cmodule_worker *worker = NULL;

	char *to_fork_name = NULL;
	char *to_parent_name = NULL;

	ALLOCATE_TMP_NAME(to_fork_name, name, "ch-to-fork");
	ALLOCATE_TMP_NAME(to_parent_name, name, "ch-to-parent");

	if ((worker = malloc(sizeof(*worker))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_cmodule_worker_new\n");
		ret = 1;
		goto out;
	}

	memset(worker, '\0', sizeof(*worker));

	if ((ret = rrr_mmap_channel_new(&worker->channel_to_fork, mmap, name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in __rrr_cmodule_worker_new\n");
		goto out_free;
	}

	if ((ret = rrr_mmap_channel_new(&worker->channel_to_parent, mmap, name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in __rrr_cmodule_worker_new\n");
		goto out_destroy_channel_to_fork;
	}

	if ((worker->name = strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate name in __rrr_cmodule_worker_new\n");
		ret = 1;
		goto out_destroy_channel_to_parent;
	}

	if ((rrr_posix_mutex_init(&worker->pid_lock, 0)) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_cmodule_worker_new\n");
		ret = 1;
		goto out_free_name;
	}

	if (sleep_time_us > spawn_interval_us) {
		sleep_time_us = spawn_interval_us;
	}

	worker->settings = settings;
	worker->fork_handler = fork_handler;
	worker->spawn_interval_us = spawn_interval_us;
	worker->sleep_time_us = sleep_time_us;
	worker->nothing_happened_limit = nothing_happened_limit;
	worker->do_spawning = do_spawning;
	worker->do_processing = do_processing;
	worker->do_drop_on_error = do_drop_on_error;

	pthread_mutex_lock(&worker->pid_lock);
	worker->pid = 0;
	pthread_mutex_unlock(&worker->pid_lock);

	*result = worker;
	worker = NULL;

	goto out;
	out_free_name:
		free(worker->name);
	out_destroy_channel_to_parent:
		rrr_mmap_channel_destroy(worker->channel_to_parent);
	out_destroy_channel_to_fork:
		rrr_mmap_channel_destroy(worker->channel_to_fork);
	out_free:
		free(worker);
	out:
		RRR_FREE_IF_NOT_NULL(to_fork_name);
		RRR_FREE_IF_NOT_NULL(to_parent_name);
		return ret;
}

// Parent need not to call this explicitly, done in destroy function.
void rrr_cmodule_worker_clear_queue_to_fork (
		struct rrr_cmodule_worker *worker
) {
	rrr_msg_holder_collection_clear(&worker->queue_to_fork);
}

// Child MUST NOT call this when exiting
void rrr_cmodule_worker_destroy (
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_destroy(worker->channel_to_fork);
	rrr_mmap_channel_destroy(worker->channel_to_parent);
	rrr_cmodule_worker_clear_queue_to_fork(worker);

	RRR_FREE_IF_NOT_NULL(worker->name);
	free(worker);
}

void rrr_cmodule_worker_get_mmap_channel_to_fork_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_get_counters_and_reset (
			read_starvation_counter,
			write_full_counter,
			worker->channel_to_fork
	);
}

void rrr_cmodule_worker_get_mmap_channel_to_parent_stats (
		unsigned long long int *read_starvation_counter,
		unsigned long long int *write_full_counter,
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_get_counters_and_reset (
			read_starvation_counter,
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

	return 0;
}

static void __rrr_cmodule_worker_log_hook (
		unsigned short loglevel_translated,
		const char *prefix,
		const char *message,
		void *private_arg
) {
	struct rrr_cmodule_worker *worker = private_arg;

	struct rrr_msg_log *message_log = NULL;

	if (rrr_msg_msg_log_new(&message_log, loglevel_translated, prefix, message) != 0) {
		goto out;
	}

	int ret = 0;
	if ((ret = rrr_mmap_channel_write (
			worker->channel_to_parent,
			message_log,
			message_log->msg_size,
			RRR_CMODULE_CHANNEL_WAIT_TIME_US,
			RRR_CMODULE_CHANNEL_WAIT_RETRIES
	)) != 0) {
		if (ret == RRR_MMAP_CHANNEL_FULL) {
			RRR_MSG_0("Warning: mmap channel was full in __rrr_cmodule_worker_fork_log_hook for worker %s in log hook\n",
				worker->name);
		}
		else {
			RRR_MSG_0("Warning: Error %i while writing to mmap channel in __rrr_cmodule_worker_fork_log_hook for worker %s in log hook\n",
				ret, worker->name);
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(message_log);
}

static int __rrr_cmodule_worker_send_setting_to_parent (
		struct rrr_setting_packed *setting,
		void *arg
) {
	struct rrr_cmodule_worker *worker = arg;

	RRR_DBG_5("cmodule worker %s notification to parent about used setting '%s'\n",
			worker->name, setting->name);

	if (rrr_mmap_channel_write(
			worker->channel_to_parent,
			setting,
			sizeof(*setting),
			RRR_CMODULE_CHANNEL_WAIT_TIME_US,
			RRR_CMODULE_CHANNEL_WAIT_RETRIES
	) != 0) {
		RRR_MSG_0("Error while writing settings to mmap channel in __rrr_cmodule_worker_send_setting_to_parent\n");
		return 1;
	}

	return 0;
}

struct rrr_cmodule_process_callback_data {
	struct rrr_cmodule_worker *worker;
	int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS);
	void *process_callback_arg;
};

static int __rrr_cmodule_worker_loop_read_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_process_callback_data *callback_data = arg;

	int ret = 0;

	const struct rrr_msg_msg *msg = data;

	if (RRR_MSG_IS_CTRL(msg)) {
		RRR_DBG_5("cmodule worker %s received control message\n", callback_data->worker->name);
		if (RRR_MSG_CTRL_F_HAS(msg, RRR_MSG_CTRL_F_PING)) {
			RRR_DBG_4("cmodule worker %s pid %ld received PING\n", callback_data->worker->name, (long) getpid());
			callback_data->worker->ping_received = 1;
		}
		else {
			RRR_DBG_4("Warning: cmodule worker %s pid %ld received unknown control message %u\n",
					callback_data->worker->name, (long) getpid(), RRR_MSG_CTRL_FLAGS(msg));
		}
	}
	else if (!callback_data->worker->do_processing) {
		RRR_MSG_0("Warning: Received a message in worker %s but no processor function is defined in configuration, dropping message\n",
				callback_data->worker->name);
	}
	else {
		const struct rrr_msg_msg *msg_msg = data;
		const struct rrr_msg_addr *msg_addr = data + MSG_TOTAL_SIZE(msg_msg);

		if (MSG_TOTAL_SIZE(msg_msg) + sizeof(*msg_addr) != data_size) {
			RRR_BUG("BUG: Size mismatch in __rrr_cmodule_worker_loop_read_callback %i+%lu != %lu\n",
					MSG_TOTAL_SIZE(msg_msg), sizeof(*msg_addr), data_size);
		}

		callback_data->worker->total_msg_mmap_to_fork++;

		RRR_DBG_3("Received a message with timestamp %" PRIu64 " in worker fork '%s'\n",
				msg->timestamp, callback_data->worker->name);
		RRR_DBG_5("cmodule worker %s received message of size %" PRIrrrl ", calling processor function\n",
				callback_data->worker->name, MSG_TOTAL_SIZE(msg_msg));

		ret = callback_data->process_callback (
				callback_data->worker,
				msg_msg,
				msg_addr,
				0, // <-- Not in spawn context
				callback_data->process_callback_arg
		);

		if (ret != 0) {
			RRR_MSG_0("Error %i from worker process function in worker %s\n", ret, callback_data->worker->name);
			if (callback_data->worker->do_drop_on_error) {
				RRR_MSG_0("Dropping message per configuration in worker %s\n", callback_data->worker->name);
				ret = 0;
			}
		}
	}

	return ret;
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
		RRR_MSG_0("Could not initialize message in __rrr_cmodule_worker_spawn_message of worker %s\n",
				worker->name);
		ret = 1;
		goto out;
	}

	struct rrr_msg_addr message_addr;
	rrr_msg_addr_init(&message_addr);

	if ((ret = process_callback(
			worker,
			message,
			&message_addr,
			1, // <-- is spawn context
			process_callback_arg
	)) != 0) {
		RRR_MSG_0("Error %i from spawn callback in __rrr_cmodule_worker_spawn_message %s\n", ret, worker->name);
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

	ret = rrr_cmodule_channel_send_message_simple(worker->channel_to_parent, &msg);

	if (ret == 0) {
		worker->total_msg_mmap_to_parent++;
	}
	// Let errors propagate

	return ret;
}

static int __rrr_cmodule_worker_loop (
		struct rrr_cmodule_worker *worker,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	struct rrr_cmodule_process_callback_data read_callback_data = {
		worker,
		process_callback,
		process_callback_arg
	};

	// Control stuff
	uint64_t time_now = 0;
	uint64_t next_spawn_time = 0;

//	int usleep_hits_b = 0;

	uint64_t prev_total_processed_msg = 0;
	uint64_t prev_total_msg_mmap_from_parent = 0;

	rrr_setting_uint consecutive_nothing_happened = 0;

	uint64_t prev_stats_time = 0;

	if (worker->do_spawning == 0 && worker->do_processing == 0) {
		RRR_BUG("BUG: Spawning nor processing mode not set in __rrr_cmodule_worker_loop\n");
	}

	RRR_DBG_5("cmodule worker %s starting loop\n", worker->name);

	while (worker->received_stop_signal == 0) {
		time_now = rrr_time_get_64();

		if (next_spawn_time == 0) {
			next_spawn_time = time_now + worker->spawn_interval_us;
		}

		if ((ret = rrr_cmodule_channel_receive_messages (
				worker->channel_to_fork,
				RRR_CMODULE_CHANNEL_WAIT_TIME_US,
				__rrr_cmodule_worker_loop_read_callback,
				&read_callback_data
		)) != 0) {
			if (ret != RRR_CMODULE_CHANNEL_EMPTY) {
				RRR_MSG_0("Error from mmap read function in worker fork named %s pid %ld\n",
						worker->name, (long) getpid());
				ret = 1;
				goto loop_out;
			}
			ret = 0;
		}

		if (worker->do_spawning) {
			if (time_now >= next_spawn_time) {
				RRR_DBG_5("cmodule worker %s spawning\n", worker->name);
				if (__rrr_cmodule_worker_spawn_message(worker, process_callback, process_callback_arg) != 0) {
					goto loop_out;
				}
				next_spawn_time = 0;
			}
		}

		if (worker->ping_received) {
			RRR_DBG_5("cmodule worker %s ping received, sending pong\n", worker->name);
			if ((ret = __rrr_cmodule_worker_send_pong(worker)) != 0) {
				RRR_MSG_0("Warning: Failed to send PONG message in worker fork named %s pid %ld return was %i\n",
						worker->name, (long) getpid(), ret);
				ret = 0;
			}
			// Always set to 0, maybe this fork should be killed if PONG messages
			// are not received by parent.
			worker->ping_received = 0;
		}

//		printf("%" PRIu64 " - %" PRIu64 "\n", prev_total_msg_mmap_from_parent, prev_total_processed_msg);

		if (	prev_total_msg_mmap_from_parent != worker->total_msg_mmap_to_fork ||
				prev_total_processed_msg != worker->total_msg_processed
		) {
			consecutive_nothing_happened = 0;
		}
		else {
			consecutive_nothing_happened++;
		}

		if (consecutive_nothing_happened > worker->nothing_happened_limit) {
			rrr_posix_usleep(worker->sleep_time_us);
		}
		else if (consecutive_nothing_happened > 100) {
			rrr_posix_usleep(100); // 100 us
		}

		if (time_now - prev_stats_time > 1000000) {
			RRR_DBG_5("cmodule worker %s alive\n", worker->name);
			// No stats here for now
			prev_stats_time = time_now;
		}

		prev_total_processed_msg = worker->total_msg_processed;
		prev_total_msg_mmap_from_parent = worker->total_msg_mmap_to_fork;
	}

	loop_out:

	RRR_DBG_1("child worker loop %s complete, received_stop_signal is %i ret is %i\n",
			worker->name,
			worker->received_stop_signal,
			ret
	);

	return ret;
}

int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback)(RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	RRR_DBG_5("cmodule worker %s running configure function\n",
			worker->name);

	if ((ret = configuration_callback(worker, configuration_callback_arg)) != 0) {
		RRR_MSG_0("Error from configuration in __rrr_cmodule_worker_loop_start\n");
		goto out;
	}

	if (rrr_settings_iterate_packed(worker->settings, __rrr_cmodule_worker_send_setting_to_parent, worker) != 0) {
		RRR_MSG_0("Error while sending back settings to parent in rrr_cmodule_worker_loop_start of worker %s\n",
				worker->name);
		ret = 1;
		goto out;
	}

	RRR_DBG_5("cmodule worker %s configuration complete, notification to parent\n",
			worker->name);

	struct rrr_msg control_msg = {0};
	rrr_msg_populate_control_msg(&control_msg, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE, 1);

	if (rrr_mmap_channel_write(
			worker->channel_to_parent,
			&control_msg,
			sizeof(control_msg),
			RRR_CMODULE_CHANNEL_WAIT_TIME_US,
			RRR_CMODULE_CHANNEL_WAIT_RETRIES
	) != 0) {
		RRR_MSG_0("Error while writing config complete control message to mmap channel in rrr_cmodule_worker_loop_start\n");
		return 1;
	}

	if ((ret = __rrr_cmodule_worker_loop(worker, process_callback, process_callback_arg)) != 0) {
		RRR_MSG_0("Error from worker loop in __rrr_cmodule_worker_loop_start\n");
		goto out;
	}

	out:
	return ret;
}

/* Example code for init wrapper */
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
			configuration_callback,
			configuration_callback_arg,
			process_callback,
			process_callback_arg
	)) != 0) {
		RRR_MSG_0("Error from worker loop in __rrr_cmodule_worker_loop_init_wrapper_default\n");
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
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	rrr_socket_close_all_no_unlink();
	rrr_log_hook_unregister_all_after_fork();

	int log_hook_handle;
	rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_worker_log_hook, worker);

	int was_found = 0;

	{
		// There is no guarantee for whether signals are active or not at this point. Disable
		// signals while working with the handler list, then always set ACTIVE afterwards.
		rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);

		// Preserve fork signal andler in case child makes any forks
		rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
		if (was_found == 0) {
			RRR_BUG("BUG: rrr_fork_signal_handler was not registered in rrr_cmodule_worker_main, should have been added in main()\n");
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
			configuration_callback,
			configuration_callback_arg,
			process_callback,
			process_callback_arg,
			init_wrapper_arg
	);

	rrr_log_hook_unregister(log_hook_handle);

	// Clear blocks allocated by us to avoid warnings in parent
	rrr_mmap_channel_writer_free_blocks(worker->channel_to_parent);

	RRR_DBG_1("cmodule %s pid %i exit\n", worker->name, getpid());

	return ret;
}
