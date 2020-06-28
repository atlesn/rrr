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
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include "cmodule.h"

#include "../global.h"
#include "rrr_mmap.h"
#include "mmap_channel.h"
#include "message_addr.h"
#include "message_log.h"
#include "messages.h"
#include "log.h"
#include "vl_time.h"
#include "posix.h"
#include "fork.h"
#include "common.h"
#include "ip_buffer_entry.h"
#include "gnu.h"

#define RRR_CMODULE_MMAP_SIZE (1024*1024*2)

static int __rrr_cmodule_deferred_message_destroy (
		struct rrr_cmodule_deferred_message *msg
) {
	RRR_FREE_IF_NOT_NULL(msg->msg);
	RRR_FREE_IF_NOT_NULL(msg->msg_addr);
	free(msg);
	return 0;
}

static int __rrr_cmodule_deferred_message_new_and_push (
		struct rrr_cmodule_deferred_message_collection *collection,
		struct rrr_message *msg,
		const struct rrr_message_addr *msg_addr
) {
	int ret = 0;

	struct rrr_cmodule_deferred_message *node = NULL;
	struct rrr_message_addr *msg_addr_tmp = NULL;

	if ((ret = rrr_message_addr_clone(&msg_addr_tmp, msg_addr)) != 0) {
		RRR_MSG_0("Could not allocate memory in __rrr_cmodule_deferred_message_push\n");
		goto out;
	}

	if ((node = malloc(sizeof(*node))) == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_cmodule_deferred_message_push\n");
		goto out;
	}

	memset(node, '\0', sizeof(*node));

	node->msg = msg;
	node->msg_addr = msg_addr_tmp;
	msg_addr_tmp = NULL;

	RRR_LL_APPEND(collection, node);
	node = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg_addr_tmp);
	if (node != NULL) {
		__rrr_cmodule_deferred_message_destroy(node);
	}
	return ret;
}

#define ALLOCATE_TMP_NAME(target, name1, name2)															\
	if (rrr_asprintf(&target, "%s-%s", name1, name2) <= 0) {											\
		RRR_MSG_0("Could not allocate temporary string for name in __rrr_cmodule_worker_new\n");		\
		ret = 1;																						\
		goto out;																						\
	}

static int __rrr_cmodule_worker_new (
		struct rrr_cmodule_worker **result,
		struct rrr_mmap *mmap,
		uint64_t spawn_interval_us,
		uint64_t sleep_interval_us,
		const char *name,
		int do_spawning,
		int do_processing,
		int do_drop_on_error,
		struct rrr_instance_settings *settings,
		struct rrr_fork_handler *fork_handler
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

	if ((rrr_mmap_channel_new(&worker->channel_to_fork, mmap, name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in __rrr_cmodule_worker_new\n");
		goto out_free;
	}

	if ((rrr_mmap_channel_new(&worker->channel_to_parent, mmap, name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in __rrr_cmodule_worker_new\n");
		goto out_destroy_channel_to_fork;
	}

	if ((worker->name = strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate name in __rrr_cmodule_worker_new\n");
		ret = 1;
		goto out_destroy_channel_to_parent;
	}

	if ((pthread_mutex_init(&worker->pid_lock, NULL)) != 0) {
		RRR_MSG_0("Could not initialize lock in __rrr_cmodule_worker_new\n");
		ret = 1;
		goto out_free_name;
	}

	worker->spawn_interval_us = spawn_interval_us;
	worker->sleep_interval_us = sleep_interval_us;

	worker->do_spawning = do_spawning;
	worker->do_processing = do_processing;
	worker->do_drop_on_error = do_drop_on_error;

	worker->settings = settings;
	worker->fork_handler = fork_handler;

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
static void __rrr_cmodule_worker_clear_deferred_to_fork (
		struct rrr_cmodule_worker *worker
) {
	RRR_LL_DESTROY(&worker->deferred_to_fork, struct rrr_cmodule_deferred_message, __rrr_cmodule_deferred_message_destroy(node));
}

// Called by child only before exiting
static void __rrr_cmodule_worker_clear_deferred_to_parent (
		struct rrr_cmodule_worker *worker
) {
	RRR_LL_DESTROY(&worker->deferred_to_parent, struct rrr_cmodule_deferred_message, __rrr_cmodule_deferred_message_destroy(node));
}

// Child MUST NOT call this when exiting
static void __rrr_cmodule_worker_destroy (
		struct rrr_cmodule_worker *worker
) {
	RRR_FREE_IF_NOT_NULL(worker->name);
	rrr_mmap_channel_destroy(worker->channel_to_fork);
	rrr_mmap_channel_destroy(worker->channel_to_parent);
	__rrr_cmodule_worker_clear_deferred_to_fork(worker);

	if (RRR_LL_COUNT(&worker->deferred_to_parent) != 0) {
		RRR_BUG("BUG: deferred_to_parent count was not 0 in __rrr_cmodule_worker_destroy. Either the parent has by accident added something, or destroy was called from child fork.\n");
	}

	free(worker);
}

// Call this only from parent
static void __rrr_cmodule_worker_kill (
		struct rrr_cmodule_worker *worker
) {
	pid_t pid = 0;

	RRR_DBG_1("Terminate worker fork %s, pid is %i\n",
			worker->name, worker->pid);

	// Make sure locking/unlocking is correct
	pthread_mutex_lock(&worker->pid_lock);
	if (worker->pid <= 0) {
		pthread_mutex_unlock(&worker->pid_lock);
		goto out;
	}

	pid = worker->pid;
	worker->pid = 0;

	pthread_mutex_unlock(&worker->pid_lock);

	// Don't wrap these inside lock
	// Just do our ting disregarding return values

	RRR_DBG_1("Sending SIGUSR1 to worker fork %s pid %i, then sleeping for 100ms\n",
			worker->name, pid);
	kill(pid, SIGUSR1);

	rrr_posix_usleep(100000); // 100 ms

	RRR_DBG_1("Sending SIGKILL to worker fork %s pid %i\n",
			worker->name, pid);

	kill(pid, SIGKILL);

	out:
		return;
}

// Called only by parent
static void __rrr_cmodule_worker_kill_and_destroy (
		struct rrr_cmodule_worker *worker
) {
	// Must unregister exit handler prior to killing worker to
	// prevent handler from getting called
	rrr_fork_unregister_exit_handler(worker->fork_handler, worker->pid);

	// This is to avoid warning when mmap channel is destroyed.
	// Child fork will call write_free_blocks on channel_to_parent.
	rrr_mmap_channel_writer_free_blocks(worker->channel_to_fork);

	// OK to call kill etc. despite fork not being started
	__rrr_cmodule_worker_kill(worker);
	__rrr_cmodule_worker_destroy(worker);
}

struct rrr_cmodule_mmap_channel_callback_data {
	const struct rrr_message_addr *addr_msg;
	const struct rrr_message *msg;
};

static int __rrr_cmodule_mmap_channel_write_callback (void *target, void *arg) {
	struct rrr_cmodule_mmap_channel_callback_data *data = arg;

	void *msg_pos = target;
	void *msg_addr_pos = target + MSG_TOTAL_SIZE(data->msg);

	memcpy(msg_pos, data->msg, MSG_TOTAL_SIZE(data->msg));
	memcpy(msg_addr_pos, data->addr_msg, sizeof(*(data->addr_msg)));

	return 0;
}

static int __rrr_cmodule_send_message (
		int *sent_total,
		struct rrr_mmap_channel *channel,
		struct rrr_cmodule_deferred_message_collection *deferred_queue,
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr
) {
	int ret = 0;

	*sent_total = 0;

	int retry_max = 500;

	// If there are deferred messages, immediately push the new message to
	// deferred queue and instead process the first one in the queue
	if (RRR_LL_COUNT(deferred_queue) > 0) {
		goto retry_defer_message;
	}

	goto send_message;

	retry_defer_message:
		if (__rrr_cmodule_deferred_message_new_and_push(deferred_queue, message, message_addr) != 0) {
			RRR_MSG_0("Error while pushing deferred message in __rrr_cmodule_send_message\n");
			ret = 1;
			goto out;
		}

		// Ownership taken by queue
		message = NULL;

		// Not to be used anymore for now
		message_addr = NULL;

		if (--retry_max == 0) {
			RRR_MSG_0("Retries exceeded in __rrr_cmodule_send_message\n");
			ret = 1;
			goto out;
		}

	// We allow the function to be called with NULL message, in which case
	// we just try to read from the deferred queue
	send_message:
		if (message == NULL) {
			if (RRR_LL_COUNT(deferred_queue) > 0) {
				struct rrr_cmodule_deferred_message *deferred_message = RRR_LL_SHIFT(deferred_queue);
				message = deferred_message->msg;
				message_addr = deferred_message->msg_addr;
				__rrr_cmodule_deferred_message_destroy(deferred_message);
			}
		}

		if (message == NULL) {
			// Nothing to do if message still is NULL
			goto out;
		}

		struct rrr_cmodule_mmap_channel_callback_data callback_data = {
			message_addr,
			message
		};

		if ((ret = rrr_mmap_channel_write_using_callback (
				channel,
				MSG_TOTAL_SIZE(message) + sizeof(*message_addr),
				__rrr_cmodule_mmap_channel_write_callback,
				&callback_data
		)) != 0) {
			if (ret == RRR_MMAP_CHANNEL_FULL) {
				ret = 0;
				goto retry_defer_message;
			}
			RRR_MSG_0("Could not send address message on mmap channel in __rrr_cmodule_send_message name\n");
			ret = 1;
			goto out;
		}

	out:
		RRR_FREE_IF_NOT_NULL(message);
		return ret;
}

// Will always free the message also upon errors
int rrr_cmodule_worker_send_message_to_parent (
		struct rrr_cmodule_worker *worker,
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr
) {
	int sent_total = 0;

	// Will always free the message also upon errors
	int ret = __rrr_cmodule_send_message (
			&sent_total,
			worker->channel_to_parent,
			&worker->deferred_to_parent,
			message,
			message_addr
	);

	worker->total_msg_mmap_to_parent += sent_total;

	return ret;
}

struct rrr_cmodule_process_callback_data {
	struct rrr_cmodule_worker *worker;
	int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS);
	void *process_callback_arg;
};

int __rrr_cmodule_worker_loop_mmap_channel_read_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_process_callback_data *callback_data = arg;

	const struct rrr_message *msg = data;
	const struct rrr_message_addr *msg_addr = data + MSG_TOTAL_SIZE(msg);

	if (MSG_TOTAL_SIZE(msg) + sizeof(*msg_addr) != data_size) {
		RRR_BUG("BUG: Size mismatch in __rrr_cmodule_worker_loop_mmap_channel_read_callback %i+%lu != %lu\n",
				MSG_TOTAL_SIZE(msg), sizeof(*msg_addr), data_size);
	}

	callback_data->worker->total_msg_mmap_to_fork++;

	int ret = callback_data->process_callback (
			callback_data->worker,
			msg,
			msg_addr,
			0, // <-- Not in spawn context
			callback_data->process_callback_arg
	);

	if (ret != 0) {
		RRR_MSG_0("Error %i from worker process fucntion in worker %s\n", callback_data->worker->name);
		if (callback_data->worker->do_drop_on_error) {
			RRR_MSG_0("Dropping message per configuration in worker %s\n", callback_data->worker->name);
			ret = 0;
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

	struct rrr_message *message = NULL;

	if (rrr_message_new_empty (
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

	struct rrr_message_addr message_addr;
	rrr_message_addr_init(&message_addr);

	if ((ret = process_callback(
			worker,
			message,
			&message_addr,
			1, // <-- is spawn context
			process_callback_arg
	)) != 0) {
		RRR_MSG_0("Error %i from spawn callback in __rrr_cmodule_worker_spawn_message %s\n", worker->name);
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

static int __rrr_cmodule_worker_loop (
		struct rrr_cmodule_worker *worker,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	if (worker->do_spawning == 0 && worker->do_processing == 0) {
		RRR_BUG("BUG: Spawning  nor processing mode not set in __rrr_cmodule_worker_loop\n");
	}

	struct rrr_cmodule_process_callback_data read_callback_data = {
		worker,
		process_callback,
		process_callback_arg
	};

	// Control stuff
	uint64_t time_now = rrr_time_get_64();
	uint64_t next_spawn_time = 0;

	if (worker->sleep_interval_us > worker->spawn_interval_us) {
		worker->sleep_interval_us = worker->spawn_interval_us;
	}

	int usleep_hits_b = 0;

	uint64_t prev_total_processed_msg = 0;
	uint64_t prev_total_msg_mmap_from_parent = 0;

	int consecutive_nothing_happend = 0;

	uint64_t prev_stats_time = 0;

	while (worker->received_stop_signal == 0) {
		// Check for backlog on the socket. Don't process any more messages untill backlog is cleared up


		time_now = rrr_time_get_64();

		if (next_spawn_time == 0) {
			next_spawn_time = time_now + worker->spawn_interval_us;
		}

		if (worker->do_processing) {
			for (int i = 0; i < 10; i++) {
				if ((ret = rrr_mmap_channel_read_all (
						worker->channel_to_fork,
						__rrr_cmodule_worker_loop_mmap_channel_read_callback,
						&read_callback_data
				)) != 0) {
					if (ret != RRR_MMAP_CHANNEL_EMPTY) {
						RRR_MSG_0("Error from mmap read function in worker fork named %s\n",
								worker->name);
						ret = 1;
						break;
					}
					ret = 0;
				}
				if (prev_total_msg_mmap_from_parent == worker->total_msg_mmap_to_fork) {
					break;
				}
			}
		}

		if (worker->do_spawning) {
			if (time_now >= next_spawn_time) {
				if (__rrr_cmodule_worker_spawn_message(worker, process_callback, process_callback_arg) != 0) {
					break;
				}
				next_spawn_time = 0;
			}
		}

		if (	prev_total_msg_mmap_from_parent != worker->total_msg_mmap_to_fork ||
				prev_total_processed_msg != worker->total_msg_processed
		) {
			consecutive_nothing_happend = 0;
		}

		if (++consecutive_nothing_happend > 250) {
			usleep_hits_b++;
			rrr_posix_usleep(worker->sleep_interval_us);
		}

		if (time_now - prev_stats_time > 1000000) {
			// No stats here for now
			prev_stats_time = time_now;
		}

		prev_total_processed_msg = worker->total_msg_processed;
		prev_total_msg_mmap_from_parent = worker->total_msg_mmap_to_fork;
	}

	RRR_DBG_1("child worker loop %s complete, received_stop_signal is %i ret is %i\n",
			worker->name,
			worker->received_stop_signal,
			ret
	);

	return ret;
}

static int __rrr_cmodule_worker_send_setting_to_parent (
		struct rrr_setting_packed *setting,
		void *arg
) {
	struct rrr_cmodule_worker *worker = arg;

	if (rrr_mmap_channel_write(worker->channel_to_parent, setting, sizeof(*setting)) != 0) {
		RRR_MSG_0("Error while writing settings to mmap channel in __rrr_cmodule_worker_send_setting_to_parent\n");
		return 1;
	}

	return 0;
}

int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback)(RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

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

	struct rrr_socket_msg control_msg = {0};
	rrr_socket_msg_populate_control_msg(&control_msg, RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE, 1);

	if (rrr_mmap_channel_write(worker->channel_to_parent, &control_msg, sizeof(control_msg)) != 0) {
		RRR_MSG_0("Error while writing config complete control message to mmap channel in __rrr_cmodule_worker_loop_start \n");
		return 1;
	}

	if ((ret = __rrr_cmodule_worker_loop(worker, process_callback, process_callback_arg)) != 0) {
		RRR_MSG_0("Error from worker loop in __rrr_cmodule_worker_loop_start\n");
		goto out;
	}

	out:
	return ret;
}

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

static int __rrr_cmodule_worker_signal_handler (int signal, void *private_arg) {
	struct rrr_cmodule_worker *worker = private_arg;

	if (signal == SIGUSR1 || signal == SIGINT || signal == SIGTERM) {
		RRR_DBG_SIGNAL("script worker %s received SIGUSR1, SIGTERM or SIGINT, stopping\n",
				worker->name);
		worker->received_stop_signal = 1;
	}

	return 0;
}

static void __rrr_cmodule_worker_fork_log_hook (
		unsigned short loglevel_translated,
		const char *prefix,
		const char *message,
		void *private_arg
) {
	struct rrr_cmodule_worker *worker = private_arg;

	struct rrr_message_log *message_log = NULL;

	if (rrr_message_log_new(&message_log, loglevel_translated, prefix, message) != 0) {
		goto out;
	}

	int ret = 0;
	if ((ret = rrr_mmap_channel_write(worker->channel_to_parent, message_log, message_log->msg_size)) != 0) {
		if (ret == RRR_MMAP_CHANNEL_FULL) {
			RRR_MSG_0("mmap channel was full in __rrr_cmodule_worker_fork_log_hook for worker %s\n",
					worker->name);
			ret = 1;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(message_log);
}

static void __rrr_cmodule_parent_exit_notify_handler (pid_t pid, void *arg) {
	struct rrr_cmodule_worker *worker = arg;

	RRR_MSG_0("Received SIGCHLD for child fork %i named %s\n",
			pid, worker->name);

	if (worker->pid == 0) {
		RRR_MSG_0("Note: Child had already exited and we knew about it, worker is named %s\n",
				worker->name);
	}
	else if (pid != worker->pid) {
		RRR_BUG("PID mismatch in __rrr_cmodule_parent_signal_handler (%i<>%i)\n", pid, worker->pid);
	}

	worker->pid = 0;
}

int rrr_cmodule_start_worker_fork (
		pid_t *handle_pid,
		struct rrr_cmodule *cmodule,
		struct rrr_fork_handler *fork_handler,
		uint64_t spawn_interval_us,
		uint64_t sleep_interval_us,
		const char *name,
		int do_spawning,
		int do_processing,
		int do_drop_on_error,
		struct rrr_instance_settings *settings,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	*handle_pid = 0;

	struct rrr_cmodule_worker *worker = NULL;

	if ((ret = __rrr_cmodule_worker_new (
			&worker,
			cmodule->mmap,
			spawn_interval_us,
			sleep_interval_us,
			name,
			do_spawning,
			do_processing,
			do_drop_on_error,
			settings,
			fork_handler
	)) != 0) {
		RRR_MSG_0("Could not create worker in rrr_cmodule_start_worker_fork\n");
		goto out_parent;
	}

	// Append to LL after forking is OK

	pid_t pid = rrr_fork(fork_handler, __rrr_cmodule_parent_exit_notify_handler, worker);

	if (pid < 0) {
		RRR_MSG_0("Could not fork in rrr_cmodule_start_worker_fork: %s\n",
				rrr_strerror(errno));
		ret = 1;
		goto out_parent;
	}
	else if (pid > 0) {
		// If we deadlock here, exit handler unregister will not be called
		pthread_mutex_lock(&worker->pid_lock);
		worker->pid = pid;
		pthread_mutex_unlock(&worker->pid_lock);

		RRR_LL_APPEND(cmodule, worker);
		worker = NULL;

		*handle_pid = pid;

		goto out_parent;
	}

	// CHILD PROCESS CODE
	rrr_socket_close_all_no_unlink();
	rrr_log_hook_unregister_all_after_fork();

	int log_hook_handle;

	rrr_log_hook_register(&log_hook_handle, __rrr_cmodule_worker_fork_log_hook, worker);

	rrr_signal_handler_remove_all();
	rrr_signal_handler_push(__rrr_cmodule_worker_signal_handler, worker);

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

	// Clear deferred queue. DO NOT call the worker destroy function, doing this causes
	// double free of mmap resources (parent calls destroy)
	__rrr_cmodule_worker_clear_deferred_to_parent(worker);

	exit(ret);

	out_parent:
		if (worker != NULL) {
			__rrr_cmodule_worker_destroy(worker);
		}
		return ret;
}

void rrr_cmodule_stop_forks (
		struct rrr_cmodule *cmodule
) {
	RRR_LL_DESTROY(cmodule, struct rrr_cmodule_worker, __rrr_cmodule_worker_kill_and_destroy(node));
}

void rrr_cmodule_stop_forks_and_destroy (
		struct rrr_cmodule *cmodule
) {
	RRR_LL_DESTROY(cmodule, struct rrr_cmodule_worker, __rrr_cmodule_worker_kill_and_destroy(node));
	if (cmodule->mmap != NULL) {
		rrr_mmap_destroy(cmodule->mmap);
		cmodule->mmap = NULL;
	}
	free(cmodule);
}

void rrr_cmodule_stop_forks_and_destroy_void (
		void *arg
) {
	rrr_cmodule_stop_forks_and_destroy(arg);
}

int rrr_cmodule_new (
		struct rrr_cmodule **result,
		const char *name
) {
	int ret = 0;

	struct rrr_cmodule *cmodule = malloc(sizeof(*cmodule));
	if (cmodule == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_cmodule_new\n");
		ret = 1;
		goto out;
	}

	memset(cmodule, '\0', sizeof(*cmodule));

	if (rrr_mmap_new(&cmodule->mmap, RRR_CMODULE_MMAP_SIZE, name) != 0) {
		RRR_MSG_0("Could not allocate mmap in rrr_cmodule_init\n");
		ret = 1;
		goto out_free;
	}

	*result = cmodule;

	goto out;
	out_free:
		free(cmodule);
	out:
		return ret;
}

struct rrr_cmodule_read_from_fork_callback_data {
		struct rrr_cmodule_worker *worker;
		int count;
		int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS);
		void *final_callback_arg;
};

static int __rrr_cmodule_read_from_fork_message_callback (
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

int __rrr_cmodule_read_from_fork_log_callback (
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

int __rrr_cmodule_read_from_fork_setting_callback (
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

static int __rrr_cmodule_read_from_fork_control_callback (
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

static int __rrr_cmodule_read_from_fork_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_read_from_fork_callback_data *callback_data = arg;

	const struct rrr_socket_msg *msg = data;

	if (RRR_SOCKET_MSG_IS_RRR_MESSAGE(msg)) {
		return __rrr_cmodule_read_from_fork_message_callback(data, data_size, callback_data);
	}
	else if (RRR_SOCKET_MSG_IS_RRR_MESSAGE_LOG(msg)) {
		return __rrr_cmodule_read_from_fork_log_callback((const struct rrr_message_log *) msg, data_size, callback_data);
	}
	else if (RRR_SOCKET_MSG_IS_SETTING(msg)) {
		return __rrr_cmodule_read_from_fork_setting_callback((const struct rrr_setting_packed *) msg, data_size, callback_data);
	}
	else if (RRR_SOCKET_MSG_IS_CTRL(msg)) {
		return __rrr_cmodule_read_from_fork_control_callback(msg, data_size, callback_data);
	}

	RRR_BUG("BUG: Unknown message type %u in __rrr_cmodule_read_from_fork_callback\n", msg->msg_type);

	return 0;
}

int rrr_cmodule_read_from_forks (
		int *read_count,
		int *config_complete,
		struct rrr_cmodule *cmodule,
		int loops,
		int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
) {
	int ret = 0;

	*read_count = 0;

	// Set to 1 first, and if any worker has config_complete set to zero, set it to zero
	*config_complete = 1;

	int read_total = 0;
	RRR_LL_ITERATE_BEGIN(cmodule, struct rrr_cmodule_worker);
		struct rrr_cmodule_read_from_fork_callback_data callback_data = {
				node,
				0, // Counter
				final_callback,
				final_callback_arg
		};
		for (int i = 0; i < loops; i++) {
			if ((ret = rrr_mmap_channel_read_all (
					node->channel_to_parent,
					__rrr_cmodule_read_from_fork_callback,
					&callback_data
			)) != 0) {
				if (ret == RRR_MMAP_CHANNEL_EMPTY) {
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

			if (callback_data.count == 0) {
				break;
			}

			read_total += callback_data.count;
			callback_data.count = 0;
		}

		if (node->config_complete == 0) {
			*config_complete = 0;
		}
	RRR_LL_ITERATE_END();


	/* TODO : Implement this
	 * 		uint64_t time_now = rrr_time_get_64();

		if (time_now > next_bubblesort_time) {
			// Speed up memory access. Sorting is usually only performed
			// when the first few thousand messages are received, after that
			// no sorting is needed.
			int was_sorted = 0;
			int max_rounds = 100;
			do {
				rrr_mmap_channel_bubblesort_pointers (data->channel_to_child, &was_sorted);
			} while (was_sorted == 0 && --max_rounds > 0);
			next_bubblesort_time = time_now + 500000; // 500ms
		}
	 */

	out:
	*read_count = read_total;
	return ret;
}

// Will always free the message also upon errors
int rrr_cmodule_send_to_fork (
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

			// Will always free the message also upon errors
			if ((ret = __rrr_cmodule_send_message (
					sent_total,
					node->channel_to_fork,
					&node->deferred_to_fork,
					msg,
					msg_addr
			)) != 0) {
				RRR_MSG_0("Error while sending message in rrr_cmodule_send_to_fork\n");
				ret = 1;
				goto out;
			}

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

// Call once in a while, like every second
void rrr_cmodule_maintain(struct rrr_fork_handler *handler) {
	rrr_fork_handle_sigchld_and_notify_if_needed(handler);
}
