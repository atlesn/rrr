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
#include <errno.h>

#include "../log.h"

#include "cmodule_defer_queue.h"
#include "cmodule_main.h"

#include "../rrr_strerror.h"
#include "../rrr_mmap.h"
#include "../mmap_channel.h"
#include "../message_addr.h"
#include "../message_log.h"
#include "../messages.h"
#include "../fork.h"
#include "../common.h"
#include "../ip_buffer_entry.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"
#include "../util/rrr_time.h"
#include "../util/posix.h"

#define ALLOCATE_TMP_NAME(target, name1, name2)															\
	if (rrr_asprintf(&target, "%s-%s", name1, name2) <= 0) {											\
		RRR_MSG_0("Could not allocate temporary string for name in __rrr_cmodule_worker_new\n");		\
		ret = 1;																						\
		goto out;																						\
	}

static int __rrr_cmodule_worker_new (
		struct rrr_cmodule_worker **result,
		struct rrr_cmodule *cmodule,
		const char *name,
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

	if ((rrr_mmap_channel_new(&worker->channel_to_fork, cmodule->mmap, name)) != 0) {
		RRR_MSG_0("Could not create mmap channel in __rrr_cmodule_worker_new\n");
		goto out_free;
	}

	if ((rrr_mmap_channel_new(&worker->channel_to_parent, cmodule->mmap, name)) != 0) {
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

	worker->config_data = &cmodule->config_data;
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
	RRR_LL_DESTROY(&worker->deferred_to_fork, struct rrr_cmodule_deferred_message, rrr_cmodule_deferred_message_destroy(node));
}

// Called by child only before exiting
static void __rrr_cmodule_worker_clear_deferred_to_parent (
		struct rrr_cmodule_worker *worker
) {
	RRR_LL_DESTROY(&worker->deferred_to_parent, struct rrr_cmodule_deferred_message, rrr_cmodule_deferred_message_destroy(node));
}

// Child MUST NOT call this when exiting
static void __rrr_cmodule_worker_destroy (
		struct rrr_cmodule_worker *worker
) {
	rrr_mmap_channel_destroy(worker->channel_to_fork);
	rrr_mmap_channel_destroy(worker->channel_to_parent);
	__rrr_cmodule_worker_clear_deferred_to_fork(worker);

	if (RRR_LL_COUNT(&worker->deferred_to_parent) != 0) {
		RRR_BUG("BUG: deferred_to_parent count was not 0 in __rrr_cmodule_worker_destroy. Either the parent has by accident added something, or destroy was called from child fork.\n");
	}

	RRR_FREE_IF_NOT_NULL(worker->name);
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

struct rrr_cmodule_process_callback_data {
	struct rrr_cmodule_worker *worker;
	int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS);
	void *process_callback_arg;
};

static int __rrr_cmodule_worker_loop_read_callback (const void *data, size_t data_size, void *arg) {
	struct rrr_cmodule_process_callback_data *callback_data = arg;

	const struct rrr_message *msg = data;
	const struct rrr_message_addr *msg_addr = data + MSG_TOTAL_SIZE(msg);

	if (MSG_TOTAL_SIZE(msg) + sizeof(*msg_addr) != data_size) {
		RRR_BUG("BUG: Size mismatch in __rrr_cmodule_worker_loop_read_callback %i+%lu != %lu\n",
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
		RRR_MSG_0("Error %i from worker process function in worker %s\n", ret, callback_data->worker->name);
		if (callback_data->worker->config_data->do_drop_on_error) {
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
		RRR_MSG_0("Error %i from spawn callback in __rrr_cmodule_worker_spawn_message %s\n", ret, worker->name);
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

	if (worker->config_data->do_spawning == 0 && worker->config_data->do_processing == 0) {
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

	if (worker->config_data->sleep_time_us > worker->config_data->spawn_interval_us) {
		worker->config_data->sleep_time_us = worker->config_data->spawn_interval_us;
	}

//	int usleep_hits_b = 0;

	uint64_t prev_total_processed_msg = 0;
	uint64_t prev_total_msg_mmap_from_parent = 0;

	rrr_setting_uint consecutive_nothing_happened = 0;

	uint64_t prev_stats_time = 0;

	while (worker->received_stop_signal == 0) {
		// Check for backlog on the socket. Don't process any more messages untill backlog is cleared up

		time_now = rrr_time_get_64();

		if (next_spawn_time == 0) {
			next_spawn_time = time_now + worker->config_data->spawn_interval_us;
		}

		if (worker->config_data->do_processing) {
			if ((ret = rrr_cmodule_channel_receive_messages (
					worker->channel_to_fork,
					RRR_CMODULE_CHANNEL_WAIT_TIME_US,
					__rrr_cmodule_worker_loop_read_callback,
					&read_callback_data
			)) != 0) {
				if (ret != RRR_CMODULE_CHANNEL_EMPTY) {
					RRR_MSG_0("Error from mmap read function in worker fork named %s\n",
							worker->name);
					ret = 1;
					goto loop_out;
				}
				ret = 0;
			}
		}

		if (worker->config_data->do_spawning) {
			if (time_now >= next_spawn_time) {
				if (__rrr_cmodule_worker_spawn_message(worker, process_callback, process_callback_arg) != 0) {
					goto loop_out;
				}
				next_spawn_time = 0;
			}
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

		if (consecutive_nothing_happened > worker->config_data->nothing_happened_limit) {
			rrr_posix_usleep(worker->config_data->sleep_time_us);
		}
		else if (consecutive_nothing_happened > 100) {
			rrr_posix_usleep(100); // 100 us
		}

		if (time_now - prev_stats_time > 1000000) {
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

static int __rrr_cmodule_worker_send_setting_to_parent (
		struct rrr_setting_packed *setting,
		void *arg
) {
	struct rrr_cmodule_worker *worker = arg;

	if (rrr_mmap_channel_write(
			worker->channel_to_parent,
			setting,
			sizeof(*setting),
			RRR_CMODULE_CHANNEL_WAIT_TIME_US
	) != 0) {
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

	if (rrr_mmap_channel_write(
			worker->channel_to_parent,
			&control_msg,
			sizeof(control_msg),
			RRR_CMODULE_CHANNEL_WAIT_TIME_US
	) != 0) {
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
		RRR_DBG_SIGNAL("script worker %s pid %i received SIGUSR1, SIGTERM or SIGINT, stopping\n",
				worker->name, getpid());
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
	if ((ret = rrr_mmap_channel_write(
			worker->channel_to_parent,
			message_log,
			message_log->msg_size,
			RRR_CMODULE_CHANNEL_WAIT_TIME_US
	)) != 0) {
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

	RRR_DBG_1("Received SIGCHLD for child fork %i named %s\n",
			pid, worker->name);

	if (worker->pid == 0) {
		RRR_DBG_1("Note: Child had already exited and we knew about it, worker is named %s\n",
				worker->name);
	}
	else if (pid != worker->pid) {
		RRR_BUG("PID mismatch in __rrr_cmodule_parent_signal_handler (%i<>%i)\n", pid, worker->pid);
	}

	worker->pid = 0;
}

int rrr_cmodule_worker_fork_start (
		pid_t *handle_pid,
		struct rrr_cmodule *cmodule,
		const char *name,
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
			cmodule,
			name,
			settings,
			cmodule->fork_handler
	)) != 0) {
		RRR_MSG_0("Could not create worker in rrr_cmodule_worker_fork_start\n");
		goto out_parent;
	}

	// Append to LL after forking is OK

	pid_t pid = rrr_fork (
			cmodule->fork_handler,
			__rrr_cmodule_parent_exit_notify_handler,
			worker
	);

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

	int was_found = 0;

	// Preserve fork signal andler in case child makes any forks
	rrr_signal_handler_remove_all_except(&was_found, &rrr_fork_signal_handler);
	if (was_found == 0) {
		RRR_BUG("BUG: rrr_fork_signal_handler was not registered in rrr_cmodule_worker_fork_start, should have been added in main()\n");
	}

	rrr_signal_handler_push(__rrr_cmodule_worker_signal_handler, worker);

	// It's safe to use the char * from cmodule_data. It will never
	// get freed by the fork, instances framework does that when the thread is exiting.
	if (cmodule->config_data.log_prefix != NULL && *(cmodule->config_data.log_prefix) != '\0') {
		rrr_config_set_log_prefix(cmodule->config_data.log_prefix);
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

	// Clear deferred queue. DO NOT call the worker destroy function, doing this causes
	// double free of mmap resources (parent calls destroy)
	__rrr_cmodule_worker_clear_deferred_to_parent(worker);

	RRR_DBG_1("cmodule %s pid %i exit\n", worker->name, getpid());

	exit(ret);

	out_parent:
		if (worker != NULL) {
			__rrr_cmodule_worker_destroy(worker);
		}
		return ret;
}

void rrr_cmodule_workers_stop (
		struct rrr_cmodule *cmodule
) {
	RRR_LL_DESTROY(cmodule, struct rrr_cmodule_worker, __rrr_cmodule_worker_kill_and_destroy(node));
	rrr_fork_handle_sigchld_and_notify_if_needed(cmodule->fork_handler, 1);
}

static void __rrr_cmodule_config_data_cleanup (
	struct rrr_cmodule_config_data *config_data
) {
	RRR_FREE_IF_NOT_NULL(config_data->config_function);
	RRR_FREE_IF_NOT_NULL(config_data->process_function);
	RRR_FREE_IF_NOT_NULL(config_data->source_function);
	RRR_FREE_IF_NOT_NULL(config_data->log_prefix);
}

void rrr_cmodule_destroy (
		struct rrr_cmodule *cmodule
) {
	rrr_cmodule_workers_stop(cmodule);
	if (cmodule->mmap != NULL) {
		rrr_mmap_destroy(cmodule->mmap);
		cmodule->mmap = NULL;
	}
	__rrr_cmodule_config_data_cleanup(&cmodule->config_data);
	free(cmodule);
}

void rrr_cmodule_destroy_void (
		void *arg
) {
	rrr_cmodule_destroy(arg);
}

int rrr_cmodule_new (
		struct rrr_cmodule **result,
		const char *name,
		struct rrr_fork_handler *fork_handler
) {
	int ret = 0;

	struct rrr_cmodule *cmodule = malloc(sizeof(*cmodule));
	if (cmodule == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_cmodule_new\n");
		ret = 1;
		goto out;
	}

	memset(cmodule, '\0', sizeof(*cmodule));

	if (rrr_mmap_new(&cmodule->mmap, RRR_CMODULE_CHANNEL_SIZE, name) != 0) {
		RRR_MSG_0("Could not allocate mmap in rrr_cmodule_init\n");
		ret = 1;
		goto out_free;
	}

	cmodule->fork_handler = fork_handler;

	*result = cmodule;

	goto out;
	out_free:
		free(cmodule);
	out:
		return ret;
}

static void __rrr_cmodule_worker_maintain (struct rrr_cmodule_worker *worker) {
	// Speed up memory access. Sorting is usually only performed
	// when the first few thousand messages are received, after that
	// no sorting is needed.
	rrr_cmodule_channel_bubblesort(worker->channel_to_fork);
	rrr_cmodule_channel_bubblesort(worker->channel_to_parent);
}

// Call once in a while, like every second
void rrr_cmodule_maintain (
		struct rrr_cmodule *cmodule
) {
	// We don't check for SIGCHLD while maintaining, main() handles that for us

	RRR_LL_ITERATE_BEGIN(cmodule, struct rrr_cmodule_worker);
		__rrr_cmodule_worker_maintain(node);
	RRR_LL_ITERATE_END();
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
