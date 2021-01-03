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

#include "cmodule_main.h"
#include "cmodule_worker.h"
#include "../fork.h"
#include "../rrr_mmap.h"
#include "../mmap_channel.h"
#include "../util/posix.h"

static void __rrr_cmodule_main_worker_kill (
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
	__rrr_cmodule_main_worker_kill(worker);
	rrr_cmodule_worker_destroy(worker);
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

int rrr_cmodule_main_worker_fork_start (
		pid_t *handle_pid,
		struct rrr_cmodule *cmodule,
		const char *name,
		struct rrr_instance_settings *settings,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
) {
	int ret = 0;

	// Use of global locks NOT ALLOWED before we are in child code

	*handle_pid = 0;

	struct rrr_cmodule_worker *worker = NULL;

	if ((ret = rrr_cmodule_worker_new (
			&worker,
			name,
			settings,
			cmodule->fork_handler,
			cmodule->mmap,
			cmodule->config_data.worker_spawn_interval_us,
			cmodule->config_data.worker_sleep_time_us,
			cmodule->config_data.worker_nothing_happened_limit,
			cmodule->config_data.do_spawning,
			cmodule->config_data.do_processing,
			cmodule->config_data.do_drop_on_error
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
		// Don't use rrr_strerror() due to use of global lock
		RRR_MSG_0("Could not fork in rrr_cmodule_start_worker_fork errno %i\n", errno);
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
	// Use of global locks OK beyond this point

	ret = rrr_cmodule_worker_main (
			worker,
			cmodule->config_data.log_prefix,
			init_wrapper_callback,
			init_wrapper_callback_arg,
			configuration_callback,
			configuration_callback_arg,
			process_callback,
			process_callback_arg
	);

	exit(ret);

	out_parent:
		if (worker != NULL) {
			rrr_cmodule_worker_destroy(worker);
		}
		return ret;
}

void rrr_cmodule_main_workers_stop (
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
	rrr_cmodule_main_workers_stop(cmodule);
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

static void __rrr_cmodule_main_worker_maintain (struct rrr_cmodule_worker *worker) {
	// Speed up memory access. Sorting is usually only performed
	// when the first few thousand messages are received, after that
	// no sorting is needed.
	rrr_cmodule_channel_bubblesort(worker->channel_to_fork);
	rrr_cmodule_channel_bubblesort(worker->channel_to_parent);
}

// Call once in a while, like every second
void rrr_cmodule_main_maintain (
		struct rrr_cmodule *cmodule
) {
	// We don't check for SIGCHLD while maintaining, main() handles that for us

	RRR_LL_ITERATE_BEGIN(cmodule, struct rrr_cmodule_worker);
		__rrr_cmodule_main_worker_maintain(node);
	RRR_LL_ITERATE_END();
}

