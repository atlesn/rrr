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

#include "../util/bsd.h"
#include "../util/posix.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include "../log.h"
#include "../allocator.h"

#include "cmodule_main.h"
#include "cmodule_worker.h"
#include "cmodule_struct.h"
#include "cmodule_config_data.h"
#include "../event/event.h"
#include "../fork.h"
#include "../mmap_channel.h"
#include "../discern_stack.h"
#include "../util/rrr_time.h"

static void __rrr_cmodule_main_worker_kill (
		struct rrr_cmodule_worker *worker
) {
	pid_t pid = 0;

	RRR_DBG_1("Parent terminate worker fork %s, pid is %i\n",
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

	RRR_DBG_1("Parent sending SIGUSR1 to worker fork %s pid %i, then sleeping for 100ms\n",
			worker->name, pid);
	kill(pid, SIGUSR1);

	rrr_posix_usleep(150000); // 150 ms

	RRR_DBG_1("Parent sending SIGKILL to worker fork %s pid %i\n",
			worker->name, pid);

	kill(pid, SIGKILL);

	out:
		return;
}

static void __rrr_cmodule_worker_kill_and_cleanup (
		struct rrr_cmodule_worker *worker
) {
	// Must unregister exit handler prior to killing worker to
	// prevent handler from getting called
	rrr_fork_unregister_exit_handler(worker->fork_handler, worker->pid);

	// This is to avoid warning when mmap channel is destroyed.
	// Child fork will call writer_free_blocks on channel_to_parent.
	rrr_mmap_channel_writer_free_blocks(worker->channel_to_fork);

	// OK to call kill etc. despite fork not being started
	__rrr_cmodule_main_worker_kill(worker);

	RRR_DBG_1("Parent destroying event queue for worker fork %s pid %i\n",
			worker->name, worker->pid);
	rrr_event_queue_destroy(worker->event_queue_worker);

	RRR_DBG_1("Parent destroying worker and shared memory for worker fork %s pid %i\n",
			worker->name, worker->pid);
	rrr_cmodule_worker_cleanup(worker);
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
		struct rrr_cmodule *cmodule,
		const char *name,
		const struct rrr_settings *settings,
		const struct rrr_settings_used *settings_used,
		struct rrr_event_queue *notify_queue,
		const struct rrr_discern_stack_collection *methods,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		struct rrr_cmodule_worker_callbacks *callbacks
) {
	int ret = 0;

	// Use of global locks NOT ALLOWED before we are in child code

	if (cmodule->worker_count == RRR_CMODULE_WORKER_MAX_WORKER_COUNT) {
		RRR_BUG("BUG: Maximum worker count exceeded in rrr_cmodule_main_worker_fork_start\n");
	}

	struct rrr_cmodule_worker *worker = &cmodule->workers[cmodule->worker_count++];

	struct rrr_event_queue *worker_queue = NULL;
	if ((ret = rrr_event_queue_new(&worker_queue)) != 0) {
		RRR_MSG_0("Failed to create event queue in rrr_cmodule_main_worker_fork_start\n");
		goto out_parent;
	}

	if ((ret = rrr_cmodule_worker_init (
			worker,
			name,
			settings,
			settings_used,
			notify_queue,
			worker_queue,
			cmodule->fork_handler,
			methods,
			cmodule->config_data.worker_spawn_interval,
			cmodule->config_data.process_mode,
			cmodule->config_data.do_spawning,
			cmodule->config_data.do_drop_on_error
	)) != 0) {
		RRR_MSG_0("Could not create worker in rrr_cmodule_worker_fork_start\n");
		goto out_parent_destroy_event_queue;
	}

	worker->index = (uint8_t) (cmodule->worker_count - 1);

	pid_t pid = rrr_fork (
			cmodule->fork_handler,
			__rrr_cmodule_parent_exit_notify_handler,
			worker
	);

	if (pid < 0) {
		// Don't use rrr_strerror() due to use of global lock
		RRR_MSG_0("Could not fork in rrr_cmodule_start_worker_fork errno %i\n", errno);
		ret = 1;
		goto out_parent_cleanup_worker;
	}
	else if (pid > 0) {
		// If we deadlock here, exit handler unregister will not be called
		pthread_mutex_lock(&worker->pid_lock);
		worker->pid = pid;
		pthread_mutex_unlock(&worker->pid_lock);

		goto out_parent;
	}

	// START CHILD PROCESS CODE
	// Use of global locks OK beyond this point

	rrr_setproctitle("[worker %s]", worker->name);

	rrr_log_socket_after_fork();

	ret = rrr_cmodule_worker_main (
			worker,
			cmodule->config_data.log_prefix,
			init_wrapper_callback,
			init_wrapper_callback_arg,
			callbacks
	);

	// Clean up any events created after forking
	rrr_event_queue_destroy(worker_queue);
	rrr_log_cleanup();
	exit(ret);

	// END CHILD PROCESS CODE

	out_parent_cleanup_worker:
		rrr_cmodule_worker_cleanup(worker);
		cmodule->worker_count--;
	out_parent_destroy_event_queue:
		rrr_event_queue_destroy(worker_queue);
	out_parent:
		return ret;
}

void __rrr_cmodule_main_workers_stop (
		struct rrr_cmodule *cmodule
) {
	for (int i = 0; i < cmodule->worker_count; i++) {
		__rrr_cmodule_worker_kill_and_cleanup(&cmodule->workers[i]);
	}
	cmodule->worker_count = 0;
	rrr_fork_handle_sigchld_and_notify_if_needed(cmodule->fork_handler, 1);
}

static void __rrr_cmodule_config_data_cleanup (
	struct rrr_cmodule_config_data *config_data
) {
	RRR_FREE_IF_NOT_NULL(config_data->config_method);
	RRR_FREE_IF_NOT_NULL(config_data->process_method);
	RRR_FREE_IF_NOT_NULL(config_data->source_method);
	RRR_FREE_IF_NOT_NULL(config_data->log_prefix);
}

void rrr_cmodule_destroy (
		struct rrr_cmodule *cmodule
) {
	__rrr_cmodule_main_workers_stop(cmodule);
	rrr_msg_holder_collection_clear(&cmodule->input_queue);
	__rrr_cmodule_config_data_cleanup(&cmodule->config_data);
	rrr_free(cmodule->name);
	rrr_free(cmodule);
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

	struct rrr_cmodule *cmodule = rrr_allocate(sizeof(*cmodule));
	if (cmodule == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_cmodule_new\n");
		ret = 1;
		goto out;
	}

	memset(cmodule, '\0', sizeof(*cmodule));

	if ((cmodule->name = rrr_strdup(name)) == NULL) {
		RRR_MSG_0("Could not allocate memory for name in rrr_cmodule_new\n");
		ret = 1;
		goto out_free;
	}

	cmodule->fork_handler = fork_handler;

	// Default settings for modules which do not parse config
	cmodule->config_data.worker_spawn_interval = rrr_time_us_from_ms(rrr_cmodule_worker_default_spawn_interval);
	cmodule->config_data.worker_count = RRR_CMODULE_WORKER_DEFAULT_WORKER_COUNT;

	// Memory map not allocated until needed

	*result = cmodule;

	goto out;
	out_free:
		rrr_free(cmodule);
	out:
		return ret;
}

static void __rrr_cmodule_main_worker_maintain (struct rrr_cmodule_worker *worker) {
	rrr_cmodule_channel_maintenance(worker->channel_to_fork);
	rrr_cmodule_channel_maintenance(worker->channel_to_parent);
}

// Call once in a while, like every second
void rrr_cmodule_main_maintain (
		struct rrr_cmodule *cmodule
) {
	// We don't check for SIGCHLD while maintaining, main() handles that for us

	for (int i = 0; i < cmodule->worker_count; i++) {
		__rrr_cmodule_main_worker_maintain(&cmodule->workers[i]);
	}
}

