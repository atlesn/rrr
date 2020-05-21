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

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "posix.h"
#include "fork.h"
#include "log.h"
#include "rrr_strerror.h"
#include "common.h"

#define RRR_FORK_HANDLER_VERIFY_SELF()																	\
	do {if (handler->self_t != pthread_self() || handler->self_p != getpid()) {							\
		RRR_BUG("BUG: A fork function which must be called from main() was called from elsewhere\n");	\
	}} while (0)

#define RRR_FORK_HANDLER_ALLOCATION_SIZE \
	(sizeof(struct rrr_fork_handler) + sysconf(_SC_PAGESIZE))

int rrr_fork_handler_new (struct rrr_fork_handler **result) {
	int ret = 0;

	struct rrr_fork_handler *handler = NULL;
	pthread_mutexattr_t attr;

	*result = NULL;

	if (pthread_mutexattr_init(&attr) != 0)  {
		RRR_MSG_ERR("Could not initialize mutexattr in rrr_fork_handler_init\n");
		goto out;
	}

	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

	if ((handler = rrr_posix_mmap(RRR_FORK_HANDLER_ALLOCATION_SIZE)) == MAP_FAILED) {
		RRR_MSG_ERR("Could not allocate memory in rrr_fork_handler_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_destroy_mutexattr;
	}

	memset(handler, '\0', sizeof(*handler));

	handler->self_t = pthread_self();
	handler->self_p = getpid();

	if (pthread_mutex_init(&handler->lock, NULL) != 0) {
		RRR_MSG_ERR("Could not initialize mutex in rrr_fork_handler_init\n");
		goto out_free;
	}

	for (int i = 0; i < RRR_FORK_MAX_FORKS; i++) {
		RRR_LL_APPEND(handler, &handler->forks[i]);
	}

	*result = handler;

	goto out_destroy_mutexattr;

	out_free:
		munmap(handler, RRR_FORK_HANDLER_ALLOCATION_SIZE);
	out_destroy_mutexattr:
		pthread_mutexattr_destroy(&attr);
	out:
		return ret;
}

void rrr_fork_handler_free (struct rrr_fork_handler *handler) {
	munmap(handler, RRR_FORK_HANDLER_ALLOCATION_SIZE);
}

void rrr_fork_handler_destroy (struct rrr_fork_handler *handler) {
	RRR_FORK_HANDLER_VERIFY_SELF();
	pthread_mutex_lock(&handler->lock);
	// Cleanup forks here
	pthread_mutex_unlock(&handler->lock);
	pthread_mutex_destroy(&handler->lock);
}

// This is per fork
static int rrr_fork_handler_signal_pending = 0;

int rrr_fork_signal_handler (int s, void *arg) {
	(void)(arg);
	if (s == SIGCHLD) {
		RRR_DBG_SIGNAL("Fork signal handler received SIGCHLD\n");
		// Do not lock, only call from main context
		rrr_fork_handler_signal_pending = 1;

		// We have taken the signal
		return RRR_SIGNAL_HANDLED;
	}

	return RRR_SIGNAL_NOT_HANDLED;
}

static int __rrr_fork_clear (struct rrr_fork *fork) {
	fork->exit_notify_arg = NULL;
	fork->exit_notify = NULL;
	fork->pid = 0;
	fork->parent_pid = 0;
	fork->has_exited = 0;
	return 0;
}

static int __rrr_fork_tag_for_clearing (struct rrr_fork *fork) {
	// The parent must call the notify function
	fork->has_exited = 1;

	return 0;
}

static int __rrr_fork_notify_and_clear (struct rrr_fork *fork) {
	if (fork->exit_notify != NULL) {
		fork->exit_notify(fork->pid, fork->exit_notify_arg);
	}
	return __rrr_fork_clear(fork);
}

void rrr_fork_send_sigusr1_and_wait (struct rrr_fork_handler *handler) {
	// Call this from main() only
	RRR_FORK_HANDLER_VERIFY_SELF();

	pthread_mutex_lock (&handler->lock);

	// Signal handlers must be disabled before we do this

	RRR_DBG_1("Sending SIGUSR1 to all forks and waiting\n");

	RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
		if (node->pid > 0) {
			RRR_DBG_1("SIGUSR1 to fork %i\n", node->pid);
			kill(node->pid, SIGUSR1);
		}
	RRR_LL_ITERATE_END();

	int active_forks = 0;
	do {
		active_forks = 0;
		RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
			if (node->pid > 0 && node->has_exited == 0) {
				pid_t pid;
				int status;

				if ((pid = waitpid(node->pid, &status, WNOHANG)) == node->pid) {
					RRR_DBG_1("Waited for fork %i, exit status was %i\n", pid, status);
					RRR_LL_ITERATE_SET_DESTROY();
				}
				else if (pid == -1 && errno == ECHILD) {
					// Child does not exist
					RRR_LL_ITERATE_SET_DESTROY();
				}

				active_forks = 1;
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_tag_for_clearing(node));

		pthread_mutex_unlock (&handler->lock);
		rrr_posix_usleep(100000); // 100ms
		pthread_mutex_lock (&handler->lock);
	} while (active_forks > 0);

	pthread_mutex_unlock (&handler->lock);
}

void rrr_fork_handle_sigchld_and_notify_if_needed  (struct rrr_fork_handler *handler) {
	pid_t self = getpid();

	// We cannot lock this because it's written to within signal context
	if (rrr_fork_handler_signal_pending != 0) {
		pthread_mutex_lock (&handler->lock);

		int outwaited_children = 0;
		RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
			if (node->pid <= 0 || node->has_exited != 0 || node->parent_pid != self) {
				RRR_LL_ITERATE_NEXT();
			}

			RRR_DBG_1("Waiting for pid %i with parent pid %i, we are pid %i\n",
					node->pid, node->parent_pid, getpid());

			pid_t pid = 0;
			int status = 0;
			if ((pid = waitpid(node->pid, &status, WNOHANG)) == node->pid) {
				RRR_DBG_1("Wait for fork %i complete\n", pid);

				if (WIFSIGNALED(status)) {
					int signal = WTERMSIG(status);
					RRR_DBG_1("Fork %i was terminated by signal %i\n", pid, signal);
				}

				if (WIFEXITED(status)) {
					int child_status = WEXITSTATUS(status);
					RRR_DBG_1("Fork %i has exited with status %i\n", pid, child_status);
				}
				// Reset node
				RRR_LL_ITERATE_SET_DESTROY();

				outwaited_children++;
			}
			else if (errno == ECHILD) {
				RRR_MSG_ERR("Warning: ECHILD while waiting for python3 fork pid %i, already waited for? Removing it.\n", node->pid);
				RRR_LL_ITERATE_SET_DESTROY();
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_tag_for_clearing(node));

		// Only reset signal_pending untill we've iterated the list without
		// anything needing to be waited for
		if (outwaited_children == 0) {
			rrr_fork_handler_signal_pending = 0;
		}

		pthread_mutex_unlock (&handler->lock);
	}

	RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
		if (node->pid < 0 || node->has_exited == 0 || node->parent_pid != self) {
			RRR_LL_ITERATE_NEXT();
		}

		RRR_DBG_1("Notification for exited pid %i in parent pid %i\n",
				node->pid, self);

		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_notify_and_clear(node));
}

static struct rrr_fork *__rrr_fork_allocate_unlocked (struct rrr_fork_handler *handler) {
	struct rrr_fork *result = NULL;

	RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
		if (node->pid == 0) {
			result = node;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return result;
}

pid_t rrr_fork (
		struct rrr_fork_handler *handler,
		void (*exit_notify)(pid_t pid, void *exit_notify_arg),
		void *exit_notify_arg
) {
	pid_t ret = 0;

	pthread_mutex_lock(&handler->lock);

	struct rrr_fork *result = __rrr_fork_allocate_unlocked (handler);
	if (result == NULL) {
		RRR_MSG_ERR("No available fork slot while forking in rrr_fork\n");
		ret = -1;
		goto out_unlock;
	}

	ret = fork();

	if (ret < 0) {
		RRR_MSG_ERR("Error while forking in rrr_fork: %s\n", rrr_strerror(errno));
		ret = -1;
		goto out_unlock;
	}
	else if (ret == 0) {
		// Only parent unlocks
		goto out;
	}

	RRR_DBG_1("=== FORK PID %i ========================================================================================\n", ret);

	result->parent_pid = getpid();
	result->pid = ret;
	result->exit_notify = exit_notify;
	result->exit_notify_arg = exit_notify_arg;

	out_unlock:
		pthread_mutex_unlock(&handler->lock);
	out:
		return ret;
}

void rrr_fork_unregister_exit_handler (
		struct rrr_fork_handler *handler,
		pid_t pid
) {
	if (pid <= 0) {
		return;
	}

	pthread_mutex_lock(&handler->lock);
	RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
		if (pid == node->pid) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_clear(node));
	pthread_mutex_unlock(&handler->lock);
}

void rrr_fork_unregister_exit_handler_void (void *arg) {
	struct rrr_fork_unregister_exit_handler_data *data = arg;
	rrr_fork_unregister_exit_handler(data->handler, *(data->pid));
}

void rrr_fork_default_exit_notification (pid_t pid, void *arg) {
	struct rrr_fork_default_exit_notification_data *data = arg;
	RRR_DBG_1("Fork of main has exited, pid was %i\n", pid);
	(*(data->int_to_set)) = 1;
}
