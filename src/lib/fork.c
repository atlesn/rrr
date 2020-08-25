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

#include "fork.h"
#include "log.h"
#include "rrr_strerror.h"
#include "common.h"
#include "util/posix.h"

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
		RRR_MSG_0("Could not initialize mutexattr in rrr_fork_handler_init\n");
		goto out;
	}

	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

	if ((handler = rrr_posix_mmap(RRR_FORK_HANDLER_ALLOCATION_SIZE)) == MAP_FAILED) {
		RRR_MSG_0("Could not allocate memory in rrr_fork_handler_new: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_destroy_mutexattr;
	}

	memset(handler, '\0', sizeof(*handler));

	handler->self_t = pthread_self();
	handler->self_p = getpid();

	if (pthread_mutex_init(&handler->lock, NULL) != 0) {
		RRR_MSG_0("Could not initialize mutex in rrr_fork_handler_init\n");
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

static void __rrr_fork_handler_free (struct rrr_fork_handler *handler) {
	munmap(handler, RRR_FORK_HANDLER_ALLOCATION_SIZE);
}

static int __rrr_fork_clear (struct rrr_fork *fork) {
	fork->exit_notify_arg = NULL;
	fork->exit_notify = NULL;
	fork->pid = 0;
	fork->parent_pid = 0;
	fork->was_waited_for = 0;
	return 0;
}

void rrr_fork_handler_destroy (struct rrr_fork_handler *handler) {
	RRR_FORK_HANDLER_VERIFY_SELF();
	pthread_mutex_lock(&handler->lock);
	RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
		if (node->pid > 0) {
			RRR_MSG_0("Warning: Child fork pid %i had not yet exited or exit notifications was not set while destroying fork handler.\n", node->pid);
			if (node->was_waited_for != 1) {
				RRR_MSG_0("Warning: Child fork pid %i had not been waited for while destroying fork handler, is now possibly a zombie.\n", node->pid);
			}
		}
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_clear(node));
	pthread_mutex_unlock(&handler->lock);
	pthread_mutex_destroy(&handler->lock);
	__rrr_fork_handler_free(handler);
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

static int __rrr_fork_set_waited_for (struct rrr_fork *fork) {
	// The parent must call the notify function
	fork->was_waited_for = 1;

	return 0;
}

static int __rrr_fork_notify_and_clear (struct rrr_fork *fork) {
	RRR_DBG_1("Notification to exit handlers for exited pid %i in parent pid %i\n",
			fork->pid, getpid());

	if (fork->exit_notify != NULL) {
		fork->exit_notify(fork->pid, fork->exit_notify_arg);
	}

	return __rrr_fork_clear(fork);
}

static int __rrr_fork_waitpid (pid_t pid, int *status, int options) {
	pid_t ret = waitpid(pid, status, options);
	if (ret > 0) {
		RRR_DBG_1("=== WAIT PID %i ========================================================================================\n", ret);
		if (WIFSIGNALED(*status)) {
			int signal = WTERMSIG(*status);
			RRR_DBG_4("Fork %i was terminated by signal %i\n", ret, signal);
		}
		if (WIFEXITED(*status)) {
			int child_status = WEXITSTATUS(*status);
			RRR_DBG_4("Fork %i has exited with status %i\n", ret, child_status);
		}
	}
	return ret;
}

static void __rrr_fork_wait_loop (int *active_forks_found, struct rrr_fork_handler *handler, int max_rounds) {
	if (pthread_mutex_trylock (&handler->lock) == 0) {
		RRR_BUG("BUG: Handler was not locked in __rrr_fork_wait_loop\n");
	}

	*active_forks_found = 0;

	do {
		if (max_rounds-- <= 0) {
			RRR_MSG_0("Timeout reached while waiting for forks to exit\n");
			break;
		}
		*active_forks_found = 0;
		RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
			if (node->pid > 0 && node->was_waited_for == 0) {
				RRR_DBG_4("After signalling, checking wait for pid %i has exited is %i\n", node->pid, node->was_waited_for);
				pid_t pid;
				int status;

				if ((pid = __rrr_fork_waitpid(node->pid, &status, WNOHANG)) == node->pid) {
					RRR_DBG_4("Wait pid %i ok\n", node->pid);
					RRR_LL_ITERATE_SET_DESTROY();
				}
				else if (pid == -1 && errno == ECHILD) {
					RRR_DBG_4("Error from waitpid on pid %i in parent %i status %i after signalling: %s. Not exited yet? Might be a child of a child (whos parent has not exited).\n",
							node->pid, getpid(), status, rrr_strerror(errno));
				}

				*active_forks_found = 1;
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_set_waited_for(node));

		pthread_mutex_unlock (&handler->lock);
		rrr_posix_usleep(100000); // 100ms
		pthread_mutex_lock (&handler->lock);
	} while (*active_forks_found != 0);
}

void rrr_fork_send_sigusr1_and_wait (struct rrr_fork_handler *handler) {
	// Call this from main() only
	RRR_FORK_HANDLER_VERIFY_SELF();

	pthread_mutex_lock (&handler->lock);

	// Signal handlers must be disabled before we do this

	int active_forks_found = 1;
	for (int i = 0; i < 10 && active_forks_found; i++) {
		RRR_DBG_1("Sending SIGUSR1 to all forks and waiting in pid %i\n", getpid());

		RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
			if (node->pid > 0) {
				RRR_DBG_1("SIGUSR1 to fork %i\n", node->pid);
				kill(node->pid, SIGUSR1);
			}
	/*		else {
	 *			// THIS ELSE CLAUSE SHOULD BE COMMENTED OUT
	 *			// Only for testing errors
	 *			node->pid = 5555;
	 *		}*/
		RRR_LL_ITERATE_END();

		__rrr_fork_wait_loop(&active_forks_found, handler, 5); // 5 rounds = ~0.5 seconds
	}

	// Try SIGKILL
	if (RRR_LL_COUNT(handler) > 0) {
		RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
			if (node->pid > 0 && node->was_waited_for == 0) {
				RRR_DBG_1("SIGKILL to fork %i\n", node->pid);
				kill(node->pid, SIGKILL);
			}
		RRR_LL_ITERATE_END();

		// Try waiting one last time
		__rrr_fork_wait_loop(&active_forks_found, handler, 10); // 10 rounds = ~1 second
		if (active_forks_found) {
			RRR_MSG_0("At least one fork was still alive after waiting, we now have a possible ghost situation.\n");
		}
	}

	pthread_mutex_unlock (&handler->lock);
}

void rrr_fork_handle_sigchld_and_notify_if_needed  (struct rrr_fork_handler *handler, int force_wait_all) {
	pid_t self = getpid();

	// We cannot lock this because it's written to within signal context
	if (rrr_fork_handler_signal_pending != 0 || force_wait_all) {
		pthread_mutex_lock (&handler->lock);
		rrr_fork_handler_signal_pending = 0;

		if (force_wait_all) {
			RRR_DBG_4("Fork force wait all, self pid is %i\n", self);
		}
		else {
			RRR_DBG_4("Fork handle SIGCHLD, self pid is %i\n", self);
		}

		int pid_count = 0;
		pid_t waited_for_pids[RRR_FORK_MAX_FORKS];

		pid_t pid_tmp;
		int status;
		while ((pid_tmp = __rrr_fork_waitpid(-1, &status, WNOHANG)) > 0) {
			if (pid_count == RRR_FORK_MAX_FORKS) {
				RRR_BUG("BUG: Too many forks in rrr_fork_handle_sigchld_and_notify_if_needed\n");
			}
			waited_for_pids[pid_count++] = pid_tmp;
			RRR_DBG_4("Fork %i exited with status %i\n", pid_tmp, status);
		}

		RRR_LL_ITERATE_BEGIN(handler, struct rrr_fork);
			int was_waited_for = 0;

			if (node->pid <= 0) {
				RRR_LL_ITERATE_NEXT();
			}
			else if (node->was_waited_for != 0) {
				was_waited_for = 1;
			}
			else {
				if (force_wait_all) {
					int status;
					RRR_DBG_4("Fork late wait for pid %i self is %i\n", node->pid, self);
					if (__rrr_fork_waitpid(node->pid, &status, WNOHANG) > 0) {
						was_waited_for = 1;
					}
					else {
						RRR_DBG_4("Fork %i had not yet exited or we are not the parent when late-waiting\n", node->pid);
					}
				}
				else {
					for (int i = 0; i < pid_count; i++) {
						if (waited_for_pids[i] == node->pid) {
							was_waited_for = 1;
						}
					}
				}
			}

			if (was_waited_for) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY_NO_REMOVE(__rrr_fork_notify_and_clear(node));

		pthread_mutex_unlock (&handler->lock);
	}
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

	/*
	 * XXX : For some reason the perl5 module might sometimes hang during
	 *       initialization when it forks out the worker. It will then hang
	 *       waiting on this lock, despite the lock reporting "not acquired"
	 *       when we attach a debugger. This seems however not to be a problem
	 *       if when spin on trylock like this (also for some reason).
	 */
	while (pthread_mutex_trylock(&handler->lock) != 0) {
		rrr_posix_usleep(5000);
	}

	struct rrr_fork *result = __rrr_fork_allocate_unlocked (handler);
	if (result == NULL) {
		RRR_MSG_0("No available fork slot while forking in rrr_fork\n");
		ret = -1;
		goto out_unlock;
	}

	ret = fork();

	if (ret < 0) {
		RRR_MSG_0("Error while forking in rrr_fork: %s\n", rrr_strerror(errno));
		ret = -1;
		goto out_unlock;
	}
	else if (ret == 0) {
		// Child code
		// Only parent unlocks. This is a PSHARED lock.
		goto out;
	}

	// Parent code

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
