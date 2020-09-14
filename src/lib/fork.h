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

#ifndef RRR_FORK_H
#define RRR_FORK_H

#include <sys/types.h>
#include <pthread.h>

#include "util/linked_list.h"

#define RRR_FORK_MAX_FORKS 128

struct rrr_fork {
	RRR_LL_NODE(struct rrr_fork);
	pid_t pid;
	pid_t parent_pid;
	int was_waited_for;
	void (*exit_notify)(pid_t pid, void *exit_notify_arg);
	void *exit_notify_arg;
};

struct rrr_fork_handler {
	RRR_LL_HEAD(struct rrr_fork);
	pthread_mutex_t lock;
	pthread_t self_t;
	pid_t self_p;
	struct rrr_fork forks[RRR_FORK_MAX_FORKS];
};

struct rrr_fork_unregister_exit_handler_data {
	struct rrr_fork_handler *handler;
	pid_t *pid;
};

struct rrr_fork_default_exit_notification_data {
	int *int_to_set;
};

int rrr_fork_handler_new (struct rrr_fork_handler **result);
void rrr_fork_handler_destroy (struct rrr_fork_handler *handler);
int rrr_fork_signal_handler(int s, void *arg);
void rrr_fork_send_sigusr1_and_wait (struct rrr_fork_handler *handler);
void rrr_fork_handle_sigchld_and_notify_if_needed  (struct rrr_fork_handler *handler, int force_wait_all);
pid_t rrr_fork (
		struct rrr_fork_handler *handler,
		void (*exit_notify)(pid_t pid, void *exit_notify_arg),
		void *exit_notify_arg
);
void rrr_fork_unregister_exit_handler (struct rrr_fork_handler *handler, pid_t pid);
void rrr_fork_unregister_exit_handler_void (void *arg);
void rrr_fork_default_exit_notification (pid_t pid, void *arg);

#endif /* RRR_FORK_H */
