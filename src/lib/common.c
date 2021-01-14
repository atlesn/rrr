/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "common.h"
#include "util/linked_list.h"

struct rrr_exit_cleanup_method {
	struct rrr_exit_cleanup_method *next;
	void (*method)(void *arg);
	void *arg;
};

static struct rrr_exit_cleanup_method *first_exit_cleanup_method = NULL;
pthread_mutex_t exit_cleanup_lock = PTHREAD_MUTEX_INITIALIZER;

void rrr_exit_cleanup_method_push (
		void (*method)(void *arg),
		void *arg
) {
	struct rrr_exit_cleanup_method *new_method = malloc(sizeof(*new_method));

	pthread_mutex_lock(&exit_cleanup_lock);
	new_method->method = method;
	new_method->arg = arg;
	new_method->next = first_exit_cleanup_method;
	first_exit_cleanup_method = new_method;
	pthread_mutex_unlock(&exit_cleanup_lock);
}

void rrr_exit_cleanup_methods_run_and_free(void) {
	pthread_mutex_lock(&exit_cleanup_lock);

	struct rrr_exit_cleanup_method *cur = first_exit_cleanup_method;
	while (cur) {
		struct rrr_exit_cleanup_method *next = cur->next;
		cur->method(cur->arg);
		free(cur);
		cur = next;
	}
	first_exit_cleanup_method = NULL;

	pthread_mutex_unlock(&exit_cleanup_lock);
}

struct rrr_signal_handler_collection {
	RRR_LL_HEAD(struct rrr_signal_handler);
};

static int signal_handlers_active = 0;
static struct rrr_signal_handler_collection signal_handlers = {0};
pthread_mutex_t signal_lock = PTHREAD_MUTEX_INITIALIZER;

int rrr_signal_handler_get_active (void) {
	int active = 0;
	pthread_mutex_lock(&signal_lock);
	active = signal_handlers_active;
	pthread_mutex_unlock(&signal_lock);
	return active;
}

void rrr_signal_handler_set_active (
		int active
) {
	pthread_mutex_lock(&signal_lock);
	signal_handlers_active = active;
	pthread_mutex_unlock(&signal_lock);
}

struct rrr_signal_handler *rrr_signal_handler_push(
		int (*handler)(int signal, void *private_arg),
		void *private_arg
) {
	struct rrr_signal_handler *h = malloc(sizeof(*h));
	h->handler = handler;
	h->private_arg = private_arg;

	pthread_mutex_lock(&signal_lock);
	if (signal_handlers_active == 1) {
		RRR_BUG("Signals were not disabled while being in rrr_signal_handler_push\n");
	}
	RRR_LL_APPEND(&signal_handlers, h);
	pthread_mutex_unlock(&signal_lock);

	return h;
}

void rrr_signal_handler_remove (
		struct rrr_signal_handler *handler
) {
	pthread_mutex_lock(&signal_lock);
	if (signal_handlers_active == 1) {
		RRR_BUG("Signals were not disabled while being in rrr_signal_handler_remove\n");
	}
	RRR_LL_REMOVE_NODE_IF_EXISTS(&signal_handlers, struct rrr_signal_handler, handler, free(node));
	pthread_mutex_unlock(&signal_lock);
}

void rrr_signal_handler_remove_all_except (
		int *was_found,
		void *function_ptr
) {
	*was_found = 0;

	pthread_mutex_lock(&signal_lock);
	if (signal_handlers_active == 1) {
		RRR_BUG("Signals were not disabled while being in rrr_signal_handler_remove_all_exceptl\n");
	}
	RRR_LL_ITERATE_BEGIN(&signal_handlers, struct rrr_signal_handler);
		if (node->handler == function_ptr) {
			*was_found = 1;
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&signal_handlers, 0; free(node));
	pthread_mutex_unlock(&signal_lock);
}

void rrr_signal (
		int s
) {
	RRR_DBG_SIGNAL("Received signal %i int pid %i signal handlers active: %i\n", s, getpid(), signal_handlers_active);

	if (signal_handlers_active == 1) {
		int handler_res = 1;
		int i = 0;
		RRR_LL_ITERATE_BEGIN(&signal_handlers, struct rrr_signal_handler);
			RRR_DBG_SIGNAL("Calling handler %i of %i with signal %i in pid %i\n",
					i, RRR_LL_COUNT(&signal_handlers), s, getpid());
			int ret = node->handler(s, node->private_arg);
			if (ret == RRR_SIGNAL_HANDLED) {
				// Handlers may also return non-zero for signal to continue
				handler_res = 0;
				RRR_LL_ITERATE_LAST();
			}
			i++;
		RRR_LL_ITERATE_END();

		if (handler_res == RRR_SIGNAL_HANDLED) {
			return;
		}
	}
}

void rrr_signal_default_signal_actions_register(void) {
	// Initialize signal handling
	struct sigaction action;
	action.sa_handler = rrr_signal;
	sigemptyset (&action.sa_mask);
	action.sa_flags = 0;

	// Handle forked children exiting
	sigaction (SIGCHLD, &action, NULL);
	// We generally ignore sigpipe and use NONBLOCK on all sockets
	signal (SIGPIPE, SIG_IGN);
	// Used to set main_running = 0. The signal is set to default afterwards
	// so that a second SIGINT will terminate the process
	sigaction (SIGINT, &action, NULL);
	// Used to set main_running = 0;
	sigaction (SIGUSR1, &action, NULL);
	// Used to set main_running = 0;
	sigaction (SIGTERM, &action, NULL);
}

int rrr_signal_default_handler (
		int *main_running,
		int s,
		void *arg
) {
	(void)(arg);

	if (s == SIGCHLD) {
		RRR_DBG_SIGNAL("Received SIGCHLD in default handler\n");
	}
	else if (s == SIGUSR1) {
		// Used internally, no printed message
		*main_running = 0;
		return RRR_SIGNAL_HANDLED;
	}
	else if (s == SIGPIPE) {
		RRR_DBG_SIGNAL("Received SIGPIPE in default handler, ignoring\n");
	}
	else if (s == SIGTERM) {
		RRR_DBG_SIGNAL("Received SIGTERM in default handler, setting main_running to 0\n");
		*main_running = 0;
		return RRR_SIGNAL_HANDLED;
	}
	else if (s == SIGINT) {
		// Allow double ctrl+c to close program
		if (s == SIGINT) {
			RRR_DBG_SIGNAL("Received SIGINT in default handler, setting main_running to 0\n");
			signal(SIGINT, SIG_DFL);
		}

		*main_running = 0;
		return RRR_SIGNAL_HANDLED;
	}

	return RRR_SIGNAL_NOT_HANDLED;
}
