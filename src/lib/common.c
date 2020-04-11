/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#include "../global.h"
#include "common.h"

struct rrr_exit_cleanup_method {
	struct rrr_exit_cleanup_method *next;
	void (*method)(void *arg);
	void *arg;
};

static struct rrr_exit_cleanup_method *first_exit_cleanup_method = NULL;
pthread_mutex_t exit_cleanup_lock = PTHREAD_MUTEX_INITIALIZER;

void rrr_exit_cleanup_method_push(void (*method)(void *arg), void *arg) {
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

static int signal_handlers_active = 0;
static struct rrr_signal_handler *first_handler = NULL;
pthread_mutex_t signal_lock = PTHREAD_MUTEX_INITIALIZER;

void rrr_signal_handler_set_active (int active) {
	pthread_mutex_lock(&signal_lock);
	signal_handlers_active = active;
	pthread_mutex_unlock(&signal_lock);
}

struct rrr_signal_handler *rrr_signal_handler_push(int (*handler)(int signal, void *private_arg), void *private_arg) {
	struct rrr_signal_handler *h = malloc(sizeof(*h));
	h->handler = handler;
	h->private_arg = private_arg;

	pthread_mutex_lock(&signal_lock);
	h->next = first_handler;
	first_handler = h;
	pthread_mutex_unlock(&signal_lock);
	return h;
}

void rrr_signal_handler_remove(struct rrr_signal_handler *handler) {
	pthread_mutex_lock(&signal_lock);
	int did_remove = 0;
	if (first_handler == handler) {
		first_handler = first_handler->next;
		free(handler);
		did_remove = 1;
	}
	else {
		struct rrr_signal_handler *test = first_handler;
		while (test) {
			if (test->next == handler) {
				test->next = test->next->next;
				free(handler);
				did_remove = 1;
				break;
			}
			test = test->next;
		}
	}
	if (did_remove != 1) {
		RRR_BUG("Attempted to remove signal handler which did not exist\n");
	}
	pthread_mutex_unlock(&signal_lock);
}

// Done in child forks
void rrr_signal_handler_remove_all(void) {
	pthread_mutex_lock(&signal_lock);

	struct rrr_signal_handler *test = first_handler;

	while (test) {
		struct rrr_signal_handler *next = test->next;
		free(test);
		test = next;
	}

	first_handler = NULL;

	pthread_mutex_unlock(&signal_lock);
}

void rrr_signal (int s) {
    RRR_DBG_1("Received signal %i\n", s);

	struct rrr_signal_handler *test = first_handler;

	if (signal_handlers_active == 1) {
		int handler_res = 1;
		while (test) {
			int ret = test->handler(s, test->private_arg);
			if (ret == 0) {
				// Handlers may also return non-zero for signal to continue
				handler_res = 0;
				break;
			}
			test = test->next;
		}

		if (handler_res == 0) {
			return;
		}
	}
}
