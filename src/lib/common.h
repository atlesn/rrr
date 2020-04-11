/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "settings.h"

#ifndef RRR_COMMON_H
#define RRR_COMMON_H

#define RRR_SIGNAL_HANDLED 0
#define RRR_SIGNAL_NOT_HANDLED 1

#define RRR_SIGNALS_ACTIVE 1
#define RRR_SIGNALS_NOT_ACTIVE 0

struct rrr_signal_handler {
	struct rrr_signal_handler *next;
	int (*handler)(int signal, void *private_arg);
	void *private_arg;
};

struct rrr_signal_functions {
	void (*set_active)(int active);
	struct rrr_signal_handler *(*push_handler)(int (*hander)(int,void*), void *private_arg);
	void (*remove_handler)(struct rrr_signal_handler *);
};

void rrr_exit_cleanup_method_push(void (*method)(void *arg), void *arg);
void rrr_exit_cleanup_methods_run_and_free(void);
void rrr_signal_handler_set_active (int active);
struct rrr_signal_handler *rrr_signal_handler_push(int (*handler)(int signal, void *private_arg), void *private_arg);
void rrr_signal_handler_remove(struct rrr_signal_handler *handler);
void rrr_signal_handler_remove_all(void);
void rrr_signal (int s);


#endif /* RRR_COMMON_H */
