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
#include "util/linked_list.h"

#ifndef RRR_COMMON_H
#define RRR_COMMON_H

#define RRR_SIGNAL_HANDLED 0
#define RRR_SIGNAL_NOT_HANDLED 1

#define RRR_SIGNALS_ACTIVE 1
#define RRR_SIGNALS_NOT_ACTIVE 0

struct rrr_signal_handler {
	RRR_LL_NODE(struct rrr_signal_handler);
	int (*handler)(int signal, void *private_arg);
	void *private_arg;
};

void rrr_exit_cleanup_method_push(void (*method)(void *arg), void *arg);
void rrr_exit_cleanup_methods_run_and_free(void);
int rrr_signal_handler_get_active (void);
void rrr_signal_handler_set_active (int active);
struct rrr_signal_handler *rrr_signal_handler_push(int (*handler)(int signal, void *private_arg), void *private_arg);
void rrr_signal_handler_remove(struct rrr_signal_handler *handler);
void rrr_signal_handler_remove_all_except(int *was_found, void *function_ptr);
void rrr_signal (int s);
void rrr_signal_default_signal_actions_register(void);
int rrr_signal_default_handler(int *main_running, int s, void *arg);

#endif /* RRR_COMMON_H */
