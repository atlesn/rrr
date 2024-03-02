/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_CMODULE_MAIN_H
#define RRR_CMODULE_MAIN_H

#define RRR_CMODULE_NATIVE_CTX
#include "../../cmodules/cmodule.h"

#include <inttypes.h>
#include <pthread.h>

#include "../log.h"

#include "cmodule_channel.h"
#include "cmodule_defines.h"
#include "../settings.h"
#include "../message_holder/message_holder_collection.h"

struct rrr_instance_config_data;
struct rrr_settings;
struct rrr_fork_handler;
struct rrr_mmap_channel;
struct rrr_cmodule_worker;
struct rrr_mmap;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_event_queue;
struct rrr_cmodule_worker_callbacks;
struct rrr_discern_stack_collection;

struct rrr_cmodule;

int rrr_cmodule_main_worker_fork_start (
		struct rrr_cmodule *cmodule,
		const char *name,
		const struct rrr_settings *settings,
		const struct rrr_settings_used *settings_used,
		struct rrr_event_queue *notify_queue,
		rrr_event_receiver_handle notify_queue_handle,
		const struct rrr_discern_stack_collection *methods,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		struct rrr_cmodule_worker_callbacks *callbacks
);
void rrr_cmodule_destroy (
		struct rrr_cmodule *cmodule
);
void rrr_cmodule_destroy_void (
		void *arg
);
int rrr_cmodule_new (
		struct rrr_cmodule **result,
		const char *name,
		struct rrr_fork_handler *fork_handler
);
// Call once in a while, like every second
void rrr_cmodule_main_maintain (
		struct rrr_cmodule *cmodule
);

#endif /* RRR_CMODULE_MAIN_H */
