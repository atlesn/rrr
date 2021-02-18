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
#include "../util/linked_list.h"

#define RRR_CMODULE_WORKER_FORK_PONG_TIMEOUT_S 10

struct rrr_instance_config_data;
struct rrr_instance_settings;
struct rrr_fork_handler;
struct rrr_mmap_channel;
struct rrr_cmodule_worker;
struct rrr_mmap;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_event_queue;

struct rrr_cmodule;

int rrr_cmodule_main_worker_fork_start (
		struct rrr_cmodule *cmodule,
		const char *name,
		struct rrr_instance_settings *settings,
		struct rrr_event_queue *notify_queue,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_callback_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg,
		int (*init_custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),
		void *init_custom_tick_callback_arg
);
void rrr_cmodule_main_workers_stop (
		struct rrr_cmodule *cmodule
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
