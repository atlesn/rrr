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

#ifndef RRR_CMODULE_DEFINES_H
#define RRR_CMODULE_DEFINES_H

#include "../socket/rrr_socket_constants.h"
#include "../read_constants.h"
#include "../util/linked_list.h"
#include "../settings.h"

#define RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE \
        RRR_MSG_CTRL_F_USR_A

#define RRR_CMODULE_CHANNEL_OK           RRR_READ_OK
#define RRR_CMODULE_CHANNEL_ERROR        RRR_READ_HARD_ERROR
#define RRR_CMODULE_CHANNEL_FULL         RRR_READ_SOFT_ERROR
#define RRR_CMODULE_CHANNEL_EMPTY        RRR_READ_SOFT_ERROR

#define RRR_CMODULE_DEFERRED_QUEUE_MAX   1000

#define RRR_CMODULE_DEFAULT_SLEEP_TIME_MS                   50
#define RRR_CMODULE_DEFAULT_NOTHING_HAPPENED_LIMIT          250

#define RRR_CMODULE_WORKER_DEFAULT_SLEEP_TIME_MS            RRR_CMODULE_DEFAULT_SLEEP_TIME_MS
#define RRR_CMODULE_WORKER_DEFAULT_NOTHING_HAPPENED_LIMIT   RRR_CMODULE_DEFAULT_NOTHING_HAPPENED_LIMIT
#define RRR_CMODULE_WORKER_DEFAULT_WORKER_COUNT             1
#define RRR_CMODULE_WORKER_DEFAULT_SPAWN_INTERVAL_MS        1000

#define RRR_CMODULE_WORKER_MAX_WORKER_COUNT                 16

#define RRR_CMODULE_CHANNEL_SIZE             (1024*1024*2*RRR_CMODULE_WORKER_MAX_WORKER_COUNT)
#define RRR_CMODULE_CHANNEL_WAIT_TIME_US     100
#define RRR_CMODULE_CHANNEL_WAIT_RETRIES     500

#define RRR_CMODULE_FINAL_CALLBACK_ARGS                        \
        const struct rrr_msg_msg *msg,                         \
        const struct rrr_msg_addr *msg_addr,                   \
        void *arg

#define RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS                \
        struct rrr_cmodule_worker *worker,                     \
        void *private_arg
                                                               \
#define RRR_CMODULE_PROCESS_CALLBACK_ARGS                      \
        struct rrr_cmodule_worker *worker,                     \
        const struct rrr_msg_msg *message,                     \
        const struct rrr_msg_addr *message_addr,               \
        int is_spawn_ctx,                                      \
        void *private_arg

#define RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS                                          \
        int *something_happened,                                                       \
        struct rrr_cmodule_worker *worker,                                             \
        void *private_arg

#define RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS                                         \
        struct rrr_cmodule_worker *worker,                                             \
        int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),        \
        void *configuration_callback_arg,                                              \
        int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),                   \
        void *process_callback_arg,                                                    \
	int (*custom_tick_callback)(RRR_CMODULE_CUSTOM_TICK_CALLBACK_ARGS),            \
	void *custom_tick_callback_arg,                                                \
        void *private_arg

struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_cmodule_worker;

#endif /* RRR_CMODULE_DEFINES_H */
