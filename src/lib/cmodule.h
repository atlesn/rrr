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

#ifndef RRR_CMODULE_H
#define RRR_CMODULE_H

#include <inttypes.h>
#include <pthread.h>

#include "linked_list.h"
#include "socket/rrr_socket_constants.h"

#define RRR_CMODULE_CONTROL_MSG_CONFIG_COMPLETE \
	RRR_SOCKET_MSG_CTRL_F_USR_A

struct rrr_mmap;
struct rrr_mmap_channel;
struct rrr_instance_settings;
struct rrr_fork_handler;

struct rrr_cmodule_deferred_message {
	RRR_LL_NODE(struct rrr_cmodule_deferred_message);
	struct rrr_message *msg;
	struct rrr_message_addr *msg_addr;
};

struct rrr_cmodule_deferred_message_collection {
	RRR_LL_HEAD(struct rrr_cmodule_deferred_message);
};

struct rrr_cmodule_worker {
	RRR_LL_NODE(struct rrr_cmodule_worker);

	char *name;

	pthread_mutex_t pid_lock;

	pid_t pid;
	int received_stop_signal;

	int config_complete;

	int do_spawning;
	int do_processing;
	int do_drop_on_error;

	uint64_t spawn_interval_us;
	uint64_t sleep_interval_us;

	struct rrr_cmodule_deferred_message_collection deferred_to_fork;
	struct rrr_cmodule_deferred_message_collection deferred_to_parent;

	struct rrr_mmap_channel *channel_to_fork;
	struct rrr_mmap_channel *channel_to_parent;

	uint64_t total_msg_mmap_to_fork;
	uint64_t total_msg_mmap_to_parent;

	uint64_t total_msg_processed;

	// Unmanaged pointers provided by application
	struct rrr_instance_settings *settings;
	struct rrr_fork_handler *fork_handler;
};

struct rrr_cmodule {
	RRR_LL_HEAD(struct rrr_cmodule_worker);
	struct rrr_mmap *mmap;
};

#define RRR_CMODULE_FINAL_CALLBACK_ARGS					\
		const struct rrr_message *msg,					\
		const struct rrr_message_addr *msg_addr,		\
		void *arg

#define RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS			\
		struct rrr_cmodule_worker *worker,				\
		void *private_arg

#define RRR_CMODULE_PROCESS_CALLBACK_ARGS					\
		struct rrr_cmodule_worker *worker,					\
		const struct rrr_message *message,					\
		const struct rrr_message_addr *message_addr,		\
		int is_spawn_ctx,									\
		void *private_arg

#define RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS 									\
		struct rrr_cmodule_worker *worker,										\
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),	\
		void *configuration_callback_arg,										\
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),			\
		void *process_callback_arg,												\
		void *private_arg

// Will always free the message also upon errors
int rrr_cmodule_worker_send_message_to_parent (
		struct rrr_cmodule_worker *worker,
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr
);
int rrr_cmodule_worker_loop_start (
		struct rrr_cmodule_worker *worker,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback)(RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
int rrr_cmodule_worker_loop_init_wrapper_default (
		RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS
);
int rrr_cmodule_start_worker_fork (
		pid_t *handle_pid,
		struct rrr_cmodule *cmodule,
		struct rrr_fork_handler *fork_handler,
		uint64_t spawn_interval_us,
		uint64_t sleep_interval_us,
		const char *name,
		int do_spawning,
		int do_processing,
		int do_drop_on_error,
		struct rrr_instance_settings *settings,
		int (*init_wrapper_callback)(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS),
		void *init_wrapper_arg,
		int (*configuration_callback)(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS),
		void *configuration_callback_arg,
		int (*process_callback) (RRR_CMODULE_PROCESS_CALLBACK_ARGS),
		void *process_callback_arg
);
void rrr_cmodule_stop_forks_and_cleanup (
		struct rrr_cmodule *cmodule
);
void rrr_cmodule_stop_forks_and_cleanup_void (
		void *arg
);
int rrr_cmodule_init (
		struct rrr_cmodule *cmodule,
		const char *name
);
int rrr_cmodule_read_from_forks (
		int *read_count,
		int *config_complete,
		struct rrr_cmodule *cmodule,
		int loops,
		int (*final_callback)(RRR_CMODULE_FINAL_CALLBACK_ARGS),
		void *final_callback_arg
);
// Will always free the message also upon errors
int rrr_cmodule_send_to_fork (
		int *sent_total,
		struct rrr_cmodule *cmodule,
		pid_t worker_handle_pid,
		struct rrr_message *msg,
		const struct rrr_message_addr *msg_addr
);
// Call once in a while, like every second
void rrr_cmodule_maintain(struct rrr_fork_handler *handler);

#endif
