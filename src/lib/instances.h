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

#ifndef RRR_INSTANCES_H
#define RRR_INSTANCES_H

#include "../global.h"
#include "modules.h"
#include "configuration.h"
#include "instance_collection.h"
#include "threads.h"

struct rrr_fork_handler;
struct rrr_stats_engine;
struct rrr_message_broker;
typedef void rrr_message_broker_costumer_handle;

// TODO : Many pointers in different structs are probably redundant

struct instance_metadata {
	struct instance_metadata *next;
	struct rrr_instance_dynamic_data *dynamic_data;
	struct rrr_instance_thread_data *thread_data;
	struct rrr_instance_collection senders;
	struct rrr_instance_collection wait_for;
	struct rrr_instance_config *config;
	struct rrr_signal_handler *signal_handler;
	unsigned long int senders_count;
};

#define INSTANCE_M_NAME(instance) instance->dynamic_data->instance_name
#define INSTANCE_M_MODULE_NAME(instance) instance->dynamic_data->module_name

struct instance_metadata_collection {
	int length;
	struct instance_metadata *first_entry;
	struct rrr_signal_functions *signal_functions;
};

struct rrr_instance_dynamic_data {
	const char *instance_name;
	const char *module_name;
	unsigned int type;
	int start_priority;
	struct rrr_module_operations operations;
	void *special_module_operations;
	void *dl_ptr;
	void *private_data;
	void (*unload)(void);
	int (*signal_handler)(int s, void *priv);
	struct instance_metadata_collection *all_instances;
};

#define INSTANCE_D_NAME(thread_data) thread_data->init_data.module->instance_name
#define INSTANCE_D_MODULE_NAME(thread_data) thread_data->init_data.module->module_name

struct instance_thread_init_data {
	struct cmd_data *cmd_data;
	struct rrr_instance_config *instance_config;
	struct rrr_config *global_config;
	struct rrr_instance_dynamic_data *module;
	struct rrr_instance_collection *senders;
	struct rrr_stats_engine *stats;
	struct rrr_message_broker *message_broker;
	struct rrr_fork_handler *fork_handler;
};

struct rrr_instance_thread_data {
	struct instance_thread_init_data init_data;

	int used_by_ghost;

	struct rrr_thread *thread;
	rrr_message_broker_costumer_handle *message_broker_handle;

	void *private_data;
	void *preload_data;
	char private_memory[RRR_MODULE_PRIVATE_MEMORY_SIZE];
	char preload_memory[RRR_MODULE_PRELOAD_MEMORY_SIZE];
};

#define INSTANCE_D_FORK(thread_data) thread_data->init_data.fork_handler
#define INSTANCE_D_STATS(thread_data) thread_data->init_data.stats
#define INSTANCE_D_BROKER(thread_data) thread_data->init_data.message_broker
#define INSTANCE_D_HANDLE(thread_data) thread_data->message_broker_handle
#define INSTANCE_D_BROKER_ARGS(thread_data) \
		thread_data->init_data.message_broker, thread_data->message_broker_handle

#define RRR_INSTANCE_LOOP(target,collection) \
	for (struct instance_metadata *target = collection->first_entry; target != NULL; target = target->next)

struct instance_metadata *rrr_instance_find_by_thread (
		struct instance_metadata_collection *collection,
		struct rrr_thread *thread
);
int rrr_instance_check_threads_stopped(struct instance_metadata_collection *target);
void rrr_instance_free_all_thread_data(struct instance_metadata_collection *target);
int rrr_instance_count_library_users (struct instance_metadata_collection *target, void *dl_ptr);
void rrr_instance_unload_all(struct instance_metadata_collection *target);
void rrr_instance_metadata_collection_destroy (struct instance_metadata_collection *target);
int rrr_instance_metadata_collection_new (
		struct instance_metadata_collection **target,
		struct rrr_signal_functions *signal_functions
);
int rrr_instance_add_senders (
		struct instance_metadata_collection *instances,
		struct instance_metadata *instance
);
int rrr_instance_add_wait_for_instances (
		struct instance_metadata_collection *instances,
		struct instance_metadata *instance
);
int rrr_instance_load_and_save (
		struct instance_metadata_collection *instances,
		struct rrr_instance_config *instance_config,
		const char **library_paths
);
struct instance_metadata *rrr_instance_find (
		struct instance_metadata_collection *target,
		const char *name
);
unsigned int rrr_instance_metadata_collection_count (struct instance_metadata_collection *collection);
void rrr_instance_destroy_thread(struct rrr_instance_thread_data *data);
void rrr_instance_destroy_thread_by_ghost (void *private_data);
struct rrr_instance_thread_data *rrr_instance_new_thread(struct instance_thread_init_data *init_data);
int rrr_instance_preload_thread(struct rrr_thread_collection *collection, struct rrr_instance_thread_data *data);
int rrr_instance_start_thread (struct rrr_instance_thread_data *data);
int rrr_instance_process_from_config(
		struct instance_metadata_collection *instances,
		struct rrr_config *config,
		const char **library_paths
);
int rrr_instance_count_receivers_of_self (struct rrr_instance_thread_data *self);
int rrr_instance_default_set_output_buffer_ratelimit_when_needed (
		int *delivery_entry_count,
		int *delivery_ratelimit_active,
		struct rrr_instance_thread_data *thread_data
);

#endif /* RRR_INSTANCES_H */
