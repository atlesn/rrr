/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>

#include "log.h"
#include "cmodule/cmodule_main.h"
#include "modules.h"
#include "threads.h"
#include "instances.h"
#include "instance_config.h"
#include "message_broker.h"
#include "poll_helper.h"
#include "mqtt/mqtt_topic.h"
#include "stats/stats_instance.h"

struct rrr_instance *rrr_instance_find_by_thread (
		struct rrr_instance_collection *instances,
		struct rrr_thread *thread
) {
	RRR_LL_ITERATE_BEGIN(instances,struct rrr_instance);
		if (node->thread == thread) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

int rrr_instance_check_threads_stopped (
		struct rrr_instance_collection *instances
) {
	int ret = 0;
	RRR_LL_ITERATE_BEGIN(instances,struct rrr_instance);
		struct rrr_instance *instance = node;
		if (
				rrr_thread_state_get(instance->thread) == RRR_THREAD_STATE_STOPPED ||
	//				rrr_thread_get_state(instance->thread_data->thread) == RRR_THREAD_STATE_STOPPING ||
				rrr_thread_ghost_check(instance->thread)
		) {
			RRR_DBG_1("Thread instance %s has stopped or is ghost\n", INSTANCE_M_NAME(instance));
			ret = 1;
			// Don't break or goto
		}
	RRR_LL_ITERATE_END();
	return ret;
}

int rrr_instance_count_library_users (
		struct rrr_instance_collection *instances,
		void *dl_ptr
) {
	int users = 0;

	RRR_LL_ITERATE_BEGIN(instances,struct rrr_instance);
		struct rrr_instance_module_data *data = node->module_data;
		if (data->dl_ptr == dl_ptr) {
			users++;
		}
	RRR_LL_ITERATE_END();

	return users;
}

void rrr_instance_unload_all (
		struct rrr_instance_collection *instances
) {
	RRR_LL_ITERATE_BEGIN(instances,struct rrr_instance);
		struct rrr_instance_module_data *data = node->module_data;
		int dl_users = rrr_instance_count_library_users(instances, data->dl_ptr);
		int no_dl_unload = (dl_users > 1 ? 1 : 0);

		if (!no_dl_unload) {
			rrr_module_unload(data->dl_ptr, data->unload);
		}
	RRR_LL_ITERATE_END();
}

static void __rrr_instance_destroy (
		struct rrr_instance *target
) {
	rrr_instance_friend_collection_clear(&target->senders);
	rrr_instance_friend_collection_clear(&target->wait_for);

	RRR_FREE_IF_NOT_NULL(target->topic_filter);
	rrr_mqtt_topic_token_destroy(target->topic_first_token);

	free(target->module_data);
	free(target);
}

static int __rrr_instance_new (
		struct rrr_instance **target
) {
	int ret = 0;

	struct rrr_instance *instance = malloc(sizeof(*instance));

	if (instance == NULL) {
		RRR_MSG_0("Could not allocate memory for instance_metadata\n");
		ret = 1;
		goto out;
	}

	memset (instance, '\0', sizeof(*instance));

	*target = instance;

	out:
	return ret;
}

static struct rrr_instance *__rrr_instance_new_and_save (
		struct rrr_instance_collection *instances,
		struct rrr_instance_module_data *module,
		struct rrr_instance_config_data *config
) {
	RRR_DBG_1 ("Saving dynamic_data instance %s\n", module->instance_name);

	struct rrr_instance *target;
	if (__rrr_instance_new (&target) != 0) {
		RRR_MSG_0("Could not save instance %s\n", module->instance_name);
		return NULL;
	}

	target->config = config;
	target->module_data = module;

	RRR_LL_APPEND(instances, target);

	return target;
}

static struct rrr_instance *__rrr_instance_load_module_new_and_save (
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_data *instance_config,
		const char **library_paths
) {
	struct rrr_instance *ret = NULL;
	char *module_name = NULL;

	RRR_LL_ITERATE_BEGIN(instances,struct rrr_instance);
		struct rrr_instance_module_data *module = node->module_data;
		if (module != NULL && strcmp(module->instance_name, instance_config->name) == 0) {
			RRR_MSG_0("Instance '%s' can't be defined more than once\n", module->instance_name);
			ret = NULL;
			goto out;
		}
	RRR_LL_ITERATE_END();

	if (rrr_instance_config_get_string_noconvert (&module_name, instance_config, "module") != 0) {
		RRR_MSG_0("Could not find module= setting for instance %s\n", instance_config->name);
		ret = NULL;
		goto out;
	}

	RRR_DBG_1("Creating dynamic_data for module '%s' instance '%s'\n", module_name, instance_config->name);

	struct rrr_module_load_data module_init_data;
	if (rrr_module_load(&module_init_data, module_name, library_paths) != 0) {
		RRR_MSG_0 ("Module '%s' could not be loaded (in load_instance_module for instance '%s')\n",
				module_name, instance_config->name);
		ret = NULL;
		goto out;
	}

	struct rrr_instance_module_data *module_data = malloc(sizeof(*module_data));
	memset(module_data, '\0', sizeof(*module_data));

	module_init_data.init(module_data);
	module_data->dl_ptr = module_init_data.dl_ptr;
	module_data->instance_name = instance_config->name;
	module_data->unload = module_init_data.unload;
	module_data->all_instances = instances;

	ret = __rrr_instance_new_and_save(instances, module_data, instance_config);

	out:
	RRR_FREE_IF_NOT_NULL(module_name);

	return ret;
}

struct rrr_instance *rrr_instance_find (
		struct rrr_instance_collection *instances,
		const char *name
) {
	RRR_LL_ITERATE_BEGIN(instances,struct rrr_instance);
		struct rrr_instance_module_data *module = node->module_data;
		if (module != NULL && strcmp(module->instance_name, name) == 0) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

int rrr_instance_load_and_save (
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_data *instance_config,
		const char **library_paths
) {
	struct rrr_instance *instance = __rrr_instance_load_module_new_and_save(instances, instance_config, library_paths);
	if (instance == NULL || instance->module_data == NULL) {
		RRR_MSG_0("Instance '%s' could not be loaded\n", instance_config->name);
		return 1;
	}

	return 0;
}

struct add_instance_data {
	struct rrr_instance_collection *instances;
	struct rrr_instance_friend_collection *collection;
};

static int __rrr_add_instance_callback(const char *value, void *_data) {
	struct add_instance_data *data = _data;

	int ret = 0;

	struct rrr_instance *instance = rrr_instance_find(data->instances, value);

	if (instance == NULL) {
		RRR_MSG_0("Could not find instance '%s'\n", value);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Added %s\n", INSTANCE_M_NAME(instance));

	rrr_instance_friend_collection_append(data->collection, instance);

	out:
	return ret;
}

static int __rrr_instance_parse_topic_filter (
		struct rrr_instance *data
) {
	int ret = 0;

	struct rrr_instance_config_data *config = data->config;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("topic_filter", topic_filter);

	if (data->topic_filter != NULL) {
		if (rrr_mqtt_topic_filter_validate_name(data->topic_filter) != 0) {
			RRR_MSG_0("Invalid topic_filter setting found for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_mqtt_topic_tokenize(&data->topic_first_token, data->topic_filter) != 0) {
			RRR_MSG_0("Error while tokenizing topic filter in __rrr_instance_parse_topic_filter\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_instance_add_wait_for_instances (
		struct rrr_instance_collection *instances,
		struct rrr_instance *instance
) {
	int ret = 0;

	RRR_DBG_1("Adding wait-for instances for instance '%s' module '%s'\n",
			instance->module_data->instance_name,
			instance->module_data->module_name
	);

	struct add_instance_data add_data = {0};

	add_data.collection = &instance->wait_for;
	add_data.instances = instances;

	struct rrr_instance_config_data *instance_config = instance->config;

	if ((ret = rrr_settings_traverse_split_commas_silent_fail (
			instance_config->settings, "wait_for",
			&__rrr_add_instance_callback, &add_data
	))!= 0) {
		RRR_MSG_0("Error while adding wait for for instance %s\n", instance->module_data->instance_name);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_instance_add_senders (
		struct rrr_instance_collection *instances,
		struct rrr_instance *instance
) {
	int ret = 0;

	RRR_DBG_1("Adding senders for instance '%s' module '%s'\n",
			INSTANCE_M_NAME(instance),
			INSTANCE_M_MODULE_NAME(instance)
	);

	struct rrr_instance_config_data *instance_config = instance->config;

	struct add_instance_data add_data = {0};
	add_data.instances = instances;
	add_data.collection = &instance->senders;

	if ((ret = rrr_settings_traverse_split_commas_silent_fail (
			instance_config->settings, "senders",
			&__rrr_add_instance_callback, &add_data
	))!= 0) {
		RRR_MSG_0("Error while adding senders for instance %s\n",
				INSTANCE_M_NAME(instance)
		);
		goto out;
	}

	if (INSTANCE_M_MODULE_TYPE(instance) == RRR_MODULE_TYPE_PROCESSOR ||
		INSTANCE_M_MODULE_TYPE(instance) == RRR_MODULE_TYPE_FLEXIBLE ||
		INSTANCE_M_MODULE_TYPE(instance) == RRR_MODULE_TYPE_DEADEND
	) {
		if (rrr_instance_friend_collection_check_empty(&instance->senders)) {
			if (INSTANCE_M_MODULE_TYPE(instance) == RRR_MODULE_TYPE_FLEXIBLE) {
				RRR_DBG_1("Module is flexible without senders specified\n");
				ret = 0;
				goto out;
			}
			RRR_MSG_0("Sender module must be specified for processor module %s instance %s\n",
					INSTANCE_M_MODULE_NAME(instance),
					INSTANCE_M_NAME(instance)
			);
			ret = 1;
			goto out;
		}

		RRR_LL_ITERATE_BEGIN(&instance->senders, struct rrr_instance_friend);
			struct rrr_instance *sender = node->instance;

			RRR_DBG_1("Checking sender instance '%s' module '%s'\n",
					INSTANCE_M_NAME(sender),
					INSTANCE_M_MODULE_NAME(sender)
			);

			if (INSTANCE_M_MODULE_TYPE(sender) == RRR_MODULE_TYPE_DEADEND) {
				RRR_MSG_0("Instance %s cannot use instance %s of type %s as a sender, this is a dead end module with no output\n",
						INSTANCE_M_NAME(instance),
						INSTANCE_M_NAME(sender),
						INSTANCE_M_MODULE_NAME(sender)
				);
				ret = 1;
				goto out;
			}

			if (sender == instance) {
				RRR_MSG_0("Instance %s set with itself as sender\n",
						INSTANCE_M_NAME(instance)
				);
				ret = 1;
				goto out;
			}
		RRR_LL_ITERATE_END();
	}
	else if (INSTANCE_M_MODULE_TYPE(instance) == RRR_MODULE_TYPE_SOURCE ||
			INSTANCE_M_MODULE_TYPE(instance) == RRR_MODULE_TYPE_NETWORK
	) {
		if (!rrr_instance_friend_collection_check_empty(&instance->senders)) {
			RRR_MSG_0("Sender module cannot be specified for instance '%s' using source module '%s'\n",
					INSTANCE_M_NAME(instance),
					INSTANCE_M_MODULE_NAME(instance)
			);
			ret = 1;
			goto out;
		}
	}
	else {
		RRR_MSG_0 ("Unknown module type for module %s: %i\n",
				INSTANCE_M_MODULE_NAME(instance),
				INSTANCE_M_MODULE_TYPE(instance)
		);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Added %d collection\n", rrr_instance_friend_collection_count(&instance->senders));

	out:
	return ret;
}

void rrr_instance_collection_clear (
		struct rrr_instance_collection *target
) {
	RRR_LL_DESTROY(target, struct rrr_instance, __rrr_instance_destroy(node));
}

unsigned int rrr_instance_collection_count (
		struct rrr_instance_collection *collection
) {
	if (RRR_LL_COUNT(collection) < 0) {
		RRR_BUG("BUG: Count was <0 in rrr_instance_metadata_collection_count\n");
	}
	return (RRR_LL_COUNT(collection));
}

void rrr_instance_runtime_data_destroy_hard (
		struct rrr_instance_runtime_data *data
) {
	rrr_message_broker_costumer_unregister(data->init_data.message_broker, data->message_broker_handle);
	free(data);
}

static int __rrr_instace_runtime_data_destroy_callback (
		struct rrr_thread *thread,
		void *arg
) {
	(void)(arg);

	struct rrr_instance_runtime_data *data = thread->private_data;
	rrr_instance_runtime_data_destroy_hard(data);
	thread->private_data = NULL;
	return 0;
}

static void __rrr_instace_runtime_data_destroy_intermediate (
		void *arg
) {
	struct rrr_instance_runtime_data *data = arg;
	RRR_DBG_8("Thread %p intermediate destroy runtime data\n", data->thread);
	rrr_thread_with_lock_do(INSTANCE_D_THREAD(data), __rrr_instace_runtime_data_destroy_callback, NULL);
}

struct rrr_instance_runtime_data *rrr_instance_runtime_data_new (
		struct rrr_instance_runtime_init_data *init_data
) {
	RRR_DBG_1 ("Init thread %s\n", init_data->module->instance_name);

	struct rrr_instance_runtime_data *data = malloc(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_init_thread\n");
		return NULL;
	}

	memset(data, '\0', sizeof(*data));
	data->init_data = *init_data;

	if (rrr_message_broker_costumer_register (
			&data->message_broker_handle,
			init_data->message_broker,
			init_data->module->instance_name
	) != 0) {
		RRR_MSG_0("Could not register with message broker in rrr_instance_new_thread\n");
		goto out_free;
	}

	goto out;
	out_free:
		free(data);
		data = NULL;
	out:
		return data;
}

static void __rrr_instance_thread_intermediate_cleanup (
		void *arg
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	pthread_mutex_lock(&thread->mutex);

	RRR_DBG_8("Thread %p intermediate cleanup cmodule is %p\n", thread, thread_data->cmodule);

	if (thread_data->cmodule == NULL) {
		goto out;
	}

	rrr_cmodule_destroy(thread_data->cmodule);

	out:
	pthread_mutex_unlock(&thread->mutex);
}

static void __rrr_instance_thread_poll_collection_clear_void (
		void *arg
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	RRR_DBG_8("Thread %p intermediate poll collection clear\n", thread);

	pthread_mutex_lock(&thread->mutex);
	rrr_poll_collection_clear(&thread_data->poll);
	pthread_mutex_unlock(&thread->mutex);
}

static void __rrr_instance_thread_stats_instance_cleanup (
		void *arg
) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	pthread_mutex_lock(&thread->mutex);

	RRR_DBG_8("Thread %p intermediate cleanup stats is %p\n", thread, thread_data->stats);

	if (thread_data->stats == NULL) {
		goto out;
	}

	rrr_stats_instance_destroy(thread_data->stats);
	thread_data->stats = NULL;
	out:
	pthread_mutex_unlock(&thread->mutex);
}

#include "fork.h"

void *rrr_instance_thread_entry_intermediate (
		struct rrr_thread *thread
) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	thread_data->thread = thread;

	pthread_cleanup_push(__rrr_instace_runtime_data_destroy_intermediate, thread->private_data);
	pthread_cleanup_push(__rrr_instance_thread_intermediate_cleanup, thread);
	pthread_cleanup_push(__rrr_instance_thread_poll_collection_clear_void, thread);
	pthread_cleanup_push(__rrr_instance_thread_stats_instance_cleanup, thread);

	if ((rrr_cmodule_new (
			&thread_data->cmodule,
			INSTANCE_D_NAME(thread_data),
			INSTANCE_D_FORK(thread_data)
	)) != 0) {
		RRR_MSG_0("Could not initialize cmodule in __rrr_instance_thread_entry_intermediate\n");
		goto out;
	}

	RRR_DBG_8("Thread %p intermediate cmodule is %p\n", thread, thread_data->cmodule);

	if (rrr_stats_instance_new (
		&thread_data->stats,
		INSTANCE_D_STATS_ENGINE(thread_data),
		INSTANCE_D_NAME(thread_data)
	) != 0) {
		RRR_MSG_0("Could not initialize stats engine for instance %s in __rrr_instance_thread_entry_intermediate\n",
				INSTANCE_D_NAME(thread_data)
		);
		goto out;
	}

	RRR_DBG_8("Thread %p intermediate stats is %p\n", thread, thread_data->stats);

	if (rrr_stats_instance_post_default_stickies(thread_data->stats) != 0) {
		RRR_MSG_0("Error while posting default sticky statistics instance %s in __rrr_instance_thread_entry_intermediate\n",
				INSTANCE_D_NAME(thread_data)
		);
		goto out;
	}

	struct rrr_instance *faulty_instance = NULL;
	if (rrr_poll_add_from_thread_senders(&faulty_instance, &thread_data->poll, thread_data) != 0) {
		RRR_MSG_0("Failed to add senders to poll collection of instance %s. Faulty sender was %s.\n",
				INSTANCE_D_NAME(thread_data), INSTANCE_M_NAME(faulty_instance));
		goto out;
	}

	// Ignore return value
	thread_data->init_data.module->operations.thread_entry(thread);

	// Keep out label ABOVE cleanup_pops
	out:

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	// Don't put code here, modules usually call pthread_exit which means we
	// only do the cleanup functions

	return NULL;
}

int rrr_instance_create_from_config (
		struct rrr_instance_collection *instances,
		struct rrr_config *config,
		const char **library_paths
) {
	int ret = 0;
	for (int i = 0; i < config->module_count; i++) {
		ret = rrr_instance_load_and_save(instances, config->configs[i], library_paths);
		if (ret != 0) {
			RRR_MSG_0("Loading of instance failed for %s. Library paths used:\n",
					config->configs[i]->name);
			for (int j = 0; *library_paths[j] != '\0'; j++) {
				RRR_MSG_0("-> %s\n", library_paths[j]);
			}
			goto out;
		}
	}

	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;
		ret = __rrr_instance_add_senders(instances, instance);
		if (ret != 0) {
			RRR_MSG_0("Adding senders failed for instance %s\n",
					INSTANCE_M_NAME(instance));
			goto out;
		}
		ret = __rrr_instance_add_wait_for_instances(instances, instance);
		if (ret != 0) {
			RRR_MSG_0("Adding wait for instances failed for instance %s\n",
					INSTANCE_M_NAME(instance));
			goto out;
		}
		ret = __rrr_instance_parse_topic_filter(instance);
		if (ret != 0) {
			RRR_MSG_0("Parsing topic filter failed for instance %s\n",
					INSTANCE_M_NAME(instance));
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

struct rrr_instance_count_receivers_of_self_callback_data {
	struct rrr_instance *self;
	int count;
};

static int __rrr_instance_count_receivers_of_self_callback (
		struct rrr_instance *instance,
		void *arg
) {
	struct rrr_instance_count_receivers_of_self_callback_data *callback_data = arg;
	if (instance == callback_data->self) {
		callback_data->count++;
	}
	return 0;
}

int rrr_instance_count_receivers_of_self (
		struct rrr_instance *self
) {
	struct rrr_instance_collection *instances = self->module_data->all_instances;

	struct rrr_instance_count_receivers_of_self_callback_data callback_data = {
			self,
			0
	};

	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;
		if (instance != self) {
			rrr_instance_friend_collection_iterate (
					&instance->senders,
					__rrr_instance_count_receivers_of_self_callback,
					&callback_data
			);
		}
	RRR_LL_ITERATE_END();

	return callback_data.count;
}

int rrr_instance_default_set_output_buffer_ratelimit_when_needed (
		int *delivery_entry_count,
		int *delivery_ratelimit_active,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	if (rrr_message_broker_get_entry_count_and_ratelimit (
			delivery_entry_count,
			delivery_ratelimit_active,
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data)
	) != 0) {
		RRR_MSG_0("Error while getting output buffer size in %s instance %s\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	if (*delivery_entry_count > 10000 && *delivery_ratelimit_active == 0) {
		RRR_DBG_1("Enabling ratelimit on buffer in %s instance %s due to slow reader\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data));
		rrr_message_broker_set_ratelimit(INSTANCE_D_BROKER(thread_data), INSTANCE_D_HANDLE(thread_data), 1);
	}
	else if (*delivery_entry_count < 10 && *delivery_ratelimit_active == 1) {
		RRR_DBG_1("Disabling ratelimit on buffer in %s instance %s due to low buffer level\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data));
		rrr_message_broker_set_ratelimit(INSTANCE_D_BROKER(thread_data), INSTANCE_D_HANDLE(thread_data), 0);
	}

	out:
	return ret;
}
