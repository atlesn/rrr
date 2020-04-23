/*
#include <instance_collection.h>

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

#include <stdlib.h>

#include "../global.h"
#include "common.h"
#include "modules.h"
#include "threads.h"
#include "instances.h"
#include "instance_config.h"

struct instance_metadata *rrr_instance_find_by_thread (
		struct instance_metadata_collection *collection,
		struct rrr_thread *thread
) {
	RRR_INSTANCE_LOOP(instance, collection) {
		if (instance->thread_data->thread == thread) {
			return instance;
		}
	}
	return NULL;
}

int rrr_instance_check_threads_stopped(struct instance_metadata_collection *instances) {
	int ret = 0;
	RRR_INSTANCE_LOOP(instance, instances) {
		if (
				rrr_thread_get_state(instance->thread_data->thread) == RRR_THREAD_STATE_STOPPED ||
//				rrr_thread_get_state(instance->thread_data->thread) == RRR_THREAD_STATE_STOPPING ||
				rrr_thread_is_ghost(instance->thread_data->thread)
		) {
			RRR_DBG_1("Thread instance %s has stopped or is ghost\n", instance->dynamic_data->instance_name);
			ret = 1;
		}
	}
	return ret;
}

void rrr_instance_free_all_thread_data(struct instance_metadata_collection *instances) {
	RRR_INSTANCE_LOOP(instance, instances) {
		rrr_instance_free_thread(instance->thread_data);
		instance->thread_data = NULL;
	}
}

int rrr_instance_count_library_users (struct instance_metadata_collection *instances, void *dl_ptr) {
	int users = 0;
	RRR_INSTANCE_LOOP(instance, instances) {
		struct rrr_instance_dynamic_data *data = instance->dynamic_data;
		if (data->dl_ptr == dl_ptr) {
			users++;
		}
	}
	return users;
}

void rrr_instance_unload_all(struct instance_metadata_collection *instances) {
	RRR_INSTANCE_LOOP(instance, instances) {
		struct rrr_instance_dynamic_data *data = instance->dynamic_data;
		int dl_users = rrr_instance_count_library_users(instances, data->dl_ptr);
		int no_dl_unload = (dl_users > 1 ? 1 : 0);

		if (!no_dl_unload) {
			rrr_module_unload(data->dl_ptr, data->unload);
		}
	}
}

static void __rrr_instance_metadata_destroy (
		struct instance_metadata_collection *instances,
		struct instance_metadata *target
) {
	rrr_instance_free_thread(target->thread_data);
	rrr_instance_collection_clear(&target->senders);
	rrr_instance_collection_clear(&target->wait_for);

	if (instances->signal_functions != NULL && target->signal_handler != NULL) {
		instances->signal_functions->remove_handler(target->signal_handler);
	}

	free(target->dynamic_data);
	free(target);
}

static int __rrr_instance_metadata_new (
		struct instance_metadata_collection *instances,
		struct instance_metadata **target,
		struct rrr_instance_dynamic_data *data
) {
	int ret = 0;

	struct instance_metadata *meta = malloc(sizeof(*meta));

	if (meta == NULL) {
		RRR_MSG_ERR("Could not allocate memory for instance_metadata\n");
		ret = 1;
		goto out;
	}

	memset (meta, '\0', sizeof(*meta));

	meta->dynamic_data = data;

	if (instances->signal_functions != NULL && data->signal_handler != NULL) {
		meta->signal_handler = instances->signal_functions->push_handler(data->signal_handler, meta);
	}

	*target = meta;

	out:
	return ret;
}

static struct instance_metadata *__rrr_instance_save (
		struct instance_metadata_collection *instances,
		struct rrr_instance_dynamic_data *module,
		struct rrr_instance_config *config
) {
	RRR_DBG_1 ("Saving dynamic_data instance %s\n", module->instance_name);

	struct instance_metadata *target;
	if (__rrr_instance_metadata_new (instances, &target, module) != 0) {
		RRR_MSG_ERR("Could not save instance %s\n", module->instance_name);
		return NULL;
	}

	target->config = config;
	target->dynamic_data = module;

	target->next = instances->first_entry;
	instances->first_entry = target;

	return target;
}

static struct instance_metadata *__rrr_instance_load_module_and_save (
		struct instance_metadata_collection *instances,
		struct rrr_instance_config *instance_config,
		const char **library_paths
) {
	struct instance_metadata *ret = NULL;
	char *module_name = NULL;

	RRR_INSTANCE_LOOP(instance, instances) {
		struct rrr_instance_dynamic_data *module = instance->dynamic_data;
		if (module != NULL && strcmp(module->instance_name, instance_config->name) == 0) {
			RRR_MSG_ERR("Instance '%s' can't be defined more than once\n", module->instance_name);
			ret = NULL;
			goto out;
		}
	}

	if (rrr_instance_config_get_string_noconvert (&module_name, instance_config, "module") != 0) {
		RRR_MSG_ERR("Could not find module= setting for instance %s\n", instance_config->name);
		ret = NULL;
		goto out;
	}

	RRR_DBG_1("Creating dynamic_data for module '%s' instance '%s'\n", module_name, instance_config->name);

	struct rrr_module_load_data start_data;
	if (rrr_module_load(&start_data, module_name, library_paths) != 0) {
		RRR_MSG_ERR ("Module %s could not be loaded (in load_instance_module for instance %s)\n",
				module_name, instance_config->name);
		ret = NULL;
		goto out;
	}

	struct rrr_instance_dynamic_data *dynamic_data = malloc(sizeof(*dynamic_data));
	memset(dynamic_data, '\0', sizeof(*dynamic_data));

	start_data.init(dynamic_data);
	dynamic_data->dl_ptr = start_data.dl_ptr;
	dynamic_data->instance_name = instance_config->name;
	dynamic_data->unload = start_data.unload;
	dynamic_data->all_instances = instances;

	ret = __rrr_instance_save(instances, dynamic_data, instance_config);

	out:
	if (module_name != NULL) {
		free(module_name);
	}

	return ret;
}

struct instance_metadata *rrr_instance_find (
		struct instance_metadata_collection *instances,
		const char *name
) {
	RRR_INSTANCE_LOOP(instance, instances) {
		struct rrr_instance_dynamic_data *module = instance->dynamic_data;
		if (module != NULL && strcmp(module->instance_name, name) == 0) {
			return instance;
		}
	}
	return NULL;
}

int rrr_instance_load_and_save (
		struct instance_metadata_collection *instances,
		struct rrr_instance_config *instance_config,
		const char **library_paths
) {
	struct instance_metadata *module = __rrr_instance_load_module_and_save(instances, instance_config, library_paths);
	if (module == NULL || module->dynamic_data == NULL) {
		RRR_MSG_ERR("Instance '%s' could not be loaded\n", instance_config->name);
		return 1;
	}

	if ((module->dynamic_data->type == RRR_MODULE_TYPE_DEADEND  || module->dynamic_data->type == RRR_MODULE_TYPE_NETWORK) && (
			module->dynamic_data->operations.poll != NULL ||
			module->dynamic_data->operations.poll_delete != NULL ||
			module->dynamic_data->operations.poll_delete_ip != NULL
	)) {
		RRR_BUG("Poll functions specified for module %s which is of deadend or network type\n",
				module->dynamic_data->instance_name);
	}

	return 0;
}

struct add_instance_data {
	struct instance_metadata_collection *instances;
	struct rrr_instance_collection *collection;
};

static int __rrr_add_instance_callback(const char *value, void *_data) {
	struct add_instance_data *data = _data;

	int ret = 0;

	struct instance_metadata *instance = rrr_instance_find(data->instances, value);

	if (instance == NULL) {
		RRR_MSG_ERR("Could not find instance '%s'\n", value);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Added %s\n", INSTANCE_M_NAME(instance));

	rrr_instance_collection_append(data->collection, instance);

	out:
	return ret;
}

int rrr_instance_add_wait_for_instances (
		struct instance_metadata_collection *instances,
		struct instance_metadata *instance
) {
	int ret = 0;

	RRR_DBG_1("Adding wait-for instances for instance '%s' module '%s'\n",
			instance->dynamic_data->instance_name,
			instance->dynamic_data->module_name
	);

	struct add_instance_data add_data = {0};

	add_data.collection = &instance->wait_for;
	add_data.instances = instances;

	struct rrr_instance_config *instance_config = instance->config;

	if ((ret = rrr_settings_traverse_split_commas_silent_fail (
			instance_config->settings, "wait_for",
			&__rrr_add_instance_callback, &add_data
	))!= 0) {
		RRR_MSG_ERR("Error while adding wait for for instance %s\n", instance->dynamic_data->instance_name);
		goto out;
	}

	out:
	return ret;
}

int rrr_instance_add_senders (
		struct instance_metadata_collection *instances,
		struct instance_metadata *instance
) {
	int ret = 0;

	RRR_DBG_1("Adding senders for instance '%s' module '%s'\n",
			instance->dynamic_data->instance_name,
			instance->dynamic_data->module_name
	);

	struct rrr_instance_config *instance_config = instance->config;

	struct add_instance_data add_data = {0};
	add_data.instances = instances;
	add_data.collection = &instance->senders;

	if ((ret = rrr_settings_traverse_split_commas_silent_fail (
			instance_config->settings, "senders",
			&__rrr_add_instance_callback, &add_data
	))!= 0) {
		RRR_MSG_ERR("Error while adding senders for instance %s\n", instance->dynamic_data->instance_name);
		goto out;
	}

	if (instance->dynamic_data->type == RRR_MODULE_TYPE_PROCESSOR ||
		instance->dynamic_data->type == RRR_MODULE_TYPE_FLEXIBLE ||
		instance->dynamic_data->type == RRR_MODULE_TYPE_DEADEND
	) {
		if (rrr_instance_collection_check_empty(&instance->senders)) {
			if (instance->dynamic_data->type == RRR_MODULE_TYPE_FLEXIBLE) {
				RRR_DBG_1("Module is flexible without senders specified\n");
				ret = 0;
				goto out;
			}
			RRR_MSG_ERR("Sender module must be specified for processor module %s instance %s\n",
					instance->dynamic_data->module_name, instance->dynamic_data->instance_name);
			ret = 1;
			goto out;
		}

		RRR_LL_ITERATE_BEGIN(&instance->senders, struct rrr_instance_collection_entry);
			struct instance_metadata *sender = node->instance;

			RRR_DBG_1("Checking sender instance '%s' module '%s'\n",
					sender->dynamic_data->instance_name,
					sender->dynamic_data->module_name
			);

			if (sender->dynamic_data->type == RRR_MODULE_TYPE_DEADEND) {
				RRR_MSG_ERR("Instance %s cannot use %s as a sender, this is a dead end module with no output\n",
						instance->dynamic_data->instance_name, sender->dynamic_data->instance_name);
				ret = 1;
				goto out;
			}

			if (sender == instance) {
				RRR_MSG_ERR("Instance %s set with itself as sender\n",
						instance->dynamic_data->instance_name);
				ret = 1;
				goto out;
			}
		RRR_LL_ITERATE_END();
	}
	else if (instance->dynamic_data->type == RRR_MODULE_TYPE_SOURCE ||
			instance->dynamic_data->type == RRR_MODULE_TYPE_NETWORK
	) {
		if (!rrr_instance_collection_check_empty(&instance->senders)) {
			RRR_MSG_ERR("Sender module cannot be specified for instance '%s' using module '%s'\n",
					instance->dynamic_data->instance_name, instance->dynamic_data->module_name);
			ret = 1;
			goto out;
		}
	}
	else {
		RRR_MSG_ERR ("Unknown module type for %s: %i\n",
				instance->dynamic_data->module_name, instance->dynamic_data->type
		);
		ret = 1;
		goto out;
	}

	RRR_DBG_1("Added %d collection\n", rrr_instance_collection_count(&instance->senders));

	out:
	return ret;
}

void rrr_instance_metadata_collection_destroy (struct instance_metadata_collection *target) {
	struct instance_metadata *meta = target->first_entry;

	while (meta != NULL) {
		struct instance_metadata *next = meta->next;

		__rrr_instance_metadata_destroy(target, meta);

		meta = next;
	}

	free(target);
}

int rrr_instance_metadata_collection_new (
		struct instance_metadata_collection **target,
		struct rrr_signal_functions *signal_functions
) {
	int ret = 0;

	*target = malloc(sizeof(**target));
	memset(*target, '\0', sizeof(**target));

	if (*target == NULL) {
		RRR_MSG_ERR("Could not allocate memory for instance_metadata_collection\n");
		ret = 1;
		goto out;
	}

	(*target)->signal_functions = signal_functions;

	out:
	return ret;
}

unsigned int rrr_instance_metadata_collection_count (struct instance_metadata_collection *collection) {
	unsigned int result = 0;

	RRR_INSTANCE_LOOP(instance, collection) {
		(void)(instance);
		result++;
	}

	return result;
}

void rrr_instance_free_thread(struct rrr_instance_thread_data *data) {
	if (data == NULL) {
		return;
	}

	if (data->used_by_ghost) {
		return;
	}

	free(data);
}

void rrr_instance_free_thread_by_ghost (void *private_data) {
	struct rrr_instance_thread_data *data = private_data;
	if (private_data == NULL) {
		return;
	}
	free(data);
}

struct rrr_instance_thread_data *rrr_instance_init_thread(struct instance_thread_init_data *init_data) {
	RRR_DBG_1 ("Init thread %s\n", init_data->module->instance_name);

	struct rrr_instance_thread_data *data = malloc(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_init_thread\n");
		return NULL;
	}

	memset(data, '\0', sizeof(*data));
	data->init_data = *init_data;

	return data;
}

int rrr_instance_preload_thread(struct rrr_thread_collection *collection, struct rrr_instance_thread_data *data) {
	struct rrr_instance_dynamic_data *module = data->init_data.module;

	RRR_DBG_1 ("Preloading thread %s\n", module->instance_name);
	if (data->thread != NULL) {
		RRR_MSG_ERR("BUG: tried to double start thread in rrr_start_thread\n");
		exit(EXIT_FAILURE);
	}
	data->thread = rrr_thread_preload_and_register (
			collection,
			module->operations.thread_entry,
			module->operations.preload,
			module->operations.poststop,
			module->operations.cancel_function,
			rrr_instance_free_thread_by_ghost,
			module->start_priority,
			data, module->instance_name
	);

	if (data->thread == NULL) {
		RRR_MSG_ERR ("Error while preloading thread for instance %s\n", module->instance_name);
		free(data);
		return 1;
	}

	return 0;
}

int rrr_instance_start_thread (struct rrr_instance_thread_data *data) {
	struct rrr_instance_dynamic_data *module = data->init_data.module;

	RRR_DBG_1 ("Starting thread %s\n", module->instance_name);
	if (rrr_thread_start(data->thread) != 0) {
		RRR_MSG_ERR ("Error while starting thread for instance %s\n", module->instance_name);
		return 1;
	}

	return 0;
}

int rrr_instance_process_from_config (
		struct instance_metadata_collection *instances,
		struct rrr_config *config,
		const char **library_paths
) {
	int ret = 0;
	for (int i = 0; i < config->module_count; i++) {
		ret = rrr_instance_load_and_save(instances, config->configs[i], library_paths);
		if (ret != 0) {
			RRR_MSG_ERR("Loading of instance failed for %s. Library paths used:\n",
					config->configs[i]->name);
			for (int j = 0; *library_paths[j] != '\0'; j++) {
				RRR_MSG_ERR("-> %s\n", library_paths[j]);
			}
			goto out;
		}
	}

	RRR_INSTANCE_LOOP(instance, instances)
	{
		ret = rrr_instance_add_senders(instances, instance);
		if (ret != 0) {
			RRR_MSG_ERR("Adding senders failed for %s\n",
					instance->dynamic_data->instance_name);
			goto out;
		}
		ret = rrr_instance_add_wait_for_instances(instances, instance);
		if (ret != 0) {
			RRR_MSG_ERR("Adding wait for instances failed for %s\n",
					instance->dynamic_data->instance_name);
			goto out;
		}
	}

	out:
	return ret;
}
