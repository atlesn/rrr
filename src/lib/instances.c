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

#include <stdlib.h>

#include "../global.h"
#include "modules.h"
#include "threads.h"
#include "instances.h"
#include "instance_config.h"
#include "senders.h"

int instance_check_threads_stopped(struct instance_metadata_collection *instances) {
	int ret = 0;
	RRR_INSTANCE_LOOP(instance, instances) {
		if (
				thread_get_state(instance->thread_data->thread) == VL_THREAD_STATE_STOPPED ||
				thread_get_state(instance->thread_data->thread) == VL_THREAD_STATE_STOPPING ||
				thread_is_ghost(instance->thread_data->thread)
		) {
			VL_DEBUG_MSG_1("Thread instance %s has stopped or is ghost\n", instance->dynamic_data->instance_name);
			ret = 1;
		}
	}
	return ret;
}

void instance_free_all_thread_data(struct instance_metadata_collection *instances) {
	RRR_INSTANCE_LOOP(instance, instances) {
		instance_free_thread(instance->thread_data);
		instance->thread_data = NULL;
	}
}

int instance_count_library_users (struct instance_metadata_collection *instances, void *dl_ptr) {
	int users = 0;
	RRR_INSTANCE_LOOP(instance, instances) {
		struct instance_dynamic_data *data = instance->dynamic_data;
		if (data->dl_ptr == dl_ptr) {
			users++;
		}
	}
	return users;
}

void instance_unload_all(struct instance_metadata_collection *instances) {
	RRR_INSTANCE_LOOP(instance, instances) {
		struct instance_dynamic_data *data = instance->dynamic_data;
		int dl_users = instance_count_library_users(instances, data->dl_ptr);
		int no_dl_unload = (dl_users > 1 ? 1 : 0);

		if (!no_dl_unload) {
			module_unload(data->dl_ptr, data->unload);
		}
	}
}

void __instance_metadata_destroy (struct instance_metadata *target) {
	instance_free_thread(target->thread_data);
	senders_clear(&target->senders);
	free(target->dynamic_data);
	free(target);
}

int __instance_metadata_new (struct instance_metadata **target, struct instance_dynamic_data *data) {
	int ret = 0;

	struct instance_metadata *meta = malloc(sizeof(*meta));

	if (meta == NULL) {
		VL_MSG_ERR("Could not allocate memory for instance_metadata\n");
		ret = 1;
		goto out;
	}

	memset (meta, '\0', sizeof(*meta));

	meta->dynamic_data = data;
	senders_init(&meta->senders);

	*target = meta;

	out:
	return ret;
}

struct instance_metadata *__instance_save (
		struct instance_metadata_collection *instances,
		struct instance_dynamic_data *module,
		struct rrr_instance_config *config
) {
	VL_DEBUG_MSG_1 ("Saving dynamic_data instance %s\n", module->instance_name);

	struct instance_metadata *target;
	if (__instance_metadata_new (&target, module) != 0) {
		VL_MSG_ERR("Could not save instance %s\n", module->instance_name);
		return NULL;
	}

	target->config = config;
	target->dynamic_data = module;

	target->next = instances->first_entry;
	instances->first_entry = target;

	return target;
}

struct instance_metadata *__instance_load_module_and_save (
		struct instance_metadata_collection *instances,
		struct rrr_instance_config *instance_config,
		const char **library_paths
) {
	struct instance_metadata *ret = NULL;

	RRR_INSTANCE_LOOP(instance, instances) {
		struct instance_dynamic_data *module = instance->dynamic_data;
		if (module != NULL && strcmp(module->instance_name, instance_config->name) == 0) {
			VL_MSG_ERR("Instance '%s' can't be defined more than once\n", module->instance_name);
			ret = NULL;
			goto out;
		}
	}

	char *module_name = NULL;
	if (rrr_instance_config_get_string_noconvert (&module_name, instance_config, "module") != 0) {
		VL_MSG_ERR("Could not find module= setting for instance %s\n", instance_config->name);
		ret = NULL;
		goto out;
	}

	VL_DEBUG_MSG_1("Creating dynamic_data for module '%s' instance '%s'\n", module_name, instance_config->name);

	struct module_load_data start_data;
	if (module_load(&start_data, module_name, library_paths) != 0) {
		VL_MSG_ERR ("Module %s could not be loaded (in load_instance_module for instance %s)\n",
				module_name, instance_config->name);
		ret = NULL;
		goto out;
	}

	struct instance_dynamic_data *dynamic_data = malloc(sizeof(*dynamic_data));
	memset(dynamic_data, '\0', sizeof(*dynamic_data));

	start_data.init(dynamic_data);
	dynamic_data->dl_ptr = start_data.dl_ptr;
	dynamic_data->instance_name = instance_config->name;
	dynamic_data->unload = start_data.unload;
	dynamic_data->all_instances = instances;

	ret = __instance_save(instances, dynamic_data, instance_config);

	out:
	if (module_name != NULL) {
		free(module_name);
	}

	return ret;
}

struct instance_metadata *instance_find (
		struct instance_metadata_collection *instances,
		const char *name
) {
	RRR_INSTANCE_LOOP(instance, instances) {
		struct instance_dynamic_data *module = instance->dynamic_data;
		if (module != NULL && strcmp(module->instance_name, name) == 0) {
			return instance;
		}
	}
	return NULL;
}

int instance_load_and_save (
		struct instance_metadata_collection *instances,
		struct rrr_instance_config *instance_config,
		const char **library_paths
) {
	struct instance_metadata *module = __instance_load_module_and_save(instances, instance_config, library_paths);
	if (module == NULL || module->dynamic_data == NULL) {
		VL_MSG_ERR("Instance '%s' could not be loaded\n", instance_config->name);
		return 1;
	}

	return 0;
}

struct add_sender_data {
	struct instance_metadata_collection *instances;
	struct instance_sender_collection *senders;
};

int __add_sender_callback(const char *value, void *_data) {
	struct add_sender_data *data = _data;

	int ret = 0;

	struct instance_metadata *sender = instance_find(data->instances, value);

	if (sender == NULL) {
		VL_MSG_ERR("Could not find sender instance '%s'\n", value);
		ret = 1;
		goto out;
	}

	senders_add_sender(data->senders, sender);

	out:
	return ret;
}

int instance_add_senders (
		struct instance_metadata_collection *instances,
		struct instance_metadata *instance
) {
	int ret = 0;

	VL_DEBUG_MSG_1("Adding senders for instance '%s' module '%s'\n",
			instance->dynamic_data->instance_name,
			instance->dynamic_data->module_name
	);

	struct rrr_instance_config *instance_config = instance->config;

	struct add_sender_data sender_data;
	sender_data.instances = instances;
	sender_data.senders = &instance->senders;

	ret = rrr_settings_traverse_split_commas_silent_fail (
			instance_config->settings, "senders",
			&__add_sender_callback, &sender_data
	);

	if (instance->dynamic_data->type == VL_MODULE_TYPE_PROCESSOR) {
		if (senders_check_empty(&instance->senders)) {
			VL_MSG_ERR("Sender module must be specified for processor module %s instance %s\n",
					instance->dynamic_data->module_name, instance->dynamic_data->instance_name);
			ret = 1;
			goto out;
		}

		RRR_SENDER_LOOP(sender_entry,&instance->senders) {
			struct instance_metadata *sender = sender_entry->sender;

			VL_DEBUG_MSG_1("Checking sender instance '%s' module '%s'\n",
					sender->dynamic_data->instance_name,
					sender->dynamic_data->module_name
			);

			if (sender == instance) {
				VL_MSG_ERR("Instance %s set with itself as sender\n",
						instance->dynamic_data->instance_name);
				ret = 1;
				goto out;
			}
		}
	}
	else if (instance->dynamic_data->type == VL_MODULE_TYPE_SOURCE) {
		if (!senders_check_empty(&instance->senders)) {
			VL_MSG_ERR("Sender module cannot be specified for instance '%s' using module '%s'\n",
					instance->dynamic_data->instance_name, instance->dynamic_data->module_name);
			ret = 1;
			goto out;
		}
	}
	else {
		VL_MSG_ERR ("Unknown module type for %s: %i\n",
				instance->dynamic_data->module_name, instance->dynamic_data->type
		);
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_1("Added %d senders\n", senders_count(&instance->senders));

	out:
	return ret;
}

void instance_metadata_collection_destroy (struct instance_metadata_collection *target) {
	struct instance_metadata *meta = target->first_entry;

	while (meta != NULL) {
		struct instance_metadata *next = meta->next;

		__instance_metadata_destroy(meta);

		meta = next;
	}

	free(target);
}

int instance_metadata_collection_new (struct instance_metadata_collection **target) {
	int ret = 0;

	*target = malloc(sizeof(**target));
	memset(*target, '\0', sizeof(**target));

	if (*target == NULL) {
		VL_MSG_ERR("Could not allocate memory for instance_metadata_collection\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

void instance_free_thread(struct instance_thread_data *data) {
	if (data == NULL) {
		return;
	}

	if (data->used_by_ghost) {
		return;
	}

	free(data);
}

struct instance_thread_data *instance_init_thread(struct instance_thread_init_data *init_data) {
	VL_DEBUG_MSG_1 ("Init thread %s\n", init_data->module->instance_name);

	struct instance_thread_data *data = malloc(sizeof(*data));
	if (data == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_init_thread\n");
		return NULL;
	}

	memset(data, '\0', sizeof(*data));
	data->init_data = *init_data;

	return data;
}

int instance_start_thread(struct vl_thread_collection *collection, struct instance_thread_data *data) {
	struct instance_dynamic_data *module = data->init_data.module;

	VL_DEBUG_MSG_1 ("Starting thread %s\n", module->instance_name);
	if (data->thread != NULL) {
		VL_MSG_ERR("BUG: tried to double start thread in rrr_start_thread\n");
		exit(EXIT_FAILURE);
	}
	data->thread = thread_preload_and_register (
			collection,
			module->operations.thread_entry,
			module->operations.preload,
			module->operations.poststop,
			module->operations.cancel_function,
			module->start_priority,
			data, module->instance_name
	);

	if (data->thread == NULL) {
		VL_MSG_ERR ("Error while starting thread for instance %s\n", module->instance_name);
		free(data);
		return 1;
	}

	return 0;
}

int instance_process_from_config(struct instance_metadata_collection *instances, struct rrr_config *config, const char **library_paths) {
	int ret = 0;
	for (int i = 0; i < config->module_count; i++) {
		ret = instance_load_and_save(instances, config->configs[i], library_paths);
		if (ret != 0) {
			VL_MSG_ERR("Loading of instance failed for %s\n",
					config->configs[i]->name);
			goto out;
		}
	}

	RRR_INSTANCE_LOOP(instance, instances)
	{
		ret = instance_add_senders(instances, instance);
		if (ret != 0) {
			VL_MSG_ERR("Adding senders failed for %s\n",
					instance->dynamic_data->instance_name);
			goto out;
		}
	}

	out:
	return ret;
}
