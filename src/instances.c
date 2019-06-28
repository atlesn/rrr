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

#include "global.h"
#include "instances.h"

#include "lib/module_thread.h"
#include "lib/instance_config.h"

int instance_check_threads_stopped(struct module_metadata instances[CMD_ARGUMENT_MAX]) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (instances[i].dynamic_data == NULL) {
			continue;
		}

		if (thread_get_state(instances[i].thread_data->thread) == VL_THREAD_STATE_STOPPED || instances[i].thread_data->thread->is_ghost == 1) {
			return 0;
		}
	}
	return 1;
}

void instance_free_all_threads(struct module_metadata instances[CMD_ARGUMENT_MAX]) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (instances[i].dynamic_data != NULL) {
			rrr_free_thread(instances[i].thread_data);
		}
	}
}

int instance_count_library_users (struct module_metadata instances[CMD_ARGUMENT_MAX], void *dl_ptr) {
	int users = 0;
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_dynamic_data *data = instances[i].dynamic_data;
		if (data != NULL) {
			if (data->dl_ptr == dl_ptr) {
				users++;
			}
		}
	}
	return users;
}

void instance_unload_all(struct module_metadata instances[CMD_ARGUMENT_MAX]) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_dynamic_data *data = instances[i].dynamic_data;
		if (data != NULL) {
			int dl_users = instance_count_library_users(instances, data->dl_ptr);
			int no_dl_unload = (dl_users > 1 ? 1 : 0);

			if (!no_dl_unload) {
				module_unload(data->dl_ptr, data->unload);
			}
		}
	}
}

struct module_metadata *__instance_save(struct module_metadata instances[CMD_ARGUMENT_MAX], struct module_dynamic_data *module) {
	VL_DEBUG_MSG_1 ("Saving dynamic_data instance %s\n", module->instance_name);
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		if (instances[i].dynamic_data == NULL) {
			instances[i].dynamic_data = module;
			return &instances[i];
		}
	}
	VL_MSG_ERR ("Too many different instances defined, max is %i\n", CMD_ARGUMENT_MAX);
	return NULL;
}

struct module_metadata *__instance_load_module (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		struct rrr_instance_config *instance_config
) {
	struct module_metadata *ret = NULL;

	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_dynamic_data *module = instances[i].dynamic_data;
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
	if (module_load(&start_data, module_name) != 0) {
		VL_MSG_ERR ("Module %s could not be loaded (in load_instance_module for instance %s)\n",
				module_name, instance_config->name);
		ret = NULL;
		goto out;
	}

	struct module_dynamic_data *dynamic_data = malloc(sizeof(*dynamic_data));
	memset(dynamic_data, '\0', sizeof(*dynamic_data));

	start_data.init(dynamic_data);
	dynamic_data->dl_ptr = start_data.dl_ptr;
	dynamic_data->instance_name = instance_config->name;
	dynamic_data->unload = start_data.unload;

	ret = __instance_save(instances, dynamic_data);

	out:
	if (module_name != NULL) {
		free(module_name);
	}

	return ret;
}

struct module_metadata *instance_find (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		const char *name
) {
	for (int i = 0; i < CMD_ARGUMENT_MAX; i++) {
		struct module_dynamic_data *module = instances[i].dynamic_data;
		if (module != NULL && strcmp(module->instance_name, name) == 0) {
			return &instances[i];
		}
	}
	return NULL;
}

int instance_load (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		struct rrr_config *all_config,
		struct rrr_instance_config *instance_config
) {
	struct module_metadata *module = __instance_load_module(instances, instance_config);
	if (module == NULL || module->dynamic_data == NULL) {
		VL_MSG_ERR("Instance '%s' could not be loaded\n", instance_config->name);
		return 1;
	}

	return 0;
}

struct add_sender_data {
	struct module_metadata *instances;
	struct module_metadata *senders[VL_MODULE_MAX_SENDERS];
	int pos;
	int max;
};

int __add_sender_callback(const char *value, void *_data) {
	struct add_sender_data *data = _data;

	int ret = 0;

	if (data->pos == data->max) {
		VL_MSG_ERR("Could not add sender: Too many senders, max is %d\n", VL_MODULE_MAX_SENDERS);
		ret = 1;
		goto out;
	}

	struct module_metadata *sender = instance_find(data->instances, value);

	if (sender == NULL) {
		VL_MSG_ERR("Could not find sender instance '%s'\n", value);
		ret = 1;
		goto out;
	}

	data->senders[data->pos] = sender;

	data->pos++;

	out:
	return ret;
}

int instance_add_senders (
		struct module_metadata instances[CMD_ARGUMENT_MAX],
		struct rrr_config *all_config,
		struct rrr_instance_config *instance_config,
		struct module_metadata *module
) {
	int ret = 0;

	VL_DEBUG_MSG_1("Adding senders for instance '%s' module '%s'\n",
			module->dynamic_data->instance_name,
			module->dynamic_data->module_name
	);

	struct add_sender_data sender_data;
	sender_data.instances = instances;
	sender_data.max = VL_MODULE_MAX_SENDERS;
	sender_data.pos = 0;

	ret = rrr_settings_traverse_split_commas_silent_fail (
			instance_config->settings, "senders",
			&__add_sender_callback, &sender_data
	);

	if (module->dynamic_data->type == VL_MODULE_TYPE_PROCESSOR) {
		if (sender_data.pos == 0) {
			VL_MSG_ERR("Sender module must be specified for processor module %s instance %s\n",
					module->dynamic_data->module_name, module->dynamic_data->instance_name);
			ret = 1;
			goto out;
		}

		for (unsigned long int j = 0; j < sender_data.pos; j++) {
			VL_DEBUG_MSG_1("Checking sender instance '%s' module '%s'\n",
					sender_data.senders[j]->dynamic_data->instance_name,
					sender_data.senders[j]->dynamic_data->module_name
			);

			struct module_metadata *module_sender = sender_data.senders[j];

			if (module_sender == module) {
				VL_MSG_ERR("Instance %s set with itself as sender\n",
						module->dynamic_data->instance_name);
				ret = 1;
				goto out;
			}

			module->senders[module->senders_count++] = module_sender;
		}
	}
	else if (module->dynamic_data->type == VL_MODULE_TYPE_SOURCE) {
		if (sender_data.pos != 0) {
			VL_MSG_ERR("Sender module cannot be specified for instance '%s' using module '%s'\n",
					module->dynamic_data->instance_name, module->dynamic_data->module_name);
			ret = 1;
			goto out;
		}
	}
	else {
		VL_MSG_ERR ("Unknown module type for %s: %i\n",
				module->dynamic_data->module_name, module->dynamic_data->type
		);
		ret = 1;
		goto out;
	}

	VL_DEBUG_MSG_1("Added %d senders\n", sender_data.pos);

	out:
	return ret;
}
