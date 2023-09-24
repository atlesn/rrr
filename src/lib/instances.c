/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include "log.h"
#include "cmodule/cmodule_main.h"
#include "modules.h"
#include "threads.h"
#include "instances.h"
#include "discern_stack.h"
#include "discern_stack_helper.h"
#include "instance_config.h"
#include "message_broker.h"
#include "message_helper.h"
#include "message_holder/message_holder_struct.h"
#include "poll_helper.h"
#include "allocator.h"
#include "event/event_functions.h"
#include "mqtt/mqtt_topic.h"
#include "stats/stats_instance.h"
#include "util/gnu.h"

#define RRR_INSTANCE_DEFAULT_THREAD_WATCHDOG_TIMER_MS 5000

struct rrr_instance_message_broker_entry_postprocess_route_callback_data {
	struct rrr_instance_runtime_data *data;
	struct rrr_msg_holder *entry;
	struct rrr_instance_friend_collection *nexthops;
};

static int __rrr_instance_message_broker_entry_postprocess_apply_cb (
		rrr_length result,
		const char *instance_name,
		void *arg
) {
	struct rrr_instance_message_broker_entry_postprocess_route_callback_data *callback_data = arg;
	struct rrr_instance_runtime_data *data = callback_data->data;

	int ret = 0;

	struct rrr_instance *instance = rrr_instance_find(INSTANCE_D_INSTANCES(data), instance_name);

	// Instances must be validated before thread is started
	assert(instance != NULL);

	// Latest result takes precedence in case of apply on same instance multiple times
	rrr_instance_friend_collection_remove (callback_data->nexthops, instance);
	if (result) {
		if ((ret = rrr_instance_friend_collection_append (
				callback_data->nexthops,
				instance,
				NULL
		)) != 0) {
			RRR_MSG_0("Failed to append to collection in %s\n", __func__);
			goto out;
		}
	}

	RRR_DBG_3("+ Apply instance %s result %s in message from instance %s\n",
			instance_name, result ? "ADD" : "REMOVE", INSTANCE_D_NAME(callback_data->data));

	out:
	return ret;
}
		
static int __rrr_instance_message_broker_entry_postprocess_callback (
		struct rrr_msg_holder *entry_locked,
		void *arg
) {
	struct rrr_instance_runtime_data *data = arg;

	int ret = 0;

	struct rrr_instance_friend_collection nexthops = {0};

	if (RRR_LL_COUNT(INSTANCE_D_ROUTES(data)) == 0) {
		goto out;
	}

	struct rrr_discern_stack_helper_callback_data resolve_callback_data = {
		entry_locked->message,
		0
	};

	struct rrr_instance_message_broker_entry_postprocess_route_callback_data apply_callback_data = {
		data,
		entry_locked,
		&nexthops
	};

	enum rrr_discern_stack_fault fault = 0;

	if ((ret = rrr_discern_stack_collection_execute (
			&fault,
			INSTANCE_D_ROUTES(data),
			rrr_discern_stack_helper_topic_filter_resolve_cb,
			rrr_discern_stack_helper_array_tag_resolve_cb,
			&resolve_callback_data,
			__rrr_instance_message_broker_entry_postprocess_apply_cb,
			&apply_callback_data
	)) != 0) {
		goto out;
	}

	RRR_DBG_3("= %i receiver instances set in message from instance %s\n",
			RRR_LL_COUNT(&nexthops), INSTANCE_D_NAME(data));

	if (RRR_LL_COUNT(&nexthops) > 0) {
		if ((ret = rrr_msg_holder_nexthops_set (entry_locked, &nexthops)) != 0) {
			RRR_MSG_0("Failed to set nexthops in %s\n", __func__);
			goto out;
		}
	}

	out:
	rrr_instance_friend_collection_clear(&nexthops);
	return ret;
}

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
	rrr_discern_stack_collection_clear(&target->routes);
	rrr_discern_stack_collection_clear(&target->methods);

	RRR_FREE_IF_NOT_NULL(target->topic_filter);
	rrr_mqtt_topic_token_destroy(target->topic_first_token);

	rrr_free(target->module_data);
	rrr_free(target);
}

static int __rrr_instance_new (
		struct rrr_instance **target
) {
	int ret = 0;

	struct rrr_instance *instance = rrr_allocate(sizeof(*instance));

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

	struct rrr_instance_module_data *module_data = rrr_allocate(sizeof(*module_data));
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

static int __rrr_instance_parse_topic_filter (
		struct rrr_instance *data
) {
	return rrr_instance_config_parse_optional_topic_filter (
			&data->topic_first_token,
			&data->topic_filter,
			data->config,
			"topic_filter"
	);
}

void __rrr_instance_parse_discern_stack_name_callback (
		const char *name,
		void *arg
) {
	(void)(arg);
	RRR_DBG_1("-> %s\n", name);
}

static int __rrr_instance_parse_route (
		struct rrr_instance *data_final
) {
	int ret = 0;

	if ((ret = rrr_instance_config_parse_route_definition_from_config_silent_fail(&data_final->routes, data_final->config, "route")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			ret = 0;
		}
		goto out;
	}

	if (RRR_DEBUGLEVEL_1) {
		RRR_DBG_1("Active route definitions for instance %s:\n", INSTANCE_M_NAME(data_final));
		rrr_discern_stack_collection_iterate_names (
				INSTANCE_I_ROUTES(data_final),
				__rrr_instance_parse_discern_stack_name_callback,
				NULL
		);
	}

	out:
	return ret;
}

static int __rrr_instance_parse_method (
		struct rrr_instance *data_final
) {
	int ret = 0;

	struct data {
		int do_methods_direct_dispatch;
	} data_tmp;

	struct data *data = &data_tmp;
	struct rrr_instance_config_data *config = data_final->config;

	if ((ret = rrr_instance_config_parse_method_definition_from_config_silent_fail(&data_final->methods, data_final->config, "methods")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("methods_direct_dispatch",
				RRR_MSG_0("Parameter methods_direct_dispatch was set without methods being set for instance %s, this is a configuration error.\n",
					INSTANCE_M_NAME(data_final));
				ret = 1;
				goto out;
			);
			ret = 0;
		}
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("methods_direct_dispatch", do_methods_direct_dispatch, 0);
	if (data_tmp.do_methods_direct_dispatch)
		data_final->misc_flags |= RRR_INSTANCE_MISC_OPTIONS_METHODS_DIRECT_DISPATCH;

	if (RRR_DEBUGLEVEL_1) {
		RRR_DBG_1("Active method definitions for instance %s:\n", INSTANCE_M_NAME(data_final));
		rrr_discern_stack_collection_iterate_names (
				INSTANCE_I_METHODS(data_final),
				__rrr_instance_parse_discern_stack_name_callback,
				NULL
		);
	}

	// Cmodules, the only ones using these parameters, will set them back
	// to being tagged as used later. Other modules will not do this and a warning
	// will be printed that the parameters are unused.
	rrr_instance_config_set_unused(data_final->config, "methods");
	rrr_instance_config_set_unused(data_final->config, "methods_direct_dispatch");

	out:
	return ret;
}

static int __rrr_instance_parse_misc (
		struct rrr_instance *data_final
) {
	int ret = 0;

	struct rrr_instance_config_data *config = data_final->config;

	struct data {
		int do_enable_buffer;
		int do_enable_backstop;
		int do_duplicate;
		int do_topic_filter_invert;
	} data_tmp;

	struct data *data = &data_tmp;

	// Note : Options are both default yes and default no, take care

	// Default YES options
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("buffer", do_enable_buffer, 1);
	if (!data->do_enable_buffer) {
		data_final->misc_flags |= RRR_INSTANCE_MISC_OPTIONS_DISABLE_BUFFER;
	}
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("backstop", do_enable_backstop, 1);
	if (!data->do_enable_backstop) {
		data_final->misc_flags |= RRR_INSTANCE_MISC_OPTIONS_DISABLE_BACKSTOP;
	}

	// Default NO options
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("duplicate", do_duplicate, 0);
	if (data->do_duplicate) {
		data_final->misc_flags |= RRR_INSTANCE_MISC_OPTIONS_DUPLICATE;
	}
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("topic_filter_invert", do_topic_filter_invert, 0);
	if (data->do_topic_filter_invert) {
		data_final->misc_flags |= RRR_INSTANCE_MISC_OPTIONS_TOPIC_FILTER_INVERT;
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

	if ((ret = rrr_instance_config_friend_collection_populate_from_config (
			&instance->wait_for,
			instances,
			instance->config,
			"wait_for"
	)) != 0) {
		RRR_MSG_0("Error while adding wait for for instance %s\n",
			INSTANCE_M_NAME(instance));
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

	if ((ret = rrr_instance_config_friend_collection_populate_from_config (
			&instance->senders,
			instances,
			instance->config,
			"senders"
	)) != 0) {
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

int rrr_instance_has_sender (
		const struct rrr_instance *instance,
		const struct rrr_instance *sender
) {
	return rrr_instance_friend_collection_check_exists (
			&instance->senders,
			sender
	);
}

void rrr_instance_collection_clear (
		struct rrr_instance_collection *target
) {
	RRR_LL_DESTROY(target, struct rrr_instance, __rrr_instance_destroy(node));
}

int rrr_instance_collection_count (
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
	rrr_message_broker_costumer_unregister(INSTANCE_D_BROKER(data), INSTANCE_D_HANDLE(data));
	rrr_free(data);
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

static int __rrr_instance_iterate_route_instances_callback (
		const char *route_definition_name,
		const char *instance_name,
		void *arg
) {
	struct rrr_instance_runtime_data *data = arg;

	int ret = 0;

	const struct rrr_instance *instance = rrr_instance_find(INSTANCE_D_INSTANCES(data), instance_name);

	if (instance == NULL) {
		RRR_MSG_0("Instance '%s' in route definition '%s' used by instance '%s' does not exist\n",
				instance_name, route_definition_name, INSTANCE_D_NAME(data));
		ret = 1;
		goto out;
	}

	if (!rrr_instance_friend_collection_check_exists(&instance->senders, INSTANCE_D_INSTANCE(data))) {
		RRR_MSG_0("Instance '%s' in route definition '%s' used by instance '%s' is not a reader of this instance\n",
				instance_name, route_definition_name, INSTANCE_D_NAME(data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static struct rrr_instance_runtime_data *__rrr_instance_runtime_data_new (
		struct rrr_instance_runtime_init_data *init_data
) {
	RRR_DBG_1 ("Init thread %s\n", init_data->module->instance_name);

	struct rrr_instance_runtime_data *data = rrr_allocate(sizeof(*data));
	if (data == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		return NULL;
	}

	memset(data, '\0', sizeof(*data));
	data->init_data = *init_data;

	// Verify that instances mentioned in any routes are readers of this instance
	if (rrr_discern_stack_collection_iterate_destination_names (
			INSTANCE_D_ROUTES(data),
			__rrr_instance_iterate_route_instances_callback,
			data
	) != 0) {
		goto out_free;
	}

	if (init_data->instance->misc_flags & RRR_INSTANCE_MISC_OPTIONS_DISABLE_BUFFER) {
		RRR_DBG_1("%s instance %s buffer is disabled, starting with one-slot buffer\n",
				init_data->instance->module_data->module_name, init_data->instance->module_data->instance_name);
	}

	if (rrr_message_broker_costumer_register (
			&data->message_broker_handle,
			init_data->message_broker,
			init_data->module->instance_name,
			(init_data->instance->misc_flags & RRR_INSTANCE_MISC_OPTIONS_DISABLE_BUFFER) != 0,
			__rrr_instance_message_broker_entry_postprocess_callback,
			data
	) != 0) {
		RRR_MSG_0("Could not register with message broker in %s\n", __func__);
		goto out_free;
	}
	
	goto out;
	out_free:
		rrr_free(data);
		data = NULL;
	out:
		return data;
}

struct rrr_instance_add_senders_to_broker_callback_data {
	struct rrr_message_broker_costumer *target;
	struct rrr_message_broker *broker;
	struct rrr_instance *faulty_sender;
};

static int __rrr_instance_add_senders_to_broker_callback (
		struct rrr_instance *instance,
		void *parameter,
		void *arg
) {
	(void)(parameter);

	int ret = 0;

	struct rrr_instance_add_senders_to_broker_callback_data *data = arg;

	struct rrr_message_broker_costumer *handle = rrr_message_broker_costumer_find_by_name (
			data->broker,
			INSTANCE_M_NAME(instance)
	);

	if (handle == NULL) {
		RRR_MSG_0("Could not find message broker costumer '%s' in __rrr_instance_add_senders_to_broker_callback\n", INSTANCE_M_NAME(instance));
		data->faulty_sender = instance;
		ret = 1;
		goto out;
	}

	if ((ret = rrr_message_broker_sender_add(data->target, handle)) != 0) {
		RRR_MSG_0("Failed to add costumer '%s' in __rrr_instance_add_senders_to_broker_callback\n", INSTANCE_M_NAME(instance));
		data->faulty_sender = instance;
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_instance_add_senders_to_broker (
		struct rrr_instance **faulty_sender,
		struct rrr_message_broker *broker,
		struct rrr_instance *instance
) {
	int ret = 0;

	struct rrr_message_broker_costumer *handle = rrr_message_broker_costumer_find_by_name(broker, instance->config->name);

	if (handle == NULL) {
		RRR_BUG("BUG: Target costumer not found in __rrr_instance_add_senders_to_broker\n");
	}

	*faulty_sender = NULL;

	struct rrr_instance_add_senders_to_broker_callback_data callback_data = {
			handle,
			broker,
			NULL
	};

	ret = rrr_instance_friend_collection_iterate (
			&instance->senders,
			__rrr_instance_add_senders_to_broker_callback,
			&callback_data
	);

	if (ret != 0) {
		*faulty_sender = callback_data.faulty_sender;
	}

	return ret;
}

// Initialize event handling, this must be done prior to starting threads
// because the write notify listener lists in message broker are not
// protected by mutexes and must may not be changed by the threads
// themselves.
static int __rrr_instance_before_start_tasks (
		struct rrr_message_broker *broker,
		struct rrr_instance *instance
) {
	int ret = 0;

	struct rrr_message_broker_costumer *self = rrr_message_broker_costumer_find_by_name(broker, instance->config->name);

	if (instance->module_data->event_functions.broker_data_available != NULL) {
		rrr_event_function_set (
			rrr_message_broker_event_queue_get(self),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			instance->module_data->event_functions.broker_data_available,
			"broker data available"
		);
	}

	struct rrr_instance *faulty_instance = NULL;
	if (__rrr_instance_add_senders_to_broker(&faulty_instance, broker, instance) != 0) {
		RRR_MSG_0("Failed to add senders of instance %s. Faulty sender was %s.\n",
				instance->config->name, (faulty_instance != NULL ? INSTANCE_M_NAME(faulty_instance): "(null)"));
		goto out;
	}

	out:
	return ret;
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

struct rrr_instance_count_receivers_of_self_callback_data {
	struct rrr_instance *self;
	rrr_length count;
};

static int __rrr_instance_count_receivers_of_self_callback (
		struct rrr_instance *instance,
		void *parameter,
		void *arg
) {
	(void)(parameter);

	struct rrr_instance_count_receivers_of_self_callback_data *callback_data = arg;
	if (instance == callback_data->self) {
		rrr_length_inc_bug(&callback_data->count);
	}
	return 0;
}

static rrr_length __rrr_instance_count_receivers_of_self (
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

static void *__rrr_instance_thread_entry_intermediate (
		struct rrr_thread *thread
) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	thread_data->thread = thread;

	pthread_cleanup_push(__rrr_instace_runtime_data_destroy_intermediate, thread->private_data);
	pthread_cleanup_push(__rrr_instance_thread_intermediate_cleanup, thread);
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

	RRR_DBG_1("Instance %s starting int PID %llu, TID %llu, thread %p, instance %p\n",
		thread->name, (unsigned long long) getpid(), (unsigned long long) rrr_gettid(), thread, thread_data);

	// Ignore return value
	thread_data->init_data.module->operations.thread_entry(thread);

	// Keep out label ABOVE cleanup_pops
	out:

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	// Don't put code here, modules usually call pthread_exit which means we
	// only do the cleanup functions

	return NULL;
}

static int __rrr_instance_thread_preload_enable_duplication_as_needed (
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	if (INSTANCE_D_FLAGS(thread_data) & RRR_INSTANCE_MISC_OPTIONS_DUPLICATE) {
		rrr_length slots = __rrr_instance_count_receivers_of_self(INSTANCE_D_INSTANCE(thread_data));

		RRR_DBG_1("%s instance %s setting up duplicated output buffer, %" PRIrrrl " readers detected\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data), slots);

		if ((ret = rrr_message_broker_setup_split_output_buffer (
				INSTANCE_D_HANDLE(thread_data),
				slots
		)) != 0) {
			RRR_MSG_0("Could not setup split buffer in buffer instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_instance_thread_preload (
		struct rrr_thread *thread
) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	int ret = 0;

	if ((ret = __rrr_instance_thread_preload_enable_duplication_as_needed (thread_data)) != 0) {
		goto out;
	}

	if (INSTANCE_D_MODULE(thread_data)->operations.preload != NULL) {
		if ((ret = INSTANCE_D_MODULE(thread_data)->operations.preload(thread)) != 0) {
			RRR_MSG_0("Preload function for module %s instance %s failed with return value %i\n",
					INSTANCE_D_MODULE_NAME(thread_data),
					INSTANCE_D_NAME(thread_data),
					ret
			);
			goto out;
		}
	}

	out:
	return ret;
}

struct rrr_instance_collection_start_threads_check_wait_for_callback_data {
	struct rrr_instance_collection *instances;
};

static int __rrr_instance_collection_start_threads_check_wait_for_callback (
		int *do_start,
		struct rrr_thread *thread,
		void *arg
) {
	struct rrr_instance_collection_start_threads_check_wait_for_callback_data *data = arg;
	struct rrr_instance *instance = rrr_instance_find_by_thread(data->instances, thread);

	if (instance == NULL) {
		RRR_BUG("Instance not found in __main_start_threads_check_wait_for_callback\n");
	}

	*do_start = 1;

	// TODO : Check for wait_for loops in configuration

	RRR_LL_ITERATE_BEGIN(&instance->wait_for, struct rrr_instance_friend);
		struct rrr_instance *check = node->instance;
		if (check == instance) {
			RRR_MSG_0("Instance %s was set up to wait for itself before starting with wait_for, this is an error.\n",
					INSTANCE_M_NAME(instance));
			return 1;
		}

		if (	rrr_thread_state_get(check->thread) == RRR_THREAD_STATE_RUNNING_FORKED ||
				rrr_thread_state_get(check->thread) == RRR_THREAD_STATE_STOPPED
		) {
			// OK
		}
		else {
			RRR_DBG_1 ("Instance %s waiting for instance %s to start\n",
					INSTANCE_M_NAME(instance), INSTANCE_M_NAME(check));
			*do_start = 0;
		}
	RRR_LL_ITERATE_END();

	return 0;
}

// This function allocates runtime data and thread data.
// - runtime data is ALWAYS destroyed by the thread. If a thread does not
//   start, we must BUG() out
// - thread data is freed by main unless thread has become ghost in which the
//   thread will free it if it wakes up

int rrr_instances_create_and_start_threads (
		struct rrr_thread_collection **thread_collection_target,
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_collection *config,
		struct cmd_data *cmd,
		struct rrr_stats_engine *stats,
		struct rrr_message_broker *message_broker,
		struct rrr_fork_handler *fork_handler
) {
	int ret = 0;

	struct rrr_thread_collection *thread_collection = NULL;

	struct rrr_instance_runtime_data *runtime_data_tmp = NULL;

	if (RRR_LL_COUNT(instances) == 0) {
		RRR_MSG_0("No instances started, exiting\n");
		ret = 1;
		goto out;
	}

	// Create thread collection
	if (rrr_thread_collection_new (&thread_collection) != 0) {
		RRR_MSG_0("Could not create thread collection\n");
		ret = 1;
		goto out;
	}

	// Initialize thread data and runtime data
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		struct rrr_instance *instance = node;

		if (instance->module_data == NULL) {
			RRR_BUG("BUG: Dynamic data was NULL in rrr_main_create_and_start_threads\n");
		}

		struct rrr_instance_runtime_init_data init_data;
		init_data.module = instance->module_data;
		init_data.senders = &instance->senders;
		init_data.cmd_data = cmd;
		init_data.global_config = config;
		init_data.instance_config = instance->config;
		init_data.stats = stats;
		init_data.message_broker = message_broker;
		init_data.fork_handler = fork_handler;
		init_data.topic_first_token = instance->topic_first_token;
		init_data.topic_str = instance->topic_filter;
		init_data.instance = instance;

		RRR_DBG_1("Initializing instance %p '%s'\n", instance, instance->config->name);

		if ((runtime_data_tmp = __rrr_instance_runtime_data_new(&init_data)) == NULL) {
			RRR_MSG_0("Error while creating runtime data for instance %s\n",
					INSTANCE_M_NAME(instance));
			ret = 1;
			goto out_destroy_collection;
		}

		struct rrr_thread *thread = rrr_thread_collection_thread_new (
				thread_collection,
				__rrr_instance_thread_entry_intermediate,
				__rrr_instance_thread_preload,
				instance->module_data->instance_name,
				RRR_INSTANCE_DEFAULT_THREAD_WATCHDOG_TIMER_MS * 1000,
				runtime_data_tmp
		);

		if (thread == NULL) {
			RRR_MSG_0("Error while starting instance %s\n",
					instance->module_data->instance_name);
			ret = 1;
			goto out_destroy_collection;
		}

		runtime_data_tmp = NULL;

		// Set shortcuts
		node->thread = thread;
	RRR_LL_ITERATE_END();

	// Task which needs to be performed when all instances have been initialized, but
	// which cannot be performed after threads have started.
	RRR_LL_ITERATE_BEGIN(instances, struct rrr_instance);
		RRR_DBG_1("Before start tasks instance %p '%s'\n", node, node->config->name);
		if ((ret = __rrr_instance_before_start_tasks(message_broker, node)) != 0) {
			goto out_destroy_collection;
		}
	RRR_LL_ITERATE_END();

	struct rrr_instance_collection_start_threads_check_wait_for_callback_data callback_data = { instances };

	if (rrr_thread_collection_start_all (
			thread_collection,
			__rrr_instance_collection_start_threads_check_wait_for_callback,
			&callback_data
	) != 0) {
		RRR_MSG_0("Error while waiting for threads to initialize\n");
		ret = 1;
		goto out_destroy_collection;
	}

	*thread_collection_target = thread_collection;

	goto out;
	out_destroy_collection:
		{
			int ghost_count = 0;
			rrr_thread_collection_destroy(&ghost_count, thread_collection);
			if (ghost_count > 0) {
				RRR_MSG_0("Warning: %i threads were ghost during destruction of collection in %s\n", ghost_count, __func__);
			}
		}
	out:
		if (runtime_data_tmp != NULL) {
			rrr_instance_runtime_data_destroy_hard(runtime_data_tmp);
		}
		return ret;
}

int rrr_instances_create_from_config (
		struct rrr_instance_collection *instances,
		struct rrr_instance_config_collection *config,
		const char **library_paths
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(config, struct rrr_instance_config_data);
		ret = rrr_instance_load_and_save(instances, node, library_paths);
		if (ret != 0) {
			RRR_MSG_0("Loading of instance failed for %s. Library paths used:\n",
					node->name);
			for (int j = 0; *library_paths[j] != '\0'; j++) {
				RRR_MSG_0("-> %s\n", library_paths[j]);
			}
			goto out;
		}
	RRR_LL_ITERATE_END();

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
		ret = __rrr_instance_parse_route(instance);
		if (ret != 0) {
			RRR_MSG_0("Parsing of route parameter failed for instance %s\n",
					INSTANCE_M_NAME(instance));
			goto out;
		}
		ret = __rrr_instance_parse_method(instance);
		if (ret != 0) {
			RRR_MSG_0("Parsing of method parameter failed for instance %s\n",
					INSTANCE_M_NAME(instance));
			goto out;
		}
		ret = __rrr_instance_parse_misc(instance);
		if (ret != 0) {
			RRR_MSG_0("Parsing of misc parameters failed for instance %s\n",
					INSTANCE_M_NAME(instance));
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_instance_default_set_output_buffer_ratelimit_when_needed (
		unsigned int *delivery_entry_count,
		int *delivery_ratelimit_active,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	if (rrr_message_broker_get_entry_count_and_ratelimit (
			delivery_entry_count,
			delivery_ratelimit_active,
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
		rrr_message_broker_set_ratelimit(INSTANCE_D_HANDLE(thread_data), 1);
	}
	else if (*delivery_entry_count < 10 && *delivery_ratelimit_active == 1) {
		RRR_DBG_1("Disabling ratelimit on buffer in %s instance %s due to low buffer level\n",
				INSTANCE_D_MODULE_NAME(thread_data), INSTANCE_D_NAME(thread_data));
		rrr_message_broker_set_ratelimit(INSTANCE_D_HANDLE(thread_data), 0);
	}

	out:
	return ret;
}
