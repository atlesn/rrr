/*

Read Route Record

Copyright (C) 2023-2024 Atle Solbakken atle@goliathdns.no

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


#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "../lib/lua/lua.h"
#include "../lib/lua/lua_config.h"
#include "../lib/lua/lua_message.h"
#include "../lib/lua/lua_cmodule.h"
#include "../lib/lua/lua_debug.h"

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/messages/msg_addr.h"
#include "../lib/cmodule/cmodule_helper.h"
#include "../lib/cmodule/cmodule_main.h"
#include "../lib/cmodule/cmodule_worker.h"
#include "../lib/cmodule/cmodule_config_data.h"
#include "../lib/cmodule/cmodule_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/util/readfile.h"

struct lua_data {
	struct rrr_instance_runtime_data *thread_data;

	char *lua_file;
	int do_precision_loss_warnings;
};

void data_init (
		struct lua_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	memset (data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

void data_cleanup(void *arg) {
	struct lua_data *data = arg;

	RRR_FREE_IF_NOT_NULL(data->lua_file);
}

int parse_config(struct lua_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	if (rrr_instance_config_get_string_noconvert_silent (&data->lua_file, config, "lua_file") != 0) {
		RRR_MSG_0("No lua_file specified for Lua instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("lua_precision_loss_warnings", do_precision_loss_warnings, 1 /* Defaults to yes */);

	out:
	return ret;
}

struct lua_child_data {
	struct lua_data *parent_data;
	struct rrr_lua *lua;
	const struct rrr_cmodule_config_data *cmodule_config_data;
	int64_t start_time;
	int64_t prev_status_time;
	uint64_t processed;
	uint64_t processed_total;
};

static int lua_ping_callback (RRR_CMODULE_PING_CALLBACK_ARGS) {
	struct lua_child_data *data = private_arg;

	(void)(worker);

	// Need status print?
	int64_t now = (int64_t) rrr_time_get_64();
	int64_t diff = now - data->prev_status_time;
	if (diff < 1 * 1000 * 1000) { // 1 Second
		return 0;
	}

	// Calculate/print status
	data->prev_status_time = now;

	double per_sec = ((double) data->processed) / ((double) diff / 1000000);
	double per_sec_average = ((double) data->processed_total) / ((double) (rrr_time_get_64() - (uint64_t) data->start_time) / 1000000);

	RRR_DBG_1("Lua instance %s processed per second %.2f average %.2f total %" PRIu64 "\n",
			INSTANCE_D_NAME(data->parent_data->thread_data),
			per_sec,
			per_sec_average,
			data->processed_total
	);

	data->processed = 0;

	return 0;
}

static int lua_configuration_callback(RRR_CMODULE_CONFIGURATION_CALLBACK_ARGS) {
	struct lua_child_data *data = private_arg;
	struct lua_data *parent_data = data->parent_data;
	const char *function = data->cmodule_config_data->config_method;

	int ret = 0;

	int ret_tmp;
	struct rrr_instance_config_data instance_config = {0};

	rrr_instance_config_move_from_settings (
			&instance_config,
			&worker->settings_used,
			&worker->settings
	);

	if (function == NULL || *function == '\0')
		goto out;

	if ((ret = rrr_lua_config_push_new (data->lua, &instance_config)) != 0) {
		RRR_MSG_0("Error pushing config in %s in Lua instance %s\n",
			__func__, INSTANCE_D_NAME(parent_data->thread_data));
		goto out;
	}

	if ((ret_tmp = rrr_lua_call(data->lua, function, 1)) != 0) {
		RRR_MSG_0("Error %i returned from Lua config function %s in Lua instance %s\n",
			ret_tmp, function, INSTANCE_D_NAME(parent_data->thread_data));
		ret = 1;
		goto out;
	}
	
	out:
	rrr_instance_config_move_to_settings (
			&worker->settings_used,
			&worker->settings,
			&instance_config
	);
	return ret;
}

static int lua_process_callback(RRR_CMODULE_PROCESS_CALLBACK_ARGS) {
	struct lua_child_data *data = private_arg;
	struct lua_data *parent_data = data->parent_data;

	(void)(worker);

	int ret = 0;

	int ret_tmp, argc;
	const char *functions[2] = {NULL, NULL};
	struct rrr_array array = {0};

	if (is_spawn_ctx) {
		assert (data->cmodule_config_data->source_method != NULL && "No source method specified");

		if ((ret = rrr_lua_message_push_new (
				data->lua
		)) != 0) {
			RRR_MSG_0("Error pushing data message in %s in Lua instance %s\n",
					__func__, INSTANCE_D_NAME(parent_data->thread_data));
			ret = 1;
			goto out;
		}

		RRR_DBG_3("Lua instance %s calling function '%s' with 1 argument while spawning\n",
			INSTANCE_D_NAME(parent_data->thread_data), data->cmodule_config_data->source_method);

		if ((ret = rrr_lua_call(data->lua, data->cmodule_config_data->source_method, 1)) != 0) {
			RRR_MSG_0("Error %i returned from Lua function '%s' while spawning in Lua instance %s\n",
					ret, data->cmodule_config_data->source_method, INSTANCE_D_NAME(parent_data->thread_data));
			ret = 1;
			goto out;
		}

		goto out;
	}

	if (INSTANCE_D_FLAGS(parent_data->thread_data) & RRR_INSTANCE_MISC_OPTIONS_METHODS_DIRECT_DISPATCH) {
		functions[0] = method;

		// Undocumented parameter, used for testing
		if (INSTANCE_D_FLAGS(parent_data->thread_data) & RRR_INSTANCE_MISC_OPTIONS_METHODS_DOUBLE_DELIVERY) {
			assert(data->cmodule_config_data->process_method != NULL);
			assert(method != NULL);
			functions[1] = data->cmodule_config_data->process_method;
		}
	}
	else if (method != NULL) {
		functions[1] = method;
	}
	else {
		functions[0] = data->cmodule_config_data->process_method;
	}

	assert((functions[0] != NULL || functions[1] != NULL) && "No process method specified");

	for (int i = 0; i < 2; i++) {
		if (functions[i] == NULL)
			continue;

		assert(RRR_MSG_ADDR_SIZE_OK(message_addr));

		if (MSG_IS_DATA(message)) {
			if ((ret = rrr_lua_message_push_new_data (
					data->lua,
					message->timestamp,
					MSG_TYPE(message),
					MSG_TOPIC_PTR(message),
					MSG_TOPIC_LENGTH(message),
					(const struct sockaddr *) message_addr->addr,
					RRR_MSG_ADDR_GET_ADDR_LEN(message_addr),
					message_addr->protocol,
					MSG_DATA_PTR(message),
					MSG_DATA_LENGTH(message)
			)) != 0) {
				RRR_MSG_0("Error pushing data message in %s in Lua instance %s\n",
					__func__, INSTANCE_D_NAME(parent_data->thread_data));
				ret = 1;
				goto out;
			}
		}
		else {
			assert(MSG_IS_ARRAY(message));

			uint16_t version;
			if ((ret = rrr_array_message_append_to_array (
					&version,
					&array,
					message
			)) != 0) {
				RRR_MSG_0("Error appending array message in %s in Lua instance %s\n",
					__func__, INSTANCE_D_NAME(parent_data->thread_data));
				ret = 1;
				goto out;
			}

			if ((ret = rrr_lua_message_push_new_array (
					data->lua,
					message->timestamp,
					MSG_TYPE(message),
					MSG_TOPIC_PTR(message),
					MSG_TOPIC_LENGTH(message),
					(const struct sockaddr *) message_addr->addr,
					RRR_MSG_ADDR_GET_ADDR_LEN(message_addr),
					message_addr->protocol,
					&array
			)) != 0) {
				RRR_MSG_0("Error pushing array message in %s in Lua instance %s\n",
					__func__, INSTANCE_D_NAME(parent_data->thread_data));
				ret = 1;
				goto out;
			}
		}

		argc = 1;

		if (i > 0) {
			rrr_lua_pushstr(data->lua, method);
			argc++;
		}

		RRR_DBG_3("Lua instance %s calling function '%s' with %i arguments while processing (pass %i)\n",
			INSTANCE_D_NAME(parent_data->thread_data), functions[i], argc, i + 1);

		if ((ret_tmp = rrr_lua_call(data->lua, functions[i], argc)) != 0) {
			RRR_MSG_0("Error %i returned from Lua function '%s'%s in Lua instance %s\n",
				ret_tmp, functions[i], is_spawn_ctx ? " while spawning" : "", INSTANCE_D_NAME(parent_data->thread_data));
			ret = 1;
			goto out;
		}
	}

	data->processed++;
	data->processed_total++;

	out:
		rrr_array_clear(&array);
		return ret;

}

int lua_init_wrapper_callback(RRR_CMODULE_INIT_WRAPPER_CALLBACK_ARGS) {
	struct lua_data *data = private_arg;

	int ret = 0;

	struct lua_child_data child_data = {0};
	struct rrr_lua *lua;
	char *script;
	rrr_biglength script_size;

	if ((ret = rrr_lua_new(&lua)) != 0) {
		RRR_MSG_0("Error creating Lua context in %s\n", __func__);
		goto out;
	}

	rrr_lua_set_precision_loss_warnings(lua, data->do_precision_loss_warnings);
	rrr_lua_message_library_register(lua);
	rrr_lua_cmodule_library_register(lua, worker);
	rrr_lua_debug_library_register(lua);

	if ((ret = rrr_readfile_read(&script, &script_size, data->lua_file, 0, 0 /* Enoent not ok */)) != 0) {
		RRR_MSG_0("Error reading Lua script file %s in Lua instance %s\n",
			data->lua_file, INSTANCE_D_NAME(data->thread_data));
		goto out_cleanup_lua;
	}

	if ((ret = rrr_lua_execute_snippet(lua, script, rrr_size_from_biglength_bug_const(script_size))) != 0) {
		RRR_MSG_0("Error executing Lua script %s in Lua instance %s\n",
			data->lua_file, INSTANCE_D_NAME(data->thread_data));
		goto out_free_temp;
	}

	rrr_free(script);

	child_data.parent_data = data;
	child_data.lua = lua;
	child_data.cmodule_config_data = rrr_cmodule_helper_config_data_get(data->thread_data);
	child_data.start_time = rrr_time_get_64();
	callbacks->ping_callback_arg = &child_data;
	callbacks->configuration_callback_arg = &child_data;
	callbacks->process_callback_arg = &child_data;

	if ((ret = rrr_cmodule_worker_loop_start (
			worker,
			callbacks
	)) != 0) {
		RRR_MSG_0("Error from worker loop in %s\n", __func__);
		goto out_cleanup_lua;
	}

	goto out_cleanup_lua;
	out_free_temp:
		rrr_free(script);
	out_cleanup_lua:
		rrr_lua_destroy(lua);
	out:
		return ret;
}

static int lua_fork (void *arg) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct lua_data *data = thread_data->private_data;

	int ret = 0;

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_cmodule_helper_parse_config(thread_data, "lua", "function") != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_cmodule_helper_worker_forks_start_with_ping_callback (
			thread_data,
			lua_init_wrapper_callback,
			data,
			lua_ping_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			lua_configuration_callback,
			NULL, // <-- in the init wrapper, this callback arg is set to child_data
			lua_process_callback,
			NULL  // <-- in the init wrapper, this callback arg is set to child_data
	) != 0) {
		RRR_MSG_0("Error while starting Lua worker fork for instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int lua_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct lua_data *data = thread_data->private_data = thread_data->private_memory;

	data_init(data, thread_data);

	RRR_DBG_1("lua instance %s\n", INSTANCE_D_NAME(thread_data));

	if (rrr_thread_start_condition_helper_fork(thread, lua_fork, thread_data) != 0) {
		goto out_message;
	}

	RRR_DBG_1 ("lua instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	if (rrr_cmodule_helper_init (thread_data) != 0) {
		RRR_MSG_0("Failed to initialize cmodule in lua instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	return 0;

	out_message:
		data_cleanup(data);
		return 1;
}

static void lua_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct lua_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(strike);

	RRR_DBG_1 ("lua instance %s exiting\n", INSTANCE_D_NAME(thread_data));

	rrr_cmodule_helper_deinit(thread_data);

	data_cleanup(data);

	*deinit_complete = 1;
}

static const char *module_name = "lua";

void load (struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->event_functions = rrr_cmodule_helper_event_functions;
	data->init = lua_init;
	data->deinit = lua_deinit;
}

void unload (void) {
	RRR_DBG_1 ("Destroy Lua module\n");
}

