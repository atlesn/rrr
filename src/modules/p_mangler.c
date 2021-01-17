/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/log.h"

#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/string_builder.h"
#include "../lib/map.h"

struct mangler_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_map convertions;
	int do_non_array_passthrough;
};

static void mangler_data_init(struct mangler_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void mangler_data_cleanup(void *arg) {
	struct mangler_data *data = arg;
	RRR_MAP_CLEAR(&data->convertions);
}

static int mangler_process_value (
		struct rrr_array *array_target,
		struct mangler_data *data,
		const struct rrr_type_value *value
) {
	int ret = 0;




	out:
	return ret;
}

static int mangler_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct mangler_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	struct rrr_array array_tmp = {0};

	RRR_DBG_3("mangler instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(thread_data),
			(long long unsigned int) message->timestamp
	);

	if (!MSG_IS_ARRAY(message)) {
		if (data->do_non_array_passthrough) {
			RRR_DBG_3("mangler instance %s passthrough of non-array message\n",
					INSTANCE_D_NAME(thread_data));
			goto out_write;
		}
		RRR_DBG_3("mangler instance %s dropping non-array message per configuration\n",
				INSTANCE_D_NAME(thread_data));
		goto out_drop;
	}

	uint16_t array_version_dummy;
	if ((ret = rrr_array_message_append_to_collection(&array_version_dummy, &array_tmp, message)) != 0) {
		RRR_MSG_0("Failed to get array values from message in mangler instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_drop;
	}

	RRR_LL_ITERATE_BEGIN(&array_tmp, const struct rrr_type_value);
		if ((ret = mangler_process_value (
				&array_tmp,
				data,
				node
		)) != 0) {
			RRR_MSG_0("Error while processing values in mangler instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_drop;
		}
	RRR_LL_ITERATE_END();

	out_write:
	ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER_ARGS(thread_data),
			entry
	);

	out_drop:
	rrr_array_clear(&array_tmp);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int mangler_parse_config (struct mangler_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mangler_non_array_passthrough", do_non_array_passthrough, 0);

	if  ((ret = rrr_instance_config_parse_comma_separated_to_map(&data->convertions, config, "manger_conversions")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Failed to parse setting 'mangler_conversions' of mangler instance %s\n",
					config->name);
			goto out;
		}
		ret = 0;
	}

	out:
	return ret;
}

static void *thread_entry_mangler (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mangler_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("mangler thread thread_data is %p\n", thread_data);

	mangler_data_init(data, thread_data);

	pthread_cleanup_push(mangler_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (mangler_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("mangler instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	while (rrr_thread_signal_encourage_stop_check(thread) != 1) {
		rrr_thread_watchdog_time_update(thread);

		if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, mangler_poll_callback, 50) != 0) {
			RRR_MSG_0("Error while polling in mangler instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}
	}

	out_message:
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread mangler %p exiting\n", thread);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mangler,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "mangler";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy mangler module\n");
}

