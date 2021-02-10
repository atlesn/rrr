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
#include "../lib/type.h"
#include "../lib/type_conversion.h"

struct mangler_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_map conversions_map;
	struct rrr_type_conversion_collection *conversions;

	int do_non_array_passthrough;
	int do_convert_tolerant_blobs;
	int do_convert_tolerant_strings;
};

static void mangler_data_init(struct mangler_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void mangler_data_cleanup(void *arg) {
	struct mangler_data *data = arg;
	RRR_MAP_CLEAR(&data->conversions_map);
	if (data->conversions != NULL) {
		rrr_type_conversion_collection_destroy(data->conversions);
	}
}

static int mangler_process_value (
		struct rrr_array *array_target,
		struct mangler_data *data,
		const struct rrr_type_value *value,
		const int convert_flags
) {
	int ret = 0;

	struct rrr_type_value *new_value = NULL;

	if ((ret = rrr_type_convert_using_list (
			&new_value,
			value,
			data->conversions,
			convert_flags
	)) != 0) {
		if (ret == RRR_TYPE_CONVERSION_NOT_POSSIBLE) {
			if ((ret = rrr_type_value_clone(&new_value, value, 1)) != 0) {
				RRR_MSG_0("Failed to clone value in mangler_process_value\n");
				goto out;
			}
		}
		else {
			goto out;
		}
	}

	RRR_LL_APPEND(array_target, new_value);
	new_value = NULL;

	out:
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
	return ret;
}

static int mangler_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct mangler_data *data = thread_data->private_data;

	(void)(source);

	int ret = 0;

	struct rrr_msg_msg *message_new = NULL;
	struct rrr_array array_from_message = {0};
	struct rrr_array array_new = {0};

	RRR_DBG_3("mangler instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(thread_data),
			(long long unsigned int) ((const struct rrr_msg_msg *) entry->message)->timestamp
	);

	if (!MSG_IS_ARRAY((const struct rrr_msg_msg *) entry->message)) {
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
	if ((ret = rrr_array_message_append_to_collection (
			&array_version_dummy,
			&array_from_message,
			(const struct rrr_msg_msg *) entry->message
	)) != 0) {
		RRR_MSG_0("Failed to get array values from message in mangler instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_drop;
	}

	const int convert_flags =
			RRR_TYPE_CONVERT_F_ON_ERROR_TRY_NEXT |
			(data->do_convert_tolerant_blobs ? 0 : RRR_TYPE_CONVERT_F_STRICT_BLOBS) |
			(data->do_convert_tolerant_strings ? 0 : RRR_TYPE_CONVERT_F_STRICT_STRINGS);

	int i = 0;
	RRR_LL_ITERATE_BEGIN(&array_from_message, const struct rrr_type_value);
		RRR_DBG_3("Mangler instance %s CONVERT idx %i type %s\n",
				INSTANCE_D_NAME(data->thread_data), i, node->definition->identifier);
		if ((ret = mangler_process_value (
				&array_new,
				data,
				node,
				convert_flags
		)) != 0) {
			RRR_MSG_0("mangler instance %s dropping message following error %i\n",
					INSTANCE_D_NAME(thread_data), ret);
			// Let only hard error propagate
			ret &= ~(1);
			goto out_drop;
		}
		i++;
	RRR_LL_ITERATE_END();

	if ((ret = rrr_array_new_message_from_collection (
			&message_new,
			&array_new,
			rrr_time_get_64(),
			MSG_TOPIC_PTR((const struct rrr_msg_msg *) entry->message),
			MSG_TOPIC_LENGTH((const struct rrr_msg_msg *) entry->message)
	)) != 0) {
		RRR_MSG_0("Failed to create array message in mangler_poll_callback\n");
		ret = 1;
		goto out_drop;
	}

	// Takes ownership of new message, old message pointer will be freed
	rrr_msg_holder_set_data_unlocked(entry, message_new, MSG_TOTAL_SIZE(message_new));
	message_new = NULL;

	out_write:
	ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER_ARGS(thread_data),
			entry,
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	);

	out_drop:
	rrr_array_clear(&array_new);
	rrr_array_clear(&array_from_message);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int mangler_parse_config (struct mangler_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mangler_non_array_passthrough", do_non_array_passthrough, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mangler_convert_tolerant_blobs", do_convert_tolerant_blobs, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mangler_convert_tolerant_strings", do_convert_tolerant_strings, 0);

	if  ((ret = rrr_instance_config_parse_comma_separated_to_map(&data->conversions_map, config, "mangler_conversions")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Failed to parse parameter 'mangler_conversions' of mangler instance %s\n",
					config->name);
			goto out;
		}
		ret = 0;
	}

	if ((ret = rrr_type_conversion_collection_new_from_map(&data->conversions, &data->conversions_map)) != 0) {
		RRR_MSG_0("Failed to parse parameter 'mangler_conversions' of mangler instance %s\n",
				config->name);
		goto out;
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

