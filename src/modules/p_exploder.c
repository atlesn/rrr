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
#include "../lib/allocator.h"

#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/helpers/string_builder.h"

struct exploder_data {
		struct rrr_instance_runtime_data *thread_data;
		int do_non_array_passthrough;
		int do_original_passthrough;
		int do_preserve_timestamp;
		int do_preserve_topic;
		int do_topic_append_tag;
		char *topic;
		uint16_t topic_len;
};

static void exploder_data_init(struct exploder_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void exploder_data_cleanup(void *arg) {
	struct exploder_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->topic);
}

static int exploder_process_value (
		struct exploder_data *data,
		const struct rrr_msg_holder *msg_holder_orig,
		const struct rrr_type_value *value,
		uint64_t timestamp,
		const struct rrr_string_builder *topic_prefix
) {
	// NOTE ! Do not write the original message to the buffer here, always clone it

	int ret = 0;

	struct rrr_msg_holder *entry_new = NULL;
	struct rrr_array array_new = {0};
	struct rrr_string_builder topic_tmp = {0};

	if ((ret = rrr_msg_holder_clone_no_data(&entry_new, msg_holder_orig)) != 0) {
		goto out;
	}

	rrr_msg_holder_lock(entry_new);

	const struct rrr_string_builder *topic_to_use;

	if (data->do_topic_append_tag && value->tag != NULL) {
		if ((ret = rrr_string_builder_append_from(&topic_tmp, topic_prefix)) != 0) {
			goto out;
		}
		if ((ret = rrr_string_builder_append(&topic_tmp, value->tag)) != 0) {
			goto out;
		}
		topic_to_use = &topic_tmp;
	}
	else {
		topic_to_use = topic_prefix;
	}

	{
		struct rrr_type_value *value_new = NULL;
		if ((ret = rrr_type_value_clone (
				&value_new,
				value,
				1 // Do clone data
		)) != 0) {
			goto out;
		}

		// Add to array immediately to manage memory
		RRR_LL_PUSH(&array_new, value_new);
		value_new = NULL;
	}

	{
		const rrr_biglength topic_length = rrr_string_builder_length(topic_to_use);
		if (topic_length > RRR_MSG_TOPIC_MAX) {
			RRR_MSG_0("Topic became too long in exploder instance %s (%" PRIrrrbl ">%llu)\n",
				INSTANCE_D_NAME(data->thread_data),
				topic_length,
				(unsigned long long) RRR_MSG_TOPIC_MAX
			);
			ret = 1;
			goto out;
		}

		struct rrr_msg_msg *msg_new = NULL;
		if ((ret = rrr_array_new_message_from_array (
				&msg_new,
				&array_new,
				timestamp,
				rrr_string_builder_buf(topic_to_use),
				(rrr_u16) topic_length
		)) != 0) {
			goto out;
		}

		// Add to message holder immediately to manage memory
		entry_new->message = msg_new;
		entry_new->data_length = MSG_TOTAL_SIZE(msg_new);
	}

	if ((ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			entry_new,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		goto out;
	}

	out:
	rrr_string_builder_clear(&topic_tmp);
	rrr_array_clear(&array_new);
	if (entry_new != NULL) {
		rrr_msg_holder_decref_while_locked_and_unlock(entry_new);
	}
	return ret;
}

static int exploder_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct exploder_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	struct rrr_string_builder topic_prefix = {0};
	struct rrr_array array_tmp = {0};

	RRR_DBG_3("exploder instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(thread_data),
			(long long unsigned int) message->timestamp
	);

	if (!MSG_IS_ARRAY(message)) {
		if (data->do_non_array_passthrough) {
			RRR_DBG_3("exploder instance %s passthrough of non-array message\n",
					INSTANCE_D_NAME(thread_data));
			goto out_write;
		}
		RRR_DBG_3("exploder instance %s dropping non-array message per configuration\n",
				INSTANCE_D_NAME(thread_data));
		goto out_drop;
	}

	uint16_t array_version_dummy;
	if ((ret = rrr_array_message_append_to_array(&array_version_dummy, &array_tmp, message)) != 0) {
		RRR_MSG_0("Failed to get array values from message in exploder instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_drop;
	}

	if (data->do_preserve_topic && MSG_TOPIC_LENGTH(message) > 0) {
		if ((ret = rrr_string_builder_append_raw(&topic_prefix, MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message))) != 0) {
			goto out_drop;
		}
	}

	if (data->topic != NULL && *(data->topic) != '\0') {
		if ((ret = rrr_string_builder_append(&topic_prefix, data->topic)) != 0) {
			goto out_drop;
		}
	}

	// Messages generated from one message should have equal timestamps
	const rrr_u64 timestamp = (data->do_preserve_timestamp ? message->timestamp : rrr_time_get_64());

	RRR_LL_ITERATE_BEGIN(&array_tmp, const struct rrr_type_value);
		if ((ret = exploder_process_value (
				data,
				entry,
				node,
				timestamp,
				&topic_prefix
		)) != 0) {
			RRR_MSG_0("Error while processing values in exploder instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_drop;
		}
	RRR_LL_ITERATE_END();

	if (!data->do_original_passthrough) {
		goto out_drop;
	}

	out_write:
	ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(thread_data),
			entry,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
	);

	out_drop:
	rrr_array_clear(&array_tmp);
	rrr_string_builder_clear(&topic_prefix);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int exploder_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	return rrr_poll_do_poll_delete (amount, thread_data, exploder_poll_callback);
}

static int exploder_parse_config (struct exploder_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("exploder_original_passthrough", do_original_passthrough, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("exploder_non_array_passthrough", do_non_array_passthrough, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("exploder_preserve_timestamp", do_preserve_timestamp, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("exploder_preserve_topic", do_preserve_topic, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("exploder_topic_append_tag", do_topic_append_tag, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("exploder_topic", topic, topic_len);

	out:
	return ret;
}

static void *thread_entry_exploder (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct exploder_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("exploder thread thread_data is %p\n", thread_data);

	exploder_data_init(data, thread_data);

	pthread_cleanup_push(exploder_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (exploder_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("exploder instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_message:
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread exploder %p exiting\n", thread);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_exploder,
		NULL,
		NULL
};

struct rrr_instance_event_functions event_functions = {
	exploder_event_broker_data_available
};

static const char *module_name = "exploder";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy exploder module\n");
}

