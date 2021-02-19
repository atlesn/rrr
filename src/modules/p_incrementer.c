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

#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/string_builder.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/map.h"
#include "../lib/mqtt/mqtt_topic.h"
#include "../lib/msgdb/msgdb_client.h"
#include "../lib/util/increment.h"

struct incrementer_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_msgdb_client_conn msgdb_conn;

	char *subject_topic_filter;
	struct rrr_mqtt_topic_token *subject_topic_filter_token;

	char *id_tag;
	char *msgdb_socket;

	rrr_setting_uint id_min;
	rrr_setting_uint id_max;
	rrr_setting_uint id_modulus;
	rrr_setting_uint id_position;

	struct rrr_map db_initial_ids;
	struct rrr_map db_used_ids;
};

static void incrementer_data_init(struct incrementer_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void incrementer_data_cleanup(void *arg) {
	struct incrementer_data *data = arg;
	rrr_msgdb_client_close(&data->msgdb_conn);
	RRR_FREE_IF_NOT_NULL(data->subject_topic_filter);
	rrr_mqtt_topic_token_destroy(data->subject_topic_filter_token);
	RRR_FREE_IF_NOT_NULL(data->id_tag);
	RRR_FREE_IF_NOT_NULL(data->msgdb_socket);
	rrr_map_clear(&data->db_initial_ids);
	rrr_map_clear(&data->db_used_ids);
}

struct incrementer_get_id_from_msgdb_callback_data {
	unsigned long long int *result;
	const char *tag;
};

static int incrementer_get_id_from_msgdb_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct incrementer_get_id_from_msgdb_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_array array_tmp = {0};
	struct rrr_msg_msg *msg_tmp = NULL;

	*(callback_data->result) = 0;

	if ((ret = rrr_msgdb_client_cmd_get(&msg_tmp, conn, callback_data->tag))) {
		goto out;
	}

	if (msg_tmp != NULL) {
		uint16_t version_dummy;
		if ((ret = rrr_array_message_append_to_collection(&version_dummy, &array_tmp, msg_tmp)) != 0) {
			RRR_MSG_0("Failed to extract array from message from message DB in incrementer_get_id_from_msgdb_callback\n");
			goto out;
		}
		const struct rrr_type_value *value;
		if ((value = rrr_array_value_get_by_tag_const (&array_tmp, "id")) == NULL) {
			RRR_MSG_0("Failed to find value with tag 'id' in message from message DB in incrementer_get_id_from_msgdb_callback\n");
			ret = 1;
			goto out;
		}
		*(callback_data->result) = value->definition->to_ull(value);
	}

	out:
	rrr_array_clear(&array_tmp);
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	return ret;
}

static int incrementer_get_id_from_msgdb (
		unsigned long long int *result_llu,
		struct incrementer_data *data,
		const char *tag
) {
	int ret = 0;

	struct incrementer_get_id_from_msgdb_callback_data callback_data = {
		result_llu,
		tag
	};

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			&data->msgdb_conn,
			data->msgdb_socket,
			incrementer_get_id_from_msgdb_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Failed to get message from  message DB in incrementer_get_id_from_msgdb\n");
		goto out;
	}

	out:
	return ret;
}

static int incrementer_get_id (
	unsigned long long int *result_llu,
	struct incrementer_data *data,
	const char *tag
) {
	int ret = 0;

	*result_llu = 0;

	RRR_DBG_3("Incrementer instance %s retrieving ID for tag '%s'...\n",
			INSTANCE_D_NAME(data->thread_data), tag);

	const char *result = NULL;
	if ((result = rrr_map_get_value(&data->db_used_ids, tag)) == NULL) {
		if ((ret = incrementer_get_id_from_msgdb(result_llu, data, tag)) != 0) {
			goto out;
		}
		if (*result_llu != 0) {
			RRR_DBG_3("=> Result from Message DB: %llu\n", *result_llu);
			goto out;
		}
		if ((result = rrr_map_get_value(&data->db_initial_ids, tag)) == NULL) {
			RRR_DBG_3("=> No result\n");
			goto out;
		}
		RRR_DBG_3("=> Result from unused ID initializer memory storage: %s\n", result);
	}
	else {
		RRR_DBG_3("=> Result from used ID memory storage: %s\n", result);
	}

	char *end = NULL;
	*result_llu = strtoull(result, &end, 10);
	if (end == NULL || *end != '\0') {
		RRR_MSG_0("Failed to parse stored ID in incrementer_get_id, value was '%s'\n",
			result);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int incrementer_update_id_msgdb_callback (
		struct rrr_msgdb_client_conn *conn,
		void *arg
) {
	struct rrr_msg_msg *msg = arg;

	int ret = 0;

	MSG_SET_TYPE(msg, MSG_TYPE_PUT);

	if ((ret = rrr_msgdb_client_send(conn, msg)) != 0) {	
		RRR_DBG_7("Failed to send message to msgdb in incrementer_udpate_id_msgdb_callback, return from send was %i\n",
			ret);
		goto out;
	}

	int positive_ack = 0;
	if ((ret = rrr_msgdb_client_await_ack(&positive_ack, conn)) != 0 || positive_ack == 0) {
		RRR_DBG_7("Failed to send message to msgdb in incrementer_update_id_msgdb_callback, return from await ack was %i positive ack was %i\n",
			ret, positive_ack);
		ret = 1; // Ensure failure is returned upon negative ACK
		goto out;
	}

	out:
	return ret;
}

struct incrementer_update_id_callback_data {
	struct incrementer_data *data;
	long long unsigned int id;
	const char *tag;
};

static int incrementer_update_id_callback (
	void *arg
) {
	struct incrementer_update_id_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_array array_tmp = {0};
	struct rrr_msg_msg *msg_tmp = NULL;

	if (callback_data->data->msgdb_socket == NULL) {
		goto out;
	}

	if ((ret = rrr_array_push_value_u64_with_tag(&array_tmp, "id", callback_data->id)) != 0) {
		RRR_MSG_0("Failed push ID to array in incrementer_update_id_callback\n");
		goto out;
	}

	if ((ret = rrr_array_new_message_from_collection (
			&msg_tmp,
			&array_tmp,
			rrr_time_get_64(),
			callback_data->tag,
			strlen(callback_data->tag)
	)) != 0) {
		RRR_MSG_0("Failed create new message in incrementer_update_id_callback\n");
		goto out;
	}

	if ((ret = rrr_msgdb_client_conn_ensure_with_callback (
			&callback_data->data->msgdb_conn,
			callback_data->data->msgdb_socket,
			incrementer_update_id_msgdb_callback,
			msg_tmp
	)) != 0) {
		RRR_MSG_0("Failed to send message to message DB in incrementer_update_id_callback\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int incrementer_update_id (
		struct incrementer_data *data,
		const char *tag,
		unsigned long long id
) {
	char buf[64];
	sprintf(buf, "%llu", id);

	struct incrementer_update_id_callback_data callback_data = {
		data,
		id,
		tag
	};

	// This structure ensures that ID is either updated in both map and msgdb
	// or in none of them. If msgdb is disabled, only map will get updated.
	return rrr_map_item_replace_new_with_callback (
			&data->db_used_ids,
			tag,
			buf,
			incrementer_update_id_callback,
			&callback_data
	);
}

static int incrementer_process_subject (
		struct incrementer_data *data,
		struct rrr_msg_holder *entry
) {
	// Do not cache message pointer from entry, it gets updated

	int ret = 0;

	char *topic_tmp = NULL;
	struct rrr_string_builder topic_new = {0};

	if ((ret = rrr_msg_msg_topic_get(&topic_tmp, (struct rrr_msg_msg *) entry->message)) != 0) {
		RRR_MSG_0("Failed to get topic in incrementer_process_subject\n");
		goto out;
	}

	unsigned long long old_id_llu = 0;

	if ((ret = incrementer_get_id(&old_id_llu, data, topic_tmp)) != 0) {
		goto out;
	}

	if (old_id_llu == 0) {
		// TODO : Error if id initializer topic is set
/*		RRR_MSG_0("No ID stored for subject with topic %s in incrementer instance %s\n",
			topic_tmp, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;*/
		RRR_DBG_2("Incrementer instance %s starting ID for tag %s at 0, not previously stored\n",
			INSTANCE_D_NAME(data->thread_data), topic_tmp);
	}

	unsigned long long new_id_llu = rrr_increment_mod(old_id_llu, data->id_modulus, data->id_min, data->id_max, data->id_position);

	if ((ret = rrr_string_builder_append_format(&topic_new, "%s/%llu", topic_tmp, new_id_llu)) != 0) {
		RRR_MSG_0("Failed to allocate new topic in incrementer_process_subject\n");
		goto out;
	}

	if ((ret = rrr_msg_msg_topic_set (
			(struct rrr_msg_msg **) &entry->message,
			rrr_string_builder_buf(&topic_new),
			rrr_string_builder_length(&topic_new)
	)) != 0) {
		RRR_MSG_0("Failed to set topic of message in incrementer_process_subject\n");
		goto out;
	}

	entry->data_length = MSG_TOTAL_SIZE((struct rrr_msg_msg *) entry->message);

	if ((ret = incrementer_update_id(data, topic_tmp, new_id_llu)) != 0) {
		RRR_MSG_0("Failed to store ID of message in incrementer_process_subject\n");
		goto out;
	}

	RRR_DBG_2("incrementer instance %s translate topic of message with timestamp %" PRIu64 " from %s to %s\n",
		INSTANCE_D_NAME(data->thread_data), ((struct rrr_msg_msg *) entry->message)->timestamp, topic_tmp, rrr_string_builder_buf(&topic_new));

	if ((ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER_ARGS(data->thread_data), 
			entry,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Failed to write entry in incrementer_process_subject of instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	rrr_string_builder_clear(&topic_new);
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	return ret;
}

static int incrementer_process_id (
		struct incrementer_data *data,
		const struct rrr_msg_holder *entry
) {
	int ret = 0;

	struct rrr_array array_tmp = {0};
	char *topic_tmp = NULL;

	if ((ret = rrr_msg_msg_topic_get (&topic_tmp, (const struct rrr_msg_msg *) entry->message)) != 0) {
		goto out;
	}

	uint16_t array_version_dummy;
	if ((ret = rrr_array_message_append_to_collection (
			&array_version_dummy,
			&array_tmp,
			(const struct rrr_msg_msg *) entry->message
	)) != 0) {
		goto out;
	}

	const struct rrr_type_value *value = rrr_array_value_get_by_tag_const (&array_tmp, data->id_tag);
	if (value == NULL) {
		RRR_BUG("BUG: Value not found in incrementer_process_id, caller must check for this\n");
	}

	long long unsigned id = value->definition->to_ull(value);

	char buf[64];
	sprintf(buf, "%llu", id);

	if ((ret = rrr_map_item_replace_new(&data->db_initial_ids, topic_tmp, buf)) != 0) {
		goto out;
	}

	RRR_DBG_3("Incrementer instance %s set initial ID of topic %s to %llu\n",
			INSTANCE_D_NAME(data->thread_data), topic_tmp, id);

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	rrr_array_clear(&array_tmp);
	return ret;
}

static int incrementer_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct incrementer_data *data = thread_data->private_data;

	int ret = 0;

	// We check stuff with the watchdog in case we are slow to process messages
	if (rrr_thread_signal_encourage_stop_check(INSTANCE_D_THREAD(data->thread_data))) {
		ret = RRR_FIFO_SEARCH_STOP;
		goto out;
	}
	rrr_thread_watchdog_time_update(INSTANCE_D_THREAD(data->thread_data));

	// Do not produce errors for message process failures, just drop them

	int does_match = 0;
	if (rrr_msg_msg_topic_match(&does_match, (const struct rrr_msg_msg *) entry->message, data->subject_topic_filter_token) != 0) {
		RRR_MSG_0("Error while checking subject topic in incrementer_poll_callback of instance %s, dropping message\n",
			INSTANCE_D_NAME(thread_data));
		goto out;
	}
	else if (!does_match) {
		goto out_forward;
	}

	if (data->id_tag != NULL && rrr_array_message_has_tag((const struct rrr_msg_msg *) entry->message, data->id_tag)) {
		if (incrementer_process_id(data, entry) != 0) {
			RRR_MSG_0("Warning: Failed to store initial ID in incrementer instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		}
	}
	else if (incrementer_process_subject(data, entry) != 0) {
		RRR_MSG_0("Warning: Failed to apply ID to message in incrementer instance %s, dropping it\n",
			INSTANCE_D_NAME(data->thread_data));
	}

	goto out;
	out_forward:
		RRR_DBG_3("Incrementer instance %s forwarding message with timestamp %" PRIu64 " without processing\n",
			INSTANCE_D_NAME(data->thread_data), ((const struct rrr_msg_msg *) entry->message)->timestamp);

		// Unknown message, forward to output
		if ((ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
				INSTANCE_D_BROKER_ARGS(data->thread_data),
				entry,
				INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
		)) != 0) {
			goto out;
		}

	out:
		rrr_msg_holder_unlock(entry);
		return ret;
}

static int incrementer_parse_config (struct incrementer_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("incrementer_msgdb_socket", msgdb_socket);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("incrementer_subject_topic_filter", subject_topic_filter);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("incrementer_id_tag", id_tag);

	if (data->subject_topic_filter == NULL || *(data->subject_topic_filter) == '\0') {
		RRR_MSG_0("Required parameter 'incrementer_subject_topic_filter' missing in incrementer instance %s\n",
			config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_mqtt_topic_tokenize (&data->subject_topic_filter_token, data->subject_topic_filter)) != 0) {
		RRR_MSG_0("Failed to parse parameter 'incrementer_subject_topic_filter' in incrementer instance %s\n",
			config->name);
		ret = 1;
		goto out;
		
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("incrementer_id_min", id_min, 1);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("incrementer_id_max", id_max, 0xffffffff);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("incrementer_id_modulus", id_modulus, 1);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("incrementer_id_position", id_position, 0);

	if ((ret = rrr_increment_verify (data->id_modulus, data->id_min, data->id_max, data->id_position)) != 0) {
		RRR_MSG_0("Invalid ID parameters in incrementer instance %s\n",
				config->name);
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_incrementer (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct incrementer_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("incrementer thread thread_data is %p\n", thread_data);

	incrementer_data_init(data, thread_data);

	pthread_cleanup_push(incrementer_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (incrementer_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("incrementer instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	while (rrr_thread_signal_encourage_stop_check(thread) != 1) {
		rrr_thread_watchdog_time_update(thread);

		uint16_t amount = 100;
		if (rrr_poll_do_poll_delete (&amount, thread_data, incrementer_poll_callback, 50) != 0) {
			RRR_MSG_0("Error while polling in incrementer instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}
	}

	out_message:
	pthread_cleanup_pop(1);

	RRR_DBG_1 ("Thread incrementer %p exiting\n", thread);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_incrementer,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "incrementer";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
}

void unload(void) {
	RRR_DBG_1 ("Destroy incrementer module\n");
}

