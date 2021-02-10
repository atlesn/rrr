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
//#include "../lib/string_builder.h"
#include "../lib/map.h"

struct incrementer_data {
	struct rrr_instance_runtime_data *thread_data;
	char *subject_topic;
	char *id_topic;
//	char *msgdb_socket;

	struct rrr_map db_all_ids;
	struct rrr_map db_used_ids;
};

static void incrementer_data_init(struct incrementer_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void incrementer_data_cleanup(void *arg) {
	struct incrementer_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->subject_topic);
	RRR_FREE_IF_NOT_NULL(data->id_topic);
//	RRR_FREE_IF_NOT_NULL(data->msgdb_socket);
	rrr_map_clear(&data->db_all_ids);
	rrr_map_clear(&data->db_used_ids);
}

static int incrementer_process_subject (
	struct incrementer_data *data,
	const struct rrr_msg_msg *message
) {
}

struct incrementer_process_id_callback_data {
	struct incrementer_data *data;
	struct rrr_map *target;
};

static int incrementer_process_id_callback (
		const struct rrr_type_value *value,
		void *arg
) {
	struct incrementer_process_id_callback_data *callback_data = arg;

	int ret = 0;

	if (value->tag_length == 0) {
		goto out;
	}

	unsigned long long int value_ull = value->definition->to_ull(value);
	char buf[64];
	sprintf(buf, "%llu", value_ull);

	if ((ret = rrr_map_item_add_new(callback_data->target, value->tag, buf)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static int incrementer_process_id (
	struct incrementer_data *data,
	const struct rrr_msg_msg *message
) {
	int ret = 0;

	struct rrr_map db_all_ids_new = {0};

	struct incrementer_process_id_callback_data callback_data = {
		data,
		&db_all_ids_new
	};

	if ((ret = rrr_array_message_iterate_values (message, incrementer_process_id_callback, &callback_data)) != 0) {
		goto out;
	}

	rrr_map_clear(&data->db_all_ids);
	RRR_MAP_MERGE_AND_CLEAR_SOURCE_HEAD(&data->db_all_ids, &db_all_ids_new);

	out:
	rrr_map_clear(&db_all_ids_new);
	return ret;
}

static int incrementer_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct incrementer_data *data = thread_data->private_data;
	const struct rrr_msg_msg *message = entry->message;

	(void)(source);
	(void)(data);

	int ret = 0;

	if (MSG_TOPIC_IS(message, data->subject_topic)) {
		ret = incrementer_process_subject(data, message);
		goto out;
	}

	if (MSG_TOPIC_IS(message, data->id_topic)) {
		ret = incrementer_process_id(data, message);
		goto out;
	}

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

/*

  7 [instance_incrementer]
    6 module=incrementer
      5 senders=instance_perl5_generator,instance_httpclient
        4 duplicate=yes
	  3 incrementer_msgdb_socket=/tmp/rrr-test-msgdb.sock
	    2 incrementer_subject_topic=rrr/increment
	      1 incrementer_id_topic=rrr/get-ids


*/

//	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("incrementer_msgdb_socket", msgdb_socket);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("incrementer_subject_topic", subject_topic);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("incrementer_id_topic", id_topic);

	if (data->id_topic == NULL || *(data->id_topic) == '\0') {
		RRR_MSG_0("Required parameter 'incrementer_id_topic' missing in incrementer instance %s\n",
			config->name);
		ret = 1;
		goto out;
	}

	if (data->subject_topic == NULL || *(data->id_topic) == '\0') {
		RRR_MSG_0("Required parameter 'incrementer_subject_topic' missing in incrementer instance %s\n",
			config->name);
		ret = 1;
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

		if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, incrementer_poll_callback, 50) != 0) {
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
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy incrementer module\n");
}

