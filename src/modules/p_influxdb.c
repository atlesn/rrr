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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/http_session.h"
#include "../lib/array.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/linked_list.h"
#include "../global.h"

#define INFLUXDB_DEFAULT_PORT 8086
#define INFLUXDB_USER_AGENT "RRR/" PACKAGE_VERSION

struct influxdb_column {
	RRR_LINKED_LIST_NODE(struct influxdb_column);
	char *input_tag;
	char *output_column;
};

struct influxdb_column_collection {
	RRR_LINKED_LIST_HEAD(struct influxdb_column);
};

static void __influxdb_column_destroy (struct influxdb_column *column) {
	RRR_FREE_IF_NOT_NULL(column->input_tag);
	RRR_FREE_IF_NOT_NULL(column->output_column);
	free(column);
}

static int __influxdb_column_new (struct influxdb_column **target, ssize_t field_size) {
	int ret = 0;

	struct influxdb_column *column = malloc(sizeof(*column));
	if (column == NULL) {
		VL_MSG_ERR("Could not allocate memory in influxdb __influxdb_column_new\n");
		ret = 1;
		goto out;
	}
	memset (column, '\0', sizeof(*column));

	column->input_tag = malloc(field_size);
	column->output_column = malloc(field_size);

	if (column->input_tag == NULL || column->output_column == NULL) {
		VL_MSG_ERR("Could not allocate memory in influxdb __influxdb_column_new\n");
		ret = 1;
		goto out;
	}

	memset(column->input_tag, '\0', field_size);
	memset(column->output_column, '\0', field_size);

	*target = column;
	column = NULL;

	out:
	if (column != NULL) {
		__influxdb_column_destroy(column);
	}
	return ret;
}

struct influxdb_data {
	struct instance_thread_data *thread_data;
	char *server;
	uint16_t server_port;
	char *table;
	int message_count;
	struct influxdb_column_collection columns;
};

void data_init(struct influxdb_data *data, struct instance_thread_data *thread_data) {
	memset (data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

void data_destroy (void *arg) {
	struct influxdb_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->table);
	RRR_LINKED_LIST_DESTROY(&data->columns, struct influxdb_column, __influxdb_column_destroy(node));
}

int send_data (struct influxdb_data *data, struct rrr_array *array) {
	struct rrr_http_session *session = NULL;

	int ret = 0;

	if ((ret = rrr_http_session_new (
			&session,
			RRR_HTTP_METHOD_POST,
			data->server,
			data->server_port,
			"/write",
			INFLUXDB_USER_AGENT
	)) != 0) {
		VL_MSG_ERR("Could not create HTTP session in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	RRR_LINKED_LIST_ITERATE_BEGIN(&data->columns, struct influxdb_column);
		struct rrr_type_value *value = rrr_array_value_get_by_tag(array, node->input_tag);
		if (value == NULL) {
			VL_MSG_ERR("Warning: Could not find value with tag %s in incoming message in influxdb instance %s, discarding message\n",
					node->input_tag, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (value->definition->type == RRR_TYPE_DEC) {
			ret = rrr_http_session_add_query_field (session, node->output_column, value->data);
		}
		else if (value->element_count > 1 || RRR_TYPE_IS_BLOB(value->definition->type)) {
			ret = rrr_http_session_add_query_field_binary (session, node->output_column, value->data, value->total_stored_length);
		}
		else if (RRR_TYPE_IS_64(value->definition->type)) {
			// TODO : Support signed
			char buf[64];
			sprintf(buf, "%" PRIu64, *((uint64_t*) value->data));
			ret = rrr_http_session_add_query_field (session, node->output_column, buf);
		}
		else {
			VL_MSG_ERR("Unknown value type %ul with tag %s when sending from influxdb instance %s, discarding message\n",
					value->definition->type, node->input_tag, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (ret != 0) {
			VL_MSG_ERR("Could not add query field in influxdb instance %s send data\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
	RRR_LINKED_LIST_ITERATE_END(&data->columns);

	RRR_LINKED_LIST_ITERATE_BEGIN(array, struct rrr_type_value);
	RRR_LINKED_LIST_ITERATE_END(array);

	if ((ret = rrr_http_session_connect(session)) != 0) {
		VL_MSG_ERR("Could not connect to influxdb server in instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	if (session != NULL) {
		rrr_http_session_destroy(session);
	}
	return ret;
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;

	struct rrr_array array = {0};

	VL_DEBUG_MSG_2 ("InfluxDB %s: Result from buffer: poll flags %u length %u timestamp from %" PRIu64 " measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), poll_data->flags, MSG_TOTAL_SIZE(reading), reading->timestamp_from, reading->data_numeric, size);

	if (!MSG_IS_ARRAY(reading)) {
		VL_MSG_ERR("Warning: Non-array message received in influxdb instance %s, discarding\n",
				INSTANCE_D_NAME(thread_data));
		goto discard;
	}

	if (rrr_array_message_to_collection(&array, reading) != 0) {
		VL_MSG_ERR("Error while parsing incoming array in influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto discard;
	}



	discard:
	rrr_array_clear(&array);
	free(data);
	return 0;
}

static int __parse_single_tag (const char *input, void *arg) {
	struct influxdb_data *data = arg;

	int ret = 0;
	struct influxdb_column *column = NULL;

	ssize_t input_length = strlen(input);

	if ((ret = __influxdb_column_new (&column, input_length + 1)) != 0) {
		goto out;
	}

	char *arrow = strstr(input, "->");
	if (arrow != NULL) {
		strncpy(column->input_tag, input, arrow - input);

		const char *pos = arrow + 2;
		if (*pos == '\0' || pos > (input + input_length)) {
			VL_MSG_ERR("Missing column name after -> in column definition\n");
			ret = 1;
			goto out;
		}

		strcpy(column->output_column, pos);
	}
	else {
		strcpy(column->input_tag, input);
		strcpy(column->output_column, input);
	}

	RRR_LINKED_LIST_APPEND(&data->columns, column);
	column = NULL;

	out:
	if (column != NULL) {
		__influxdb_column_destroy(column);
	}

	return ret;
}

int parse_tags (struct influxdb_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	if (rrr_settings_traverse_split_commas(config->settings, "influxdb_tags", __parse_single_tag, data) != 0) {
		VL_MSG_ERR("Error while parsing influxdb_tags of instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (RRR_LINKED_LIST_COUNT(&data->columns) == 0) {
		VL_MSG_ERR("No columns specified in influxdb_tags for instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int parse_config (struct influxdb_data *data, struct rrr_instance_config *config) {
	int ret = 0;
	int ret_final = 0;
//	int yesno = 0;

	rrr_setting_uint port = 0;

	rrr_instance_config_get_string_noconvert_silent (&data->server, config, "influxdb_server");
	rrr_instance_config_get_string_noconvert_silent (&data->table, config, "influxdb_table");

	if (data->server == NULL) {
		VL_MSG_ERR("No influxdb_server specified for instance %s\n", config->name);
		ret_final = 1;
	}

	if (data->table == NULL) {
		VL_MSG_ERR("No influxdb_table specified for instance %s\n", config->name);
		ret_final = 1;
	}

	if ((ret = rrr_instance_config_read_port_number (&port, config, "influxdb_port")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing server port in influxdb instance %s\n", config->name);
			ret_final = 1;
		}
	}
	if (port == 0) {
		port = INFLUXDB_DEFAULT_PORT;
	}

	if ((ret = parse_tags (data, config)) != 0) {
		ret_final = 1;
	}

	/* On error, memory is freed by data_cleanup */

	return ret_final;
}

static void *thread_entry_influxdb (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	data_init(influxdb_data, thread_data);

	VL_DEBUG_MSG_1 ("InfluxDB thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(thread_set_stopping, thread);
	pthread_cleanup_push(data_destroy, influxdb_data);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(influxdb_data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Error while parsing configuration for influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(
			&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_POLL_DELETE_IP
	) != 0) {
		VL_MSG_ERR("InfluxDB requires poll_delete or poll_delete_ip from senders\n");
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("InfluxDB started thread %p\n", thread_data);

	uint64_t timer_start = time_get_64();
	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_combined_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		uint64_t timer_now = time_get_64();
		if (timer_now - timer_start > 1000000) {
			timer_start = timer_now;

			VL_DEBUG_MSG_1("InfluxDB instance %s messages per second: %i\n",
					INSTANCE_D_NAME(thread_data), influxdb_data->message_count);

			influxdb_data->message_count = 0;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread influxdb %p instance %s exiting 1 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	VL_DEBUG_MSG_1 ("Thread influxdb %p instance %s exiting 2 state is %i\n", thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	VL_DEBUG_MSG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_influxdb,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "influxdb";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy influxdb module\n");
}

