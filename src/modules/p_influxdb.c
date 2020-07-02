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

#include "../lib/http/http_session.h"
#include "../lib/array.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/fixed_point.h"
#include "../lib/linked_list.h"
#include "../lib/gnu.h"
#include "../lib/map.h"
#include "../lib/string_builder.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/message_broker.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/log.h"

#define INFLUXDB_DEFAULT_PORT 8086
#define INFLUXDB_USER_AGENT "RRR/" PACKAGE_VERSION

#define INFLUXDB_OK		  0
#define INFLUXDB_HARD_ERR 1
#define INFLUXDB_SOFT_ERR 2

struct influxdb_data {
	struct rrr_instance_thread_data *thread_data;
	char *server;
	uint16_t server_port;
	char *database;
	char *table;
	int message_count;
	struct rrr_map tags;
	struct rrr_map fields;
	struct rrr_map fixed_tags;
	struct rrr_map fixed_fields;
	struct rrr_ip_buffer_entry_collection error_buf;
	struct rrr_net_transport *transport;
};

int data_init(struct influxdb_data *data, struct rrr_instance_thread_data *thread_data) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	if (rrr_net_transport_new(&data->transport, RRR_NET_TRANSPORT_PLAIN, 0, NULL, NULL, NULL, NULL) != 0) {
		RRR_MSG_0("Could not create transport in influxdb data_init\n");
		ret = 1;
		goto out;
	}

	data->thread_data = thread_data;

	rrr_map_init(&data->tags);
	rrr_map_init(&data->fields);
	rrr_map_init(&data->fixed_tags);
	rrr_map_init(&data->fixed_fields);

	goto out;
	out:
		return ret;
}

void data_destroy (void *arg) {
	struct influxdb_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->database);
	RRR_FREE_IF_NOT_NULL(data->table);
	rrr_map_clear(&data->tags);
	rrr_map_clear(&data->fields);
	rrr_map_clear(&data->fixed_tags);
	rrr_map_clear(&data->fixed_fields);
	rrr_ip_buffer_entry_collection_clear(&data->error_buf);
	if (data->transport != NULL) {
		rrr_net_transport_destroy(data->transport);
	}
}

static int __escape_field (char **target, const char *source, ssize_t length, int add_double_quotes) {
	ssize_t new_size = length * 2 + 1 + 2;

	*target = NULL;

	char *result = malloc(new_size);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in influxdb escape_field\n");
		return 1;
	}

	char *wpos = result;

	if (add_double_quotes != 0) {
		*(wpos++) = '"';
	}

	for (ssize_t i = 0; i < length; i++) {
		char c = *(source + i);
		if (c == '"' || (add_double_quotes == 0 && (c == ',' || c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n'))) {
			*(wpos++) = '\\';
		}
		*(wpos++) = c;
	}

	if (add_double_quotes != 0) {
		*(wpos++) = '"';
	}

	*wpos = '\0';

	*target = result;

	return 0;
}

static int __query_append_values_from_array (
		struct rrr_string_builder *string_builder,
		struct rrr_map *columns,
		struct rrr_array *array,
		int no_comma_on_first
) {
	int ret = INFLUXDB_OK;

	char *name_tmp = NULL;
	char *value_tmp = NULL;

	int first = 1;

	char buf[512];
	memset(buf, '\0', 511); // Valgrind moans about conditional jumps on uninitialized bytes

	if (array->version != 6) {
		RRR_BUG("Array version mismatch in InfluxDB __query_append_values_from_array (%u vs %i), module must be updated\n",
				array->version, 6);
	}

	RRR_MAP_ITERATE_BEGIN(columns);
		struct rrr_type_value *value = rrr_array_value_get_by_tag(array, node_tag);
		if (value == NULL) {
			RRR_MSG_0("Warning: Could not find value with tag %s in incoming message, discarding message\n",
					node->tag);
			ret = INFLUXDB_SOFT_ERR;
			goto out;
		}

		if (value->element_count > 1) {
			RRR_MSG_0("Warning: Received message with array of value with tag %s in, discarding message\n",
					node->tag);
			ret = INFLUXDB_SOFT_ERR;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(name_tmp);
		RRR_FREE_IF_NOT_NULL(value_tmp);

		if (*node_value != '\0') {
			ret = __escape_field(&name_tmp, node_value, strlen(node_value), 0);
		}
		else {
			ret = __escape_field(&name_tmp, node->tag, strlen(node_tag), 0);
		}
		if (ret != 0) {
			RRR_MSG_0("Could not escape field in influxdb __query_append_values_from_array\n");
			ret = INFLUXDB_HARD_ERR;
			goto out;
		}

		if (no_comma_on_first == 0 || first == 0) {
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, ",", "Could not append comma to query buffer in influxdb __query_append_values_from_array\n");
		}
		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, name_tmp, "Could not append name to query buffer in influxdb __query_append_values_from_array\n");
		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, "=", "Could not append equal sign to query buffer in influxdb __query_append_values_from_array\n");

		if (RRR_TYPE_IS_FIXP(value->definition->type)) {
			if ((ret = rrr_fixp_to_str(buf, 511, *((rrr_fixp*) value->data))) != 0) {
				RRR_MSG_0("Could not convert fixed point to string for value with tag %s in influxdb __query_append_values_from_array\n",
						node->tag);
				ret = INFLUXDB_SOFT_ERR;
				goto out;
			}

			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, buf, "Could not append fixed point to query buffer in influxdb __query_append_values_from_array\n");
		}
		else if (RRR_TYPE_IS_64(value->definition->type)) {
			// TODO : Support signed
			char buf[64];
			if (RRR_TYPE_FLAG_IS_SIGNED(value->flags)) {
				sprintf(buf, "%" PRIi64, *((int64_t*) value->data));
			}
			else {
				sprintf(buf, "%" PRIu64, *((uint64_t*) value->data));
			}
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, buf, "Could not append 64 type to query buffer in influxdb __query_append_values_from_array\n");
		}
		else if (RRR_TYPE_IS_BLOB(value->definition->type)) {
			if (__escape_field(&value_tmp, value->data, value->total_stored_length, 1) != 0) {
				RRR_MSG_0("Could not escape blob field in influxdb __query_append_values_from_array\n");
				ret = INFLUXDB_HARD_ERR;
				goto out;
			}
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, value_tmp, "Could not append blob type to query buffer in influxdb __query_append_values_from_array\n");
		}
		else {
			RRR_MSG_0("Unknown value type %ul with tag %s when sending from influxdb, discarding message\n",
					value->definition->type, node->tag);
			ret = INFLUXDB_SOFT_ERR;
			goto out;
		}

		first = 0;
	RRR_MAP_ITERATE_END();

	out:
	RRR_FREE_IF_NOT_NULL(name_tmp);
	RRR_FREE_IF_NOT_NULL(value_tmp);
	return ret;
}

static int __query_append_values (
		struct rrr_string_builder *string_builder,
		struct rrr_map *columns,
		int no_comma_on_first
) {
	int ret = INFLUXDB_OK;

	char *name_tmp = NULL;
	char *value_tmp = NULL;

	int first = 1;

	RRR_MAP_ITERATE_BEGIN(columns);
		RRR_FREE_IF_NOT_NULL(name_tmp);
		RRR_FREE_IF_NOT_NULL(value_tmp);

		if (__escape_field(&name_tmp, node_tag, strlen(node_tag), 0) != 0) {
			RRR_MSG_0("Could not escape field in influxdb __query_append_values\n");
			ret = INFLUXDB_HARD_ERR;
			goto out;
		}

		if (no_comma_on_first == 0 || first == 0) {
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, ",", "Could not append comma to query buffer in influxdb __query_append_values\n");
		}
		RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, name_tmp, "Could not append name to query buffer in influxdb __query_append_values\n");

		if (*node_value != '\0') {
			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, "=", "Could not append equal sign to query buffer in influxdb __query_append_values\n");

			if (__escape_field(&value_tmp, node_value, strlen(node_value), 0) != 0) {
				RRR_MSG_0("Could not escape field in influxdb __query_append_values\n");
				ret = INFLUXDB_HARD_ERR;
				goto out;
			}

			RRR_STRING_BUILDER_APPEND_AND_CHECK(string_builder, value_tmp, "Could not append blob type to query buffer in influxdb __query_append_values\n");
		}

		first = 0;
	RRR_MAP_ITERATE_END();

	out:
	RRR_FREE_IF_NOT_NULL(name_tmp);
	RRR_FREE_IF_NOT_NULL(value_tmp);
	return ret;
}

#define CHECK_RET()																			\
		do {if (ret != 0) {																	\
			if (ret == INFLUXDB_SOFT_ERR) {													\
				RRR_MSG_0("Soft error in influxdb instance %s, discarding message\n",		\
					INSTANCE_D_NAME(data->thread_data));									\
				ret = 0;																	\
				goto out;																	\
			}																				\
			RRR_MSG_0("Hard error in influxdb instance %s\n",								\
				INSTANCE_D_NAME(data->thread_data));										\
			ret = 1;																		\
			goto out;																		\
		}} while(0)


struct response_callback_data {
	struct influxdb_data *data;
	int save_ok;
};

static int __receive_http_response (struct rrr_http_part *part, const char *data_ptr, void *arg) {
	struct response_callback_data *data = arg;

	int ret = 0;

	// TODO : Read error message from JSON

	if (part->response_code < 200 || part->response_code > 299) {
		RRR_MSG_0("HTTP error from influxdb in instance %s: %i %s\n",
				INSTANCE_D_NAME(data->data->thread_data), part->response_code, part->response_str);
		ret = 1;
		goto out;
	}

	data->save_ok = 1;

	out:
	return ret;
}

struct send_data_callback_data {
	struct influxdb_data *data;
	struct rrr_array *array;
	int ret;
};

static void __send_data_callback (struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg) {
	struct send_data_callback_data *callback_data = arg;

	(void)(sockaddr);
	(void)(socklen);

	struct influxdb_data *data = callback_data->data;
	struct rrr_array *array = callback_data->array;

	int ret = INFLUXDB_OK;

	struct rrr_string_builder string_builder = {0};

	char *uri = NULL;
	if ((ret = rrr_asprintf(&uri, "/write?db=%s", data->database)) <= 0) {
		RRR_MSG_0("Error while creating URI in send_data of influxdb instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_client_new (
			handle,
			RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING,
			uri,
			INFLUXDB_USER_AGENT
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	// Append table name
	RRR_STRING_BUILDER_APPEND_AND_CHECK(&string_builder, data->table, "Could not append table name in influxdb send_data\n");

	// Append tags from array
	ret = __query_append_values_from_array(&string_builder, &data->tags, array, 0);
	CHECK_RET();

	// Append fixed tags from config
	ret = __query_append_values(&string_builder, &data->fixed_tags, 0);
	CHECK_RET();

	// Append separator
	RRR_STRING_BUILDER_APPEND_AND_CHECK(&string_builder, " ", "Could not append space in influxdb send_data\n");

	// Append fields from array
	ret = __query_append_values_from_array(&string_builder, &data->fields, array, 1);
	CHECK_RET();

	// Append fixed fields from config
	ret = __query_append_values(&string_builder, &data->fixed_fields,  RRR_LL_COUNT(&data->fields) == 0);
	CHECK_RET();

	// TODO : Better distingushing of soft/hard errors from HTTP layer

	if ((ret = rrr_http_session_transport_ctx_add_query_field(handle, NULL, string_builder.buf)) != 0) {
		RRR_MSG_0("Could not add data to HTTP query in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_send_request(handle, data->server)) != 0) {
		RRR_MSG_0("Could not send HTTP request in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	struct response_callback_data response_callback_data = {
			data, 0
	};

	if (rrr_http_session_transport_ctx_receive(handle, __receive_http_response, &response_callback_data) != 0) {
		RRR_MSG_0("Could not receive HTTP response in influxdb instance %sd\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = INFLUXDB_HARD_ERR;
		goto out;
	}

	if (response_callback_data.save_ok != 1) {
		RRR_MSG_0("Warning: Error in HTTP response in influxdb instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = INFLUXDB_SOFT_ERR;
		goto out;
	}

	out:
	rrr_string_builder_clear(&string_builder);
	RRR_FREE_IF_NOT_NULL(uri);
	callback_data->ret = ret;
}

static int send_data (struct influxdb_data *data, struct rrr_array *array) {
	struct send_data_callback_data callback_data = {
			data,
			array,
			0
	};

	int ret = 0;

	ret |= rrr_net_transport_connect_and_close_after_callback (
			data->transport,
			data->server_port,
			data->server,
			__send_data_callback,
			&callback_data
	);
	ret |= callback_data.ret;

	return ret;
}

static int common_callback(struct rrr_ip_buffer_entry *entry, struct influxdb_data *influxdb_data) {
	struct rrr_message *reading = entry->message;

	int ret = 0;

	struct rrr_array array = {0};

	RRR_DBG_2 ("InfluxDB %s: Result from buffer: length %u timestamp from %" PRIu64 "\n",
			INSTANCE_D_NAME(influxdb_data->thread_data), MSG_TOTAL_SIZE(reading), reading->timestamp);

	if (!MSG_IS_ARRAY(reading)) {
		RRR_MSG_0("Warning: Non-array message received in influxdb instance %s, discarding\n",
				INSTANCE_D_NAME(influxdb_data->thread_data));
		ret = 0;
		goto discard;
	}

	if (rrr_array_message_to_collection(&array, reading) != 0) {
		RRR_MSG_0("Error while parsing incoming array in influxdb instance %s\n",
				INSTANCE_D_NAME(influxdb_data->thread_data));
		ret = 0;
		goto discard;
	}

	ret = send_data(influxdb_data, &array);
	if (ret != 0) {
		if (ret == INFLUXDB_SOFT_ERR) {
			RRR_MSG_0("Storing message with error in buffer for later retry in influxdb instance %s\n",
					INSTANCE_D_NAME(influxdb_data->thread_data));

			rrr_ip_buffer_entry_incref_while_locked(entry);
			RRR_LL_APPEND(&influxdb_data->error_buf, entry);
			ret = 0;
			goto discard;
		}
		RRR_MSG_0("Hard error from send_data in influxdb instance %s\n",
				INSTANCE_D_NAME(influxdb_data->thread_data));
		ret = 1;
		goto discard;
	}

	discard:
	rrr_array_clear(&array);
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static int poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	return common_callback(entry, thread_data->private_data);
}

int parse_tags (struct influxdb_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, "influxdb_tags", rrr_map_parse_pair_arrow, &data->tags)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing influxdb_tags of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, "influxdb_fields", rrr_map_parse_pair_arrow, &data->fields)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing influxdb_fields of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, "influxdb_fixed_tags", rrr_map_parse_pair_equal, &data->fixed_tags)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing influxdb_fixed_tags of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, "influxdb_fixed_fields", rrr_map_parse_pair_equal, &data->fixed_fields)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing influxdb_fixed_fields of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	if (RRR_LL_COUNT(&data->fields) == 0 && RRR_LL_COUNT(&data->fixed_fields) == 0) {
		RRR_MSG_0("No fields specified in config for influxdb instance %s\n", config->name);
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
	rrr_instance_config_get_string_noconvert_silent (&data->database, config, "influxdb_database");
	rrr_instance_config_get_string_noconvert_silent (&data->table, config, "influxdb_table");

	if (data->server == NULL) {
		RRR_MSG_0("No influxdb_server specified for instance %s\n", config->name);
		ret_final = 1;
	}

	if (data->database == NULL) {
		RRR_MSG_0("No influxdb_database specified for instance %s\n", config->name);
		ret_final = 1;
	}

	if (data->table == NULL) {
		RRR_MSG_0("No influxdb_table specified for instance %s\n", config->name);
		ret_final = 1;
	}

	if ((ret = rrr_instance_config_read_port_number (&port, config, "influxdb_port")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing server port in influxdb instance %s\n", config->name);
			ret_final = 1;
		}
	}
	if (port == 0) {
		port = INFLUXDB_DEFAULT_PORT;
	}

	data->server_port = port;

	if ((ret = parse_tags (data, config)) != 0) {
		ret_final = 1;
	}

	/* On error, memory is freed by data_cleanup */

	return ret_final;
}

static void *thread_entry_influxdb (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data = thread_data->private_memory;
	struct rrr_ip_buffer_entry_collection error_buf_tmp = {0};

	if (data_init(influxdb_data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_exit;
	}

	RRR_DBG_1 ("InfluxDB thread data is %p\n", thread_data);

	pthread_cleanup_push(data_destroy, influxdb_data);
	pthread_cleanup_push(rrr_ip_buffer_entry_collection_clear_void, &error_buf_tmp);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(influxdb_data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Error while parsing configuration for influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_poll_add_from_thread_senders (thread_data->poll, thread_data);

	RRR_DBG_1 ("InfluxDB started thread %p\n", thread_data);

	uint64_t timer_start = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		if (rrr_poll_do_poll_delete (thread_data, thread_data->poll, poll_callback, 50) != 0) {
			RRR_MSG_ERR("Error while polling in influxdb instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		uint64_t timer_now = rrr_time_get_64();
		if (timer_now - timer_start > 1000000) {
			timer_start = timer_now;

			RRR_DBG_1("InfluxDB instance %s messages per second: %i\n",
					INSTANCE_D_NAME(thread_data), influxdb_data->message_count);

			influxdb_data->message_count = 0;

			RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&error_buf_tmp, &influxdb_data->error_buf);

			// The callback might add entries back into data->error_buf
			RRR_LL_ITERATE_BEGIN(&error_buf_tmp, struct rrr_ip_buffer_entry);
				rrr_ip_buffer_entry_lock(node);
				if (common_callback(node, influxdb_data) != 0) {
					RRR_MSG_ERR("Error while iterating error buffer in influxdb instance %s\n",
							INSTANCE_D_NAME(thread_data));
					rrr_ip_buffer_entry_unlock(node);
					goto out_message;
				}
				RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_END_CHECK_DESTROY(&error_buf_tmp, 0; rrr_ip_buffer_entry_decref_while_locked_and_unlock(node));
		}
	}

	out_message:
	RRR_DBG_1 ("Thread influxdb %p instance %s exiting 1 state is %i\n",
			thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	out_exit:
	RRR_DBG_1 ("Thread influxdb %p instance %s exiting 2 state is %i\n",
			thread_data->thread, INSTANCE_D_NAME(thread_data), thread_data->thread->state);

	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_influxdb,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "influxdb";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy influxdb module\n");
}

