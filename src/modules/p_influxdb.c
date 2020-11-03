/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include "../lib/array.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/map.h"
#include "../lib/message_broker.h"
#include "../lib/read_constants.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/http/http_session.h"
#include "../lib/http/http_query_builder.h"
#include "../lib/http/http_client_config.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/util/linked_list.h"
#include "../lib/util/gnu.h"

#define INFLUXDB_DEFAULT_SERVER "localhost"
#define INFLUXDB_DEFAULT_PORT 8086

// Standardized return values, HTTP-framework compatible
#define INFLUXDB_OK		 	RRR_READ_OK
#define INFLUXDB_HARD_ERR	RRR_READ_HARD_ERROR
#define INFLUXDB_SOFT_ERR	RRR_READ_SOFT_ERROR

struct influxdb_data {
	struct rrr_instance_runtime_data *thread_data;
	char *database;
	char *table;
	int message_count;
	struct rrr_msg_holder_collection error_buf;

	struct rrr_http_client_config http_client_config;
	struct rrr_net_transport_config net_transport_config;

	// NOT managed by cleanup function, separate cleanup_push/pop
	struct rrr_net_transport *transport;
};

static int influxdb_data_init(struct influxdb_data *data, struct rrr_instance_runtime_data *thread_data) {
	int ret = 0;

	memset (data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	goto out;
	out:
		return ret;
}

static void influxdb_data_destroy (void *arg) {
	struct influxdb_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->database);
	RRR_FREE_IF_NOT_NULL(data->table);
	rrr_msg_holder_collection_clear(&data->error_buf);
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_http_client_config_cleanup(&data->http_client_config);
	// DO NOT cleanup net_transport pointer, done in separate pthread_cleanup push/pop
}

#define CHECK_RET()																			\
		do {if (ret != 0) {																	\
			if (ret == RRR_HTTP_SOFT_ERROR) {												\
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

static int influxdb_receive_http_response (
		RRR_HTTP_SESSION_RECEIVE_CALLBACK_ARGS
) {
	struct response_callback_data *data = arg;

	(void)(handle);
	(void)(data_ptr);
	(void)(sockaddr);
	(void)(socklen);
	(void)(overshoot_bytes);
	(void)(request_part);
	(void)(unique_id);
	(void)(upgrade_mode);

	int ret = 0;

	// TODO : Read error message from JSON

	if (response_part->response_code < 200 || response_part->response_code > 299) {
		RRR_MSG_0("HTTP error from influxdb in instance %s: %i %s\n",
				INSTANCE_D_NAME(data->data->thread_data), response_part->response_code, response_part->response_str);
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

static void influxdb_send_data_callback (
		struct rrr_net_transport_handle *handle,
		const struct sockaddr *sockaddr,
		socklen_t socklen,
		void *arg
) {
	struct send_data_callback_data *callback_data = arg;

	(void)(sockaddr);
	(void)(socklen);

	struct influxdb_data *data = callback_data->data;
	struct rrr_array *array = callback_data->array;

	int ret = INFLUXDB_OK;

	char *uri = NULL;
	struct rrr_http_query_builder query_builder;

	if (rrr_http_query_builder_init(&query_builder) != 0) {
		RRR_MSG_0("Could not initialize query builder in influxdb_send_data_callback\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_asprintf(&uri, "/write?db=%s", data->database)) <= 0) {
		RRR_MSG_0("Error while creating URI in send_data of influxdb instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_client_new_or_clean (
			handle,
			RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING,
			RRR_HTTP_CLIENT_USER_AGENT
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_set_endpoint (
			handle,
			uri
	)) != 0) {
		RRR_MSG_0("Could set endpoint in HTTP session in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	// Append table name
	ret = rrr_http_query_builder_append_raw (
			&query_builder,
			data->table
	);
	CHECK_RET();

	// Append tags from array
	ret = rrr_http_query_builder_append_values_from_array (
			&query_builder,
			array,
			&data->http_client_config.tags,
			",",
			0, // 0 = put comma before first name
			1  // 1 = add double quotes on values
	);
	CHECK_RET();

	// Append fixed tags from config
	ret = rrr_http_query_builder_append_values_from_map (
			&query_builder,
			&data->http_client_config.fixed_tags,
			",",
			0 // 0 = put comma before first name
	);
	CHECK_RET();

	// Append separator
	ret = rrr_http_query_builder_append_raw (
			&query_builder,
			" "
	);
	CHECK_RET();

	// Append fields from array
	ret = rrr_http_query_builder_append_values_from_array (
			&query_builder,
			array,
			&data->http_client_config.fields,
			",",
			1, // 1 = do not put comma before first name
			1  // 1 = add double quotes on values
	);
	CHECK_RET();

	// Append fixed fields from config
	ret = rrr_http_query_builder_append_values_from_map (
			&query_builder,
			&data->http_client_config.fixed_fields,
			",",
			RRR_LL_COUNT(&data->http_client_config.fields) == 0
	);
	CHECK_RET();

	// TODO : Better distinguishing of soft/hard errors from HTTP layer

	if ((ret = rrr_http_session_transport_ctx_add_query_field (
			handle,
			NULL,
			rrr_http_query_builder_buf_get(&query_builder),
			rrr_http_query_builder_wpos_get(&query_builder),
			NULL // <-- No content-type
	)) != 0) {
		RRR_MSG_0("Could not add data to HTTP query in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_request_send(handle, data->http_client_config.server)) != 0) {
		RRR_MSG_0("Could not send HTTP request in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	struct response_callback_data response_callback_data = {
			data, 0
	};

	if (rrr_http_session_transport_ctx_receive (
			handle,
			RRR_HTTP_CLIENT_TIMEOUT_STALL_MS * 1000,
			RRR_HTTP_CLIENT_TIMEOUT_TOTAL_MS * 1000,
			0, // No max read size
			0, // No unique id
			NULL,
			NULL,
			influxdb_receive_http_response,
			&response_callback_data,
			NULL,
			NULL
	) != 0) {
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
	rrr_http_query_builder_cleanup(&query_builder);
	RRR_FREE_IF_NOT_NULL(uri);
	callback_data->ret = ret;
}

static int influxdb_send_data (
		struct influxdb_data *data,
		struct rrr_array *array
) {
	struct send_data_callback_data callback_data = {
			data,
			array,
			0
	};

	int ret = 0;

	ret |= rrr_net_transport_connect_and_close_after_callback (
			data->transport,
			data->http_client_config.server_port,
			data->http_client_config.server,
			influxdb_send_data_callback,
			&callback_data
	);
	ret |= callback_data.ret;

	return ret;
}

static int influxdb_common_callback (
		struct rrr_msg_holder *entry,
		struct influxdb_data *influxdb_data
) {
	struct rrr_msg_msg *reading = entry->message;

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

	if (rrr_array_message_append_to_collection(&array, reading) != 0) {
		RRR_MSG_0("Error while parsing incoming array in influxdb instance %s\n",
				INSTANCE_D_NAME(influxdb_data->thread_data));
		ret = 0;
		goto discard;
	}

	ret = influxdb_send_data(influxdb_data, &array);
	if (ret != 0) {
		if (ret == INFLUXDB_SOFT_ERR) {
			RRR_MSG_0("Storing message with error in buffer for later retry in influxdb instance %s\n",
					INSTANCE_D_NAME(influxdb_data->thread_data));

			rrr_msg_holder_incref_while_locked(entry);
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
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int influxdb_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	return influxdb_common_callback(entry, thread_data->private_data);
}

static int influxdb_parse_config (struct influxdb_data *data, struct rrr_instance_config_data *config) {
	// NOTE : Special return handling, all parsing is done upon errors, we don't
	//        stop if something fail. Make sure ret is not overwritten if it has
	//        been set to 1
	int ret = 0;

	rrr_instance_config_get_string_noconvert_silent (&data->database, config, "influxdb_database");
	rrr_instance_config_get_string_noconvert_silent (&data->table, config, "influxdb_table");

	if (data->database == NULL) {
		RRR_MSG_0("No influxdb_database specified for instance %s\n", config->name);
		ret = 1;
	}

	if (data->table == NULL) {
		RRR_MSG_0("No influxdb_table specified for instance %s\n", config->name);
		ret = 1;
	}

	if (rrr_http_client_config_parse (
			&data->http_client_config,
			config,
			"influxdb",
			INFLUXDB_DEFAULT_SERVER,
			INFLUXDB_DEFAULT_PORT,
			1, // <-- Enable fixed tags and fields
			0, // <-- Do not enable endpoint
			0  // <-- Don't check for raw mode consistency
	) != 0) {
		ret = 1;
	}

	if (RRR_LL_COUNT(&data->http_client_config.fields) == 0 && RRR_LL_COUNT(&data->http_client_config.fixed_fields) == 0) {
		RRR_MSG_0("No fields specified in config for influxdb instance %s, this an error\n", config->name);
		ret = 1;
	}

	if (rrr_net_transport_config_parse(
			&data->net_transport_config,
			config,
			"influxdb",
			0,
			RRR_NET_TRANSPORT_PLAIN
	) != 0) {
		ret = 1;
	}

	/* On error, memory is freed by data_cleanup */

	return ret;
}

static void *thread_entry_influxdb (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data = thread_data->private_memory;
	struct rrr_msg_holder_collection error_buf_tmp = {0};
	struct rrr_net_transport *transport = NULL;

	if (influxdb_data_init(influxdb_data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_exit;
	}

	RRR_DBG_1 ("InfluxDB thread data is %p\n", thread_data);

	pthread_cleanup_push(influxdb_data_destroy, influxdb_data);
	pthread_cleanup_push(rrr_msg_holder_collection_clear_void, &error_buf_tmp);

	rrr_thread_start_condition_helper_nofork(thread);

	if (influxdb_parse_config(influxdb_data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Error while parsing configuration for influxdb instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (rrr_net_transport_new (
			&transport,
			&influxdb_data->net_transport_config,
			0
	) != 0) {
		RRR_MSG_0("Could not create transport in influxdb data_init\n");
		goto out_message;
	}

	influxdb_data->transport = transport;

	pthread_cleanup_push(rrr_net_transport_destroy_void, transport);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("InfluxDB started thread %p\n", thread_data);

	uint64_t timer_start = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(thread) != 1) {
		rrr_thread_update_watchdog_time(thread);

		if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, influxdb_poll_callback, 50) != 0) {
			RRR_MSG_0("Error while polling in influxdb instance %s\n",
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
			RRR_LL_ITERATE_BEGIN(&error_buf_tmp, struct rrr_msg_holder);
				rrr_msg_holder_lock(node);
				if (influxdb_common_callback(node, influxdb_data) != 0) {
					RRR_MSG_0("Error while iterating error buffer in influxdb instance %s\n",
							INSTANCE_D_NAME(thread_data));
					rrr_msg_holder_unlock(node);
					goto out_cleanup_transport;
				}
				RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_END_CHECK_DESTROY(&error_buf_tmp, 0; rrr_msg_holder_decref_while_locked_and_unlock(node));
		}
	}

	out_cleanup_transport:
	pthread_cleanup_pop(1);

	out_message:
	RRR_DBG_1 ("Thread influxdb %p instance %s exiting 1 state is %i\n",
			thread, INSTANCE_D_NAME(thread_data), rrr_thread_get_state(thread));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	out_exit:
	RRR_DBG_1 ("Thread influxdb %p instance %s exiting 2 state is %i\n",
			thread, INSTANCE_D_NAME(thread_data), rrr_thread_get_state(thread));

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_influxdb,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "influxdb";

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
	RRR_DBG_1 ("Destroy influxdb module\n");
}
