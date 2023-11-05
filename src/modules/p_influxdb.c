/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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
#include "../lib/event/event.h"
#include "../lib/event/event_functions.h"
#include "../lib/event/event_collection.h"
#include "../lib/event/event_collection_struct.h"
#include "../lib/allocator.h"
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
#include "../lib/http/http_util.h"
#include "../lib/http/http_application.h"
#include "../lib/http/http_session.h"
#include "../lib/http/http_query_builder.h"
#include "../lib/http/http_client_config.h"
#include "../lib/http/http_transaction.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/util/linked_list.h"
#include "../lib/util/gnu.h"

#define INFLUXDB_DEFAULT_SERVER "localhost"
#define INFLUXDB_DEFAULT_PORT 8086
#define INFLUXDB_DEFAULT_CONCURRENT_CONNECTIONS 10
#define INFLUXDB_MAX_REDIRECTS 5

// Standardized return values, HTTP-framework compatible
#define INFLUXDB_OK          RRR_READ_OK
#define INFLUXDB_HARD_ERR    RRR_READ_HARD_ERROR
#define INFLUXDB_SOFT_ERR    RRR_READ_SOFT_ERROR

#define INFLUXDB_INPUT_QUEUE_MAX 1000000

struct influxdb_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_msg_holder_collection input_buffer;
	struct rrr_event_collection events;
	rrr_event_handle event_process_entries;

	char *database;
	char *table;
	int message_count;

	struct rrr_http_client_config http_client_config;
	struct rrr_net_transport_config net_transport_config;

	rrr_http_unique_id unique_id_counter;

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
	rrr_event_collection_clear(&data->events);
	RRR_FREE_IF_NOT_NULL(data->database);
	RRR_FREE_IF_NOT_NULL(data->table);
	rrr_msg_holder_collection_clear(&data->input_buffer);
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_http_client_config_cleanup(&data->http_client_config);
	// DO NOT cleanup net_transport pointer, done in separate pthread_cleanup push/pop
}

#define CHECK_RET()                                                                         \
        do {if (ret != 0) {                                                                 \
            if (ret == RRR_HTTP_SOFT_ERROR) {                                               \
                RRR_MSG_0("Soft error in influxdb instance %s, discarding message\n",       \
                    INSTANCE_D_NAME(data->thread_data));                                    \
                ret = 0;                                                                    \
                goto out;                                                                   \
            }                                                                               \
            RRR_MSG_0("Hard error in influxdb instance %s\n",                               \
                INSTANCE_D_NAME(data->thread_data));                                        \
            ret = 1;                                                                        \
            goto out;                                                                       \
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
	(void)(overshoot_bytes);
	(void)(next_application_type);

	int ret = 0;

	// TODO : Read error message from JSON

	if (transaction->response_part->response_code < 200 || transaction->response_part->response_code > 299) {
		RRR_MSG_0("HTTP error from influxdb in instance %s: %i %s\n",
				INSTANCE_D_NAME(data->data->thread_data),
				transaction->response_part->response_code,
				rrr_http_util_iana_response_phrase_from_status_code((unsigned int) transaction->response_part->response_code)
		);
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

static int influxdb_unique_id_generator (
		RRR_HTTP_COMMON_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
) {
	struct send_data_callback_data *callback_data = arg;
	*unique_id = ++(callback_data->data->unique_id_counter);
	return 0;
}

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

	struct rrr_http_application *upgraded_app = NULL;
	struct rrr_http_transaction *transaction = NULL;
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

	struct response_callback_data response_callback_data = {
		data, 0
	};

	if ((ret = rrr_http_session_transport_ctx_client_new_or_clean (
			RRR_HTTP_APPLICATION_HTTP1,
			handle,
			RRR_HTTP_CLIENT_USER_AGENT,
			NULL,
			influxdb_receive_http_response,
			NULL, /* Failure callback, not implemented in InfluxDB) */
			NULL,
			NULL,
			&response_callback_data
	)) != 0) {
		RRR_MSG_0("Could not create HTTP session in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_http_transaction_new (
			&transaction,
			RRR_HTTP_METHOD_POST,
			RRR_HTTP_BODY_FORMAT_URLENCODED_NO_QUOTING,
			INFLUXDB_MAX_REDIRECTS,
			influxdb_unique_id_generator,
			callback_data,
			NULL,
			NULL
	)) != 0) {
		RRR_MSG_0("Could not create HTTP transaction in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_http_transaction_endpoint_set (
			transaction,
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

	const rrr_biglength length = rrr_http_query_builder_wpos_get(&query_builder);

	if (length > RRR_LENGTH_MAX) {
		RRR_MSG_0("Query size overflow in influxdb instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if ((ret = rrr_http_transaction_query_field_add (
			transaction,
			NULL,
			rrr_http_query_builder_buf_get(&query_builder),
			(rrr_length) length,
			NULL, // <-- No content-type
			NULL  // <-- No original value
	)) != 0) {
		RRR_MSG_0("Could not add data to HTTP query in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_http_session_transport_ctx_request_send (
			&upgraded_app,
			handle,
			data->http_client_config.server,
			transaction,
			RRR_HTTP_UPGRADE_MODE_NONE,
			RRR_HTTP_VERSION_11
	)) != 0) {
		RRR_MSG_0("Could not send HTTP request in influxdb instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (upgraded_app != NULL) {
		rrr_http_session_transport_ctx_application_set(&upgraded_app, handle);
	}

	rrr_biglength received_bytes = 0;

	do {
		if ((ret = rrr_http_session_transport_ctx_tick_client (
				&received_bytes,
				handle,
				0 // No max read size
		)) != 0 && ret != RRR_READ_INCOMPLETE) {
			RRR_MSG_0("Could not receive HTTP response in influxdb instance %sd\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = INFLUXDB_HARD_ERR;
			goto out;
		}
	} while (ret != 0);

	if (response_callback_data.save_ok != 1) {
		RRR_MSG_0("Warning: Error in HTTP response in influxdb instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = INFLUXDB_SOFT_ERR;
		goto out;
	}

	out:
	rrr_http_transaction_decref_if_not_null(transaction);
	rrr_http_application_destroy_if_not_null(&upgraded_app);
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

static int influxdb_process_entry (
		struct influxdb_data *influxdb_data,
		struct rrr_msg_holder *entry
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

	uint16_t array_version_dummy;
	if (rrr_array_message_append_to_array(&array_version_dummy, &array, reading) != 0) {
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
			RRR_LL_APPEND(&influxdb_data->input_buffer, entry);
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

static void influxdb_process_entries (
		struct influxdb_data *data,
		struct rrr_msg_holder_collection *source_buffer
) {
	RRR_LL_ITERATE_BEGIN(source_buffer, struct rrr_msg_holder);
		RRR_LL_VERIFY_NODE(source_buffer);
		rrr_msg_holder_lock(node);
		influxdb_process_entry(data, node);
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY_NO_FREE(source_buffer);
}

static void influxdb_event_process_entries (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	struct influxdb_data *data = arg;

	struct rrr_msg_holder_collection process_buffer_tmp = {0};

	pthread_cleanup_push(rrr_msg_holder_collection_clear_void, &process_buffer_tmp);

	// Entries which are to be retried are written back to the input buffer
	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(&process_buffer_tmp, &data->input_buffer);
	influxdb_process_entries(data, &process_buffer_tmp);

	pthread_cleanup_pop(1);

	// Failing entries will be retried when this event runs again due to the
	// timer or when some other entry gets polled and this event gets activated
	if (RRR_LL_COUNT(&data->input_buffer) == 0) {
		EVENT_REMOVE(data->event_process_entries);
	}
}

static int influxdb_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct influxdb_data *influxdb_data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_3 ("influxdb: Result from buffer: timestamp %" PRIu64 "\n", message->timestamp);

	rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&influxdb_data->input_buffer, entry);

	rrr_msg_holder_unlock(entry);

	return 0;
}

static int influxdb_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data;

	int ret = rrr_poll_do_poll_delete (amount, thread_data, influxdb_poll_callback);

	EVENT_ADD(influxdb_data->event_process_entries);
	EVENT_ACTIVATE(influxdb_data->event_process_entries);

	return ret;
}

static int influxdb_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct influxdb_data *influxdb_data = thread_data->private_data;

	RRR_DBG_1("InfluxDB instance %s messages per second: %i\n",
			INSTANCE_D_NAME(thread_data), influxdb_data->message_count);
	influxdb_data->message_count = 0;

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(thread);
}
		
static void influxdb_pause_check (RRR_EVENT_FUNCTION_PAUSE_ARGS) {
	struct rrr_instance_runtime_data *thread_data = callback_arg;
	struct influxdb_data *data = thread_data->private_data;

	if (is_paused) {
		*do_pause = RRR_LL_COUNT(&data->input_buffer) > (INFLUXDB_INPUT_QUEUE_MAX * 0.75) ? 1 : 0;
	}
	else {
		*do_pause = RRR_LL_COUNT(&data->input_buffer) > INFLUXDB_INPUT_QUEUE_MAX ? 1 : 0;
	}	
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
			INFLUXDB_DEFAULT_CONCURRENT_CONNECTIONS,
			1, // <-- Enable fixed tags and fields
			0, // <-- Do not enable endpoint
			0  // <-- Do not enable body format
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
			0, // Disallow multiple transports
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
			0, // Don't allow specifying certificate without transport type being TLS
			RRR_NET_TRANSPORT_PLAIN,
			RRR_NET_TRANSPORT_F_PLAIN | RRR_NET_TRANSPORT_F_TLS
#else
			RRR_NET_TRANSPORT_PLAIN,
			RRR_NET_TRANSPORT_F_PLAIN
#endif
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

	if (rrr_net_transport_new_simple (
			&transport,
			&influxdb_data->net_transport_config,
			"influxDB",
			0,
			INSTANCE_D_EVENTS(thread_data)
	) != 0) {
		RRR_MSG_0("Could not create transport in influxdb data_init\n");
		goto out_message;
	}

	influxdb_data->transport = transport;

	pthread_cleanup_push(rrr_net_transport_destroy_void, transport);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("InfluxDB started thread %p\n", thread_data);

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			influxdb_pause_check,
			thread_data
	);

	if (rrr_event_collection_push_periodic (
			&influxdb_data->event_process_entries,
			&influxdb_data->events,
			influxdb_event_process_entries,
			influxdb_data,
			1000 // 1000 ms
	) != 0) {
		RRR_MSG_0("Failed to create queue process event in influxdb instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup_transport;
	}

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			influxdb_event_periodic,
			thread
	);

	out_cleanup_transport:
	pthread_cleanup_pop(1);

	out_message:
	RRR_DBG_1 ("Thread influxdb %p instance %s exiting 1 state is %i\n",
			thread, INSTANCE_D_NAME(thread_data), rrr_thread_state_get(thread));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	out_exit:
	RRR_DBG_1 ("Thread influxdb %p instance %s exiting 2 state is %i\n",
			thread, INSTANCE_D_NAME(thread_data), rrr_thread_state_get(thread));

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_influxdb,
		NULL
};

static const char *module_name = "influxdb";

struct rrr_instance_event_functions event_functions = {
	influxdb_event_broker_data_available
};

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
	RRR_DBG_1 ("Destroy influxdb module\n");
}
