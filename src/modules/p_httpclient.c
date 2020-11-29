/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include "../lib/http/http_client.h"
#include "../lib/http/http_client_config.h"
#include "../lib/http/http_query_builder.h"
#include "../lib/http/http_session.h"
#include "../lib/http/http_transaction.h"
#include "../lib/http/http_util.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/helpers/nullsafe_str.h"

#define RRR_HTTPCLIENT_DEFAULT_SERVER			"localhost"
#define RRR_HTTPCLIENT_DEFAULT_PORT				0 // 0=automatic
#define RRR_HTTPCLIENT_DEFAULT_REDIRECTS_MAX	5
#define RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX		500
#define RRR_HTTPCLIENT_READ_MAX_SIZE			1 * 1024 * 1024 * 1024 // 1 GB

struct httpclient_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_msg_holder_collection defer_queue;

	int do_no_data;
	int do_rrr_msg_to_array;
	int do_drop_on_error;
	int do_keepalive;
	int do_receive_raw_data;
	int do_receive_part_data;
	int do_send_raw_data;
	int do_plain_http2;

	char *endpoint_tag;
	int do_endpoint_tag_force;

	char *server_tag;
	int do_server_tag_force;

	char *port_tag;
	int do_port_tag_force;

	rrr_setting_uint message_timeout_us;

	rrr_setting_uint redirects_max;

	struct rrr_net_transport_config net_transport_config;

	struct rrr_net_transport *keepalive_transport;
	int keepalive_handle;

	// Array fields, server name etc.
	struct rrr_http_client_config http_client_config;
};

static void httpclient_data_cleanup(void *arg) {
	struct httpclient_data *data = arg;
	if (data->keepalive_transport != NULL) {
		rrr_net_transport_destroy(data->keepalive_transport);
	}

	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_http_client_config_cleanup(&data->http_client_config);
	rrr_msg_holder_collection_clear(&data->defer_queue);
	RRR_FREE_IF_NOT_NULL(data->endpoint_tag);
	RRR_FREE_IF_NOT_NULL(data->server_tag);
	RRR_FREE_IF_NOT_NULL(data->port_tag);
}

struct httpclient_transaction_data {
	char *msg_topic;
};

static int httpclient_transaction_data_new (
		struct httpclient_transaction_data **target,
		const char *topic,
		size_t topic_len
) {
	int ret = 0;

	*target = NULL;

	struct httpclient_transaction_data *result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_httpclient_transaction_data_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((result->msg_topic = malloc(topic_len + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory for topic in rrr_httpclient_transaction_data_new\n");
		ret = 1;
		goto out_free;
	}

	if (topic != NULL && topic_len != 0) {
		memcpy(result->msg_topic, topic, topic_len);
	}
	result->msg_topic[topic_len] = '\0';

	*target = result;

	goto out;
	out_free:
		free(result);
	out:
		return ret;
}

static void httpclient_transaction_destroy (struct httpclient_transaction_data *target) {
	RRR_FREE_IF_NOT_NULL(target->msg_topic);
	free(target);
}

static void httpclient_transaction_destroy_void (void *target) {
	httpclient_transaction_destroy(target);
}

struct httpclient_create_message_callback_data {
	struct httpclient_data *httpclient_data;
	const struct httpclient_transaction_data *transaction_data;
	const void *data;
	size_t size;
};

static int httpclient_create_message_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct httpclient_create_message_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	if (callback_data->size > 0xffffffff) { // Eight f's
		RRR_MSG_0("HTTP length too long in httpclient_create_message_callback, max is 0xffffffff\n");
		ret = RRR_MESSAGE_BROKER_DROP;
		goto out;
	}

	if ((ret = rrr_msg_msg_new_with_data (
			(struct rrr_msg_msg **) &new_entry->message,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			callback_data->transaction_data->msg_topic,
			(callback_data->transaction_data->msg_topic != NULL ? strlen(callback_data->transaction_data->msg_topic) : 0),
			callback_data->data,
			callback_data->size
	)) != 0) {
		RRR_MSG_0("Failed to create message in httpclient_create_message_callback\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	out:
	rrr_msg_holder_unlock(new_entry);
	return ret;
}

struct httpclient_final_callback_data {
	struct httpclient_data *httpclient_data;
};

static int httpclient_final_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	struct httpclient_data *httpclient_data = arg;

	int ret = RRR_HTTP_OK;
/*
	if (data->response_code < 200 || data->response_code > 299) {
		RRR_BUG("BUG: Invalid response %i propagated from http framework to httpclient module\n", data->response_code);
	}
*/
	RRR_DBG_3("HTTP response from server in httpclient instance %s: data size %" PRIrrrl "\n",
			INSTANCE_D_NAME(httpclient_data->thread_data),
			rrr_nullsafe_str_len(response_data)
	);

	if (!httpclient_data->do_receive_part_data) {
		goto out;
	}

	struct httpclient_create_message_callback_data callback_data_broker = {
			httpclient_data,
			transaction->application_data,
			response_data->str,
			response_data->len
	};

	RRR_DBG_3("httpclient instance %s creating message with HTTP response data\n",
			INSTANCE_D_NAME(httpclient_data->thread_data));

	ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(httpclient_data->thread_data),
			NULL,
			0,
			0,
			httpclient_create_message_callback,
			&callback_data_broker
	);

	out:
	return ret;
}

static int httpclient_transaction_field_add (
		struct httpclient_data *data,
		struct rrr_http_transaction *transaction,
		const struct rrr_type_value *value,
		const char *tag_to_use
) {
	int ret = 0;

	struct rrr_http_query_builder query_builder;

	char *buf_tmp = NULL;

	if ((rrr_http_query_builder_init(&query_builder)) != 0) {
		RRR_MSG_0("Could not initialize query builder in httpclient_add_multipart_array_value\n");
		ret = 1;
		goto out;
	}

	RRR_DBG_3("HTTP add array value with tag '%s' type '%s'\n",
			(tag_to_use != NULL ? tag_to_use : "(no tag)"), value->definition->identifier);

	if (RRR_TYPE_IS_MSG(value->definition->type)) {
		rrr_length buf_size = 0;

		if (rrr_type_value_allocate_and_export(&buf_tmp, &buf_size, value) != 0) {
			RRR_MSG_0("Error while exporting RRR message in httpclient_add_multipart_array_value\n");
			ret = 1;
			goto out_cleanup_query_builder;
		}

		ret = rrr_http_transaction_query_field_add (
				transaction,
				tag_to_use,
				buf_tmp,
				buf_size,
				RRR_MESSAGE_MIME_TYPE
		);
	}
	else if (RRR_TYPE_IS_STR(value->definition->type)) {
		// MUST be signed due to decrement counting. Also, do not get
		// export length as it will add two bytes for quotes ""
		int64_t buf_size = value->total_stored_length;
		const char *buf = value->data;

		// Remove trailing 0's
		while (buf_size > 0 && buf[buf_size - 1] == '\0') {
			buf_size--;
		}

		if (buf_size > 0) {
			ret = rrr_http_transaction_query_field_add (
					transaction,
					tag_to_use,
					buf,
					buf_size,
					"text/plain"
			);
		}
	}
	else if (RRR_TYPE_IS_BLOB(value->definition->type)) {
		ret = rrr_http_transaction_query_field_add (
				transaction,
				tag_to_use,
				value->data,
				value->total_stored_length,
				"application/octet-stream"
		);
	}
	else {
		// BLOB and STR must be treated as special case above, this
		// function would otherwise modify the data by escaping
		if ((ret = rrr_http_query_builder_append_type_value_as_escaped_string (
				&query_builder,
				value,
				0
		)) != 0) {
			RRR_MSG_0("Error while exporting non-BLOB in httpclient_add_multipart_array_value\n");
			goto out_cleanup_query_builder;
		}

		ret = rrr_http_transaction_query_field_add (
				transaction,
				tag_to_use,
				rrr_http_query_builder_buf_get(&query_builder),
				rrr_http_query_builder_wpos_get(&query_builder),
				"text/plain"
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Could not add data to HTTP query in instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_cleanup_query_builder;
	}

	out_cleanup_query_builder:
		rrr_http_query_builder_cleanup(&query_builder);
	out:
		RRR_FREE_IF_NOT_NULL(buf_tmp);
		return ret;
}

static int httpclient_get_values_from_message (
		struct rrr_array *target_array,
		const struct rrr_msg_msg *message
) {
	int ret = 0;

	if (rrr_array_message_append_to_collection(target_array, message) != 0) {
		RRR_MSG_0("Error while converting message to collection in httpclient_get_values_from_message\n");
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int httpclient_get_metadata_from_message (
		struct rrr_array *target_array,
		const struct rrr_msg_msg *message
) {
	int ret = 0;

	// Push timestamp
	if (rrr_array_push_value_u64_with_tag(target_array, "timestamp", message->timestamp) != 0) {
		RRR_MSG_0("Could not create timestamp array value in httpclient_get_values_from_message\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	// Push topic
	if (MSG_TOPIC_LENGTH(message) > 0) {
		if (rrr_array_push_value_str_with_tag_with_size (
				target_array,
				"topic",
				MSG_TOPIC_PTR(message),
				MSG_TOPIC_LENGTH(message)
		) != 0) {
			RRR_MSG_0("Could not create topic array value in httpclient_get_values_from_message\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	// Push data
	if (MSG_DATA_LENGTH(message) > 0) {
		if (rrr_array_push_value_blob_with_tag_with_size (
				target_array,
				"data",
				MSG_DATA_PTR(message),
				MSG_DATA_LENGTH(message)
		) != 0) {
			RRR_MSG_0("Could not create data array value in httpclient_get_values_from_message\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int httpclient_session_query_prepare_callback_process_override (
		char **result,
		struct httpclient_data *data,
		const struct rrr_array *array,
		const char *tag,
		int do_force,
		const char *debug_name
) {
	int ret = RRR_HTTP_OK;

	*result = NULL;

	char *data_to_free = NULL;

	const struct rrr_type_value *value = rrr_array_value_get_by_tag_const(array, tag);
	if (value == NULL) {
		// Use default if force is not enabled
	}
	else {
		if (value->definition->to_str == NULL) {
			RRR_MSG_0("Warning: Received message in httpclient instance %s where the specified type of the %s tagged '%s' in the message was of type '%s' which cannot be used as a string\n",
					INSTANCE_D_NAME(data->thread_data),
					debug_name,
					tag,
					value->definition->identifier
			);
		}
		else if (value->definition->to_str(&data_to_free, value) != 0) {
			RRR_MSG_0("Warning: Failed to convert array value tagged '%s' to string for use as %s in httpserver instance %s\n",
					tag,
					debug_name,
					INSTANCE_D_NAME(data->thread_data)
			);
		}
	}

	if (data_to_free == NULL && do_force) {
		RRR_MSG_0("Warning: Received message in httpclient instance %s with missing/unusable %s tag '%s' (which is enforced in configuration), dropping it\n",
				INSTANCE_D_NAME(data->thread_data),
				debug_name,
				tag
		);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	*result = data_to_free;
	data_to_free = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(data_to_free);
	return ret;
}

struct httpclient_prepare_callback_data {
	struct httpclient_data *data;
	const struct rrr_msg_msg *message;
	const struct rrr_array *array_from_msg;
};

#define HTTPCLIENT_PREPARE_OVERRIDE(name)												\
	do {if (	data->RRR_PASTE(name,_tag) != NULL &&									\
				(ret = httpclient_session_query_prepare_callback_process_override (		\
						&RRR_PASTE(name,_to_free),										\
						data,															\
						callback_data->array_from_msg,									\
						data->RRR_PASTE(name,_tag),										\
						data->RRR_PASTE_3(do_,name,_tag_force),							\
						RRR_QUOTE(name)													\
				)) != 0) { goto out; }} while (0)

static int httpclient_connection_prepare_callback (
		RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS
) {
	struct httpclient_prepare_callback_data *callback_data = arg;
	struct httpclient_data *data = callback_data->data;

	int ret = 0;

	*server_override = NULL;
	// DO NOT set *port_ovveride to zero here, leave it as is

	char *server_to_free = NULL;
	char *port_to_free = NULL;

	HTTPCLIENT_PREPARE_OVERRIDE(server);
	HTTPCLIENT_PREPARE_OVERRIDE(port);

	if (port_to_free != NULL) {
		char *end = NULL;
		unsigned long long port = strtoull(port_to_free, &end, 10);
		if (end == NULL || *end != '\0' || port == 0 || port > 65535) {
			RRR_MSG_0("Warning: Invalid override port value of '%s' in message to httpclient instance %s, dropping it\n",
					port_to_free, INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		*port_override = port;
	}

	*server_override = server_to_free;
	server_to_free = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(server_to_free);
	RRR_FREE_IF_NOT_NULL(port_to_free);
	return ret;
}

static int httpclient_session_query_prepare_callback (
		RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS
) {
	struct httpclient_prepare_callback_data *callback_data = arg;
	struct httpclient_data *data = callback_data->data;
	const struct rrr_msg_msg *message = callback_data->message;

	*query_string = NULL;
	*endpoint_override = NULL;

	int ret = RRR_HTTP_OK;

	char *endpoint_to_free = NULL;
	struct rrr_array array_to_send_tmp = {0};

	array_to_send_tmp.version = RRR_ARRAY_VERSION;

	HTTPCLIENT_PREPARE_OVERRIDE(endpoint);

	if (data->do_no_data == 0) {
		rrr_array_append_from(&array_to_send_tmp, callback_data->array_from_msg);

		if (data->do_rrr_msg_to_array) {
			if ((ret = httpclient_get_metadata_from_message(&array_to_send_tmp, message))) {
				goto out;
			}
		}
	}

	if (data->do_no_data != 0 && (RRR_MAP_COUNT(&data->http_client_config.tags) + RRR_LL_COUNT(&array_to_send_tmp) > 0)) {
		RRR_BUG("BUG: HTTP do_no_data is set but tags map and array are not empty in httpclient_session_query_prepare_callback\n");
	}

	if ((ret = rrr_http_transaction_keepalive_set (
			transaction,
			data->do_keepalive
	)) != 0) {
		RRR_MSG_0("Failed to set keep-alive in httpclient_session_query_prepare_callback\n");
		ret = 1;
		goto out;
	}

	if (RRR_MAP_COUNT(&data->http_client_config.tags) == 0) {
		// Add all array fields
		RRR_LL_ITERATE_BEGIN(&array_to_send_tmp, const struct rrr_type_value);
			if ((ret = httpclient_transaction_field_add (
					data,
					transaction,
					node,
					node->tag // NULL allowed
			)) != RRR_HTTP_OK) {
				goto out;
			}
		RRR_LL_ITERATE_END();
	}
	else {
		// Add chosen array fields
		RRR_MAP_ITERATE_BEGIN(&data->http_client_config.tags);
			const struct rrr_type_value *value = rrr_array_value_get_by_tag_const(callback_data->array_from_msg, node_tag);
			if (value == NULL) {
				RRR_MSG_0("Could not find array tag %s while adding HTTP query values in instance %s.\n",
						node_tag, INSTANCE_D_NAME(data->thread_data));
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			// If value is set in map, tag is to be translated
			const char *tag_to_use = (node_value != NULL && *node_value != '\0') ? node_value : node_tag;

			if ((ret = httpclient_transaction_field_add (
					data,
					transaction,
					value,
					tag_to_use
			)) != RRR_HTTP_OK) {
				goto out;
			}
		RRR_MAP_ITERATE_END();
	}

	RRR_MAP_ITERATE_BEGIN(&data->http_client_config.fields);
		RRR_DBG_3("HTTP add field value with tag '%s' value '%s'\n",
				node_tag, node_value != NULL ? node_value : "(no value)");
		if ((ret = rrr_http_transaction_query_field_add (
				transaction,
				node_tag,
				node_value,
				strlen(node_value),
				"text/plain"
		)) != RRR_HTTP_OK) {
			goto out;
		}
	RRR_MAP_ITERATE_END();

	if (RRR_DEBUGLEVEL_3) {
		RRR_MSG_3("HTTP using method %s\n", RRR_HTTP_METHOD_TO_STR(transaction->method));
		rrr_http_transaction_query_fields_dump(transaction);
	}

	{
		const char *endpoint_to_print = (endpoint_to_free != NULL ? endpoint_to_free : data->http_client_config.endpoint);
		RRR_DBG_2("httpclient instance %s sending request from message with timestamp %" PRIu64 " endpoint %s\n",
				INSTANCE_D_NAME(data->thread_data),
				message->timestamp,
				endpoint_to_print
		);
	}

	*endpoint_override = endpoint_to_free;
	endpoint_to_free = NULL;

	out:
		rrr_array_clear(&array_to_send_tmp);
		RRR_FREE_IF_NOT_NULL(endpoint_to_free);
		return ret;
}

struct httpclient_raw_callback_data {
	struct httpclient_data *httpclient_data;
};

static int httpclient_raw_callback (
		RRR_HTTP_SESSION_RAW_RECEIVE_CALLBACK_ARGS
)  {
	struct httpclient_data *httpclient_data = arg;

	(void)(unique_id);
	(void)(next_protocol_version);

	int ret = 0;

	if (!httpclient_data->do_receive_raw_data) {
		goto out;
	}

	struct httpclient_create_message_callback_data callback_data_broker = {
			httpclient_data,
			transaction->application_data,
			data,
			data_size
	};

	RRR_DBG_3("httpclient instance %s creating message with raw HTTP response size %" PRIrrrbl "\n",
			INSTANCE_D_NAME(httpclient_data->thread_data), data_size);

	ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(httpclient_data->thread_data),
			NULL,
			0,
			0,
			httpclient_create_message_callback,
			&callback_data_broker
	);

	out:
	return ret;
}

static int httpclient_request_send (
		struct httpclient_data *data,
		struct rrr_msg_holder *entry
) {
	struct rrr_msg_msg *message = entry->message;

	int ret = RRR_HTTP_OK;

	struct rrr_http_client_request_data request_data = {0};
	struct rrr_array array_from_msg_tmp = {0};
	struct httpclient_transaction_data *transaction_data = NULL;

	array_from_msg_tmp.version = RRR_ARRAY_VERSION;

	if ((ret = httpclient_transaction_data_new (
			&transaction_data,
			MSG_TOPIC_PTR(message),
			MSG_TOPIC_LENGTH(message)
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_http_client_request_data_init (
			&request_data,
			RRR_HTTP_CLIENT_USER_AGENT,
			(void**) &transaction_data,
			httpclient_transaction_destroy_void
	)) != 0) {
		RRR_MSG_0("Could not initialize httpclient httpclient_data in httpclient_data_init\n");
		ret = 1;
		goto out;
	}

	enum rrr_http_transport http_transport_force = RRR_HTTP_TRANSPORT_ANY;

	switch (data->net_transport_config.transport_type) {
		case RRR_NET_TRANSPORT_TLS:
			http_transport_force = RRR_HTTP_TRANSPORT_HTTPS;
			 break;
		case RRR_NET_TRANSPORT_PLAIN:
			http_transport_force = RRR_HTTP_TRANSPORT_HTTP;
			 break;
		default:
			http_transport_force = RRR_HTTP_TRANSPORT_ANY;
			break;
	};

	if (rrr_http_client_data_reset (
			&request_data,
			&data->http_client_config,
			http_transport_force
	) != 0) {
		RRR_MSG_0("Could not store HTTP client configuration in httpclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret =  RRR_HTTP_HARD_ERROR;
		goto out;
	}

	if (data->do_send_raw_data) {
		if (MSG_DATA_LENGTH(message) == 0) {
			RRR_DBG_1("httpclient instance %s has http_send_raw_data set, but a received message had 0 length data. Dropping it.\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		if (MSG_CLASS(message) != MSG_CLASS_DATA) {
			RRR_DBG_1("httpclient instance %s has http_send_raw_data set, but a received message had wrong class (%u). Note that only raw data messages can be sent, not arrays.\n",
					INSTANCE_D_NAME(data->thread_data), MSG_CLASS(message));
			goto out;
		}

		ret = rrr_http_client_request_raw_send (
				&request_data,
				data->http_client_config.method,
				RRR_HTTP_APPLICATION_HTTP1,
				RRR_HTTP_UPGRADE_MODE_NONE,
				&data->keepalive_transport,
				&data->keepalive_handle,
				&data->net_transport_config,
				MSG_DATA_PTR(message),
				MSG_DATA_LENGTH(message),
				NULL,
				NULL
		);
	}
	else {
		if (MSG_IS_ARRAY(message)) {
			if ((ret = httpclient_get_values_from_message(&array_from_msg_tmp, message)) != RRR_HTTP_OK) {
				goto out;
			}
		}

		struct httpclient_prepare_callback_data prepare_callback_data = {
				data,
				message,
				&array_from_msg_tmp
		};

		enum rrr_http_upgrade_mode upgrade_mode = RRR_HTTP_UPGRADE_MODE_HTTP2;

		// Upgrade to HTTP2 only possibly with GET requests in plain mode or with all request methods in TLS mode
		if (data->http_client_config.method != RRR_HTTP_METHOD_GET && data->net_transport_config.transport_type != RRR_NET_TRANSPORT_TLS) {
			upgrade_mode = RRR_HTTP_UPGRADE_MODE_NONE;
		}

		ret = rrr_http_client_request_send (
				&request_data,
				data->http_client_config.method,
				RRR_HTTP_APPLICATION_HTTP1,
				upgrade_mode,
				data->do_plain_http2,
				&data->keepalive_transport,
				&data->keepalive_handle,
				&data->net_transport_config,
				httpclient_connection_prepare_callback,
				&prepare_callback_data,
				httpclient_session_query_prepare_callback,
				&prepare_callback_data
		);
	}

	// Do not add anything here, let return value from last function call propagate

	out:
	if (transaction_data != NULL) {
		httpclient_transaction_destroy(transaction_data);
	}
	rrr_array_clear(&array_from_msg_tmp);
	rrr_http_client_request_data_cleanup(&request_data);
	return ret;
}

static int httpclient_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
//	printf ("httpclient got entry %p\n", entry);

	struct rrr_instance_runtime_data *thread_data = arg;
	struct httpclient_data *data = thread_data->private_data;
	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_3("httpclient instance %s received message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	// Important : Set send_time for correct timeout behavior
	entry->send_time = rrr_time_get_64();

	int ret = RRR_FIFO_SEARCH_GIVE;

	//rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&data->defer_queue, entry);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int httpclient_data_init (
		struct httpclient_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	goto out;
//	out_cleanup_data:
//		httpclient_data_cleanup(httpclient_data);
	out:
		return ret;
}

#define HTTPCLIENT_OVERRIDE_TAG_GET(parameter) 																					\
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_" RRR_QUOTE(parameter) "_tag", RRR_PASTE(parameter,_tag));		\
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_" RRR_QUOTE(parameter) "_tag_force", RRR_PASTE_3(do_,parameter,_tag_force), 0)

#define HTTPCLIENT_OVERRIDE_TAG_VALIDATE(parameter)						\
	do {if (data->RRR_PASTE_3(do_,parameter,_tag_force) != 0) {			\
		if (data->RRR_PASTE(parameter,_tag) == NULL) {					\
			RRR_MSG_0("http_" RRR_QUOTE(parameter) " was 'yes' in httpclient instance %s but no tag was specified in http_" RRR_QUOTE(parameter) "_tag\n",\
					config->name);										\
			ret = 1;													\
		}																\
		if (RRR_INSTANCE_CONFIG_EXISTS("http_" RRR_QUOTE(parameter))) {	\
			RRR_MSG_0("http_" RRR_QUOTE(parameter) "_tag_force was 'yes' in httpclient instance %s while http_" RRR_QUOTE(parameter) " was also set, this is a configuration error\n",\
					config->name);										\
			ret = 1;													\
		}																\
		if (ret != 0) { goto out; }}} while(0)

static int httpclient_parse_config (
		struct httpclient_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_no_data", do_no_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_rrr_msg_to_array", do_rrr_msg_to_array, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_drop_on_error", do_drop_on_error, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_keepalive", do_keepalive, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_raw_data", do_receive_raw_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_part_data", do_receive_part_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_send_raw_data", do_send_raw_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_plain_http2", do_plain_http2, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_message_timeout_ms", message_timeout_us, 0);
	// Remember to mulitply to get useconds. Zero means no timeout.
	data->message_timeout_us *= 1000;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_max_redirects", redirects_max, RRR_HTTPCLIENT_DEFAULT_REDIRECTS_MAX);

	HTTPCLIENT_OVERRIDE_TAG_GET(endpoint);
	HTTPCLIENT_OVERRIDE_TAG_GET(server);
	HTTPCLIENT_OVERRIDE_TAG_GET(port);

	if (data->redirects_max > RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX) {
		RRR_MSG_0("Setting http_max_redirects of instance %s oustide range, maximum is %i\n",
				config->name, RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX);
		ret = 1;
		goto out;
	}

	if (data->do_no_data) {
		if (RRR_MAP_COUNT(&data->http_client_config.tags) > 0) {
			RRR_MSG_0("Setting http_no_data in instance %s was 'yes' while http_tags was also set. This is an error.\n",
					config->name);
			ret = 1;
		}
		if (data->do_rrr_msg_to_array) {
			RRR_MSG_0("Setting http_no_data in instance %s was 'yes' while http_rrr_msg_to_array was also 'yes'. This is an error.\n",
					config->name);
			ret = 1;
		}
		if (ret != 0) {
			goto out;
		}
	}

	if (data->do_send_raw_data) {
		if (data->do_no_data) {
			RRR_MSG_0("Both http_send_raw_data and http_no_data was yes in httpclient instance %s. The first implies the latter, it is an error to specify both.\n",
					config->name);
			ret = 1;
		}
		if (data->do_rrr_msg_to_array) {
			RRR_MSG_0("http_rrr_msg_to_array as well as http_send_raw_data were yes in httpclient instance %s, this is an invalid combination.\n",
					config->name);
			ret = 1;
		}
		if (data->endpoint_tag != NULL || data->server_tag || data->port_tag) {
			RRR_MSG_0("http_{endpoint|server|port}_tag parameters cannot be set while http_send_raw_data is yes in httpclient instance %s, check configuration.\n",
					config->name);
			ret = 1;
		}
		if (ret != 0) {
			goto out;
		}
	}

	if (rrr_http_client_config_parse (
			&data->http_client_config,
			config,
			"http",
			RRR_HTTPCLIENT_DEFAULT_SERVER,
			RRR_HTTPCLIENT_DEFAULT_PORT,
			0, // <-- Disable fixed tags and fields
			1, // <-- Enable endpoint
			data->do_send_raw_data // Check raw consisitency based on this option
	) != 0) {
		ret = 1;
		goto out;
	}

	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(endpoint);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(server);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(port);

	if (rrr_net_transport_config_parse (
			&data->net_transport_config,
			config,
			"http",
			1,
			RRR_NET_TRANSPORT_BOTH
	) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_httpclient (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data = thread_data->private_memory;

	if (httpclient_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in httpclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("httpclient thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(httpclient_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (httpclient_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("httpclient started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread) != 1) {
		rrr_thread_update_watchdog_time(thread);

		if (RRR_LL_COUNT(&data->defer_queue) > 0) {
			int ret_tmp = RRR_HTTP_OK;

			int send_timeout_count = 0;
//			int pos = 0;
			RRR_LL_ITERATE_BEGIN(&data->defer_queue, struct rrr_msg_holder);
//				printf("send loop %i/%i\n", pos++, RRR_LL_COUNT(&data->defer_queue));
				if (rrr_thread_check_encourage_stop(thread)) {
					RRR_LL_ITERATE_BREAK();
				}
				rrr_thread_update_watchdog_time(thread);

				rrr_msg_holder_lock(node);

				if (data->message_timeout_us != 0 && rrr_time_get_64() > node->send_time + data->message_timeout_us) {
						send_timeout_count++;
						RRR_LL_ITERATE_SET_DESTROY();
				}
				else if ((ret_tmp = httpclient_request_send(data, node)) != RRR_HTTP_OK) {
					if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
						// Let soft error propagate
					}
					else {
						RRR_MSG_0("Hard error while iterating defer queue in httpclient instance %s\n",
								INSTANCE_D_NAME(thread_data));
						ret_tmp = RRR_HTTP_HARD_ERROR;
					}
					RRR_LL_ITERATE_LAST(); // Don't break, unlock first
				}
				else {
					RRR_LL_ITERATE_SET_DESTROY();
				}
				rrr_msg_holder_unlock(node);
			RRR_LL_ITERATE_END_CHECK_DESTROY(&data->defer_queue, 0; rrr_msg_holder_decref(node));

			if (send_timeout_count > 0) {
				RRR_MSG_0("Send timeout for %i messages in httpclient instance %s\n",
						send_timeout_count,
						INSTANCE_D_NAME(data->thread_data));
			}

			if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
				rrr_posix_usleep(500000); // 500ms to avoid spamming server when there are errors
			}
		}

		// TODO : Implement nothing happened-stuff

		if (rrr_poll_do_poll_search(thread_data, &thread_data->poll, httpclient_poll_callback, thread_data, RRR_LL_COUNT(&data->defer_queue) > 0 ? 0 : 30) != 0) {
			RRR_MSG_0("Error while polling in httpclient instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		if (data->keepalive_transport != NULL && data->keepalive_handle != 0) {
			uint64_t bytes_total = 0;
			int ret_tmp = rrr_http_client_tick (
					&bytes_total,
					data->keepalive_transport,
					data->keepalive_handle,
					RRR_HTTPCLIENT_READ_MAX_SIZE,
					httpclient_final_callback,
					data,
					NULL,
					NULL,
					NULL,
					NULL,
					httpclient_raw_callback,
					data
			);

			if ((ret_tmp != 0 && ret_tmp != RRR_HTTP_OK && ret_tmp != RRR_READ_INCOMPLETE) || !(data->do_keepalive)) {
				rrr_http_client_terminate_if_open(data->keepalive_transport, data->keepalive_handle);
				data->keepalive_handle = 0;
			}
			if (ret_tmp != 0 && ret_tmp != RRR_READ_INCOMPLETE) {
				RRR_MSG_0("HTTP request failed in httpclient instance %s, return was %i\n",
						INSTANCE_D_NAME(data->thread_data), ret_tmp);
			}
		}
	}

	out_message:
	RRR_DBG_1 ("Thread httpclient %p exiting\n", thread);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_httpclient,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "httpclient";

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
	RRR_DBG_1 ("Destroy httpclient module\n");
}
