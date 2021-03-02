/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/map.h"
#include "../lib/buffer.h"
#include "../lib/http/http_session.h"
#include "../lib/http/http_transaction.h"
#include "../lib/http/http_server.h"
#include "../lib/http/http_util.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/net_transport/net_transport.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/mqtt/mqtt_topic.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip_defines.h"
#include "../lib/util/gnu.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/helpers/nullsafe_str.h"
#include "../lib/rrr_types.h"

#define RRR_HTTPSERVER_DEFAULT_PORT_PLAIN                     80
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
#    define RRR_HTTPSERVER_DEFAULT_PORT_TLS                   443
#endif
#define RRR_HTTPSERVER_DEFAULT_WORKER_THREADS                   5
#define RRR_HTTPSERVER_DEFAULT_RESPONSE_FROM_SENDERS_TIMEOUT_MS 2000

#define RRR_HTTPSERVER_REQUEST_TOPIC_PREFIX                   "httpserver/request/"
#define RRR_HTTPSERVER_WEBSOCKET_TOPIC_PREFIX                 "httpserver/websocket/"
#define RRR_HTTPSERVER_WORKER_THREADS_MAX                     1024

struct httpserver_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_net_transport_config net_transport_config;

	rrr_setting_uint port_plain;

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	rrr_setting_uint port_tls;
#endif

	struct rrr_map http_fields_accept;

	int do_http_fields_accept_any;
	int do_allow_empty_messages;
	int do_receive_full_request;
	int do_accept_websocket_binary;
	int do_receive_websocket_rrr_message;
	int do_disable_http2;
	int do_get_response_from_senders;

	rrr_setting_uint response_timeout_ms;
	rrr_setting_uint worker_threads;

	struct rrr_fifo_buffer buffer;

	struct rrr_map websocket_topic_filters;

	char *allow_origin_header;

	pthread_mutex_t oustanding_responses_lock;

	// Settings for test suite
	rrr_setting_uint startup_delay_us;
	int do_fail_once;
};

static void httpserver_data_cleanup(void *arg) {
	struct httpserver_data *data = arg;
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_map_clear(&data->http_fields_accept);
	rrr_map_clear(&data->websocket_topic_filters);
	rrr_fifo_buffer_destroy(&data->buffer);
	RRR_FREE_IF_NOT_NULL(data->allow_origin_header);
}

static int httpserver_data_init (
		struct httpserver_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	if (rrr_fifo_buffer_init_custom_free(&data->buffer, rrr_msg_holder_decref_void) != 0) {
		return 1;
	}

	return 0;
}

static int httpserver_parse_config (
		struct httpserver_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	if (rrr_net_transport_config_parse (
			&data->net_transport_config,
			config,
			"http_server",
			1,
			RRR_NET_TRANSPORT_PLAIN
	) != 0) {
		ret = 1;
		goto out;
	}

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_port_tls", port_tls, RRR_HTTPSERVER_DEFAULT_PORT_TLS);
	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_server_port_tls",
		if (data->net_transport_config.transport_type != RRR_NET_TRANSPORT_TLS &&
			data->net_transport_config.transport_type != RRR_NET_TRANSPORT_BOTH
		) {
			RRR_MSG_0("Setting http_server_port_tls is set for httpserver instance %s but TLS transport is not configured.\n",
					config->name);
			ret = 1;
			goto out;
		}
	);
#endif

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_port_plain", port_plain, RRR_HTTPSERVER_DEFAULT_PORT_PLAIN);
	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_server_port_plain",
		if (data->net_transport_config.transport_type != RRR_NET_TRANSPORT_PLAIN &&
			data->net_transport_config.transport_type != RRR_NET_TRANSPORT_BOTH
		) {
			RRR_MSG_0("Setting http_server_port_plain is set for httpserver instance %s but plain transport is not configured.\n",
					config->name);
			ret = 1;
			goto out;
		}
	);

	if ((ret = rrr_instance_config_parse_comma_separated_associative_to_map(&data->http_fields_accept, config, "http_server_fields_accept", "->")) != 0) {
		RRR_MSG_0("Could not parse setting http_server_fields_accept for instance %s\n",
				config->name);
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_fields_accept_any", do_http_fields_accept_any, 0);

	if (RRR_MAP_COUNT(&data->http_fields_accept) > 0 && data->do_http_fields_accept_any != 0) {
		RRR_MSG_0("Setting http_server_fields_accept in instance %s was set while http_server_fields_accept_any was 'yes', this is an invalid configuration.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_receive_full_request", do_receive_full_request, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_get_response_from_senders", do_get_response_from_senders, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_response_timeout_ms", response_timeout_ms, RRR_HTTPSERVER_DEFAULT_RESPONSE_FROM_SENDERS_TIMEOUT_MS);

	if (data->do_get_response_from_senders) {
		if (RRR_INSTANCE_CONFIG_EXISTS("http_server_receive_full_request") && !data->do_receive_full_request) {
			RRR_MSG_0("http_server_get_response_from_senders was 'yes' while http_server_receive_full_request was explicitly set to 'no' in httpserver instance %s, this is an invalid configuration.\n",
					config->name);
			ret = 1;
			goto out;
		}
		data->do_receive_full_request = 1;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_allow_empty_messages", do_allow_empty_messages, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_worker_threads", worker_threads, RRR_HTTPSERVER_DEFAULT_WORKER_THREADS);

	if (data->worker_threads > RRR_HTTPSERVER_WORKER_THREADS_MAX || data->worker_threads == 0) {
		RRR_MSG_0("Invalid value %" PRIrrrbl " for http_server_worker_threads in httpserver instance %s, must be in the range 0 < n < " RRR_QUOTE(RRR_HTTPSERVER_WORKER_THREADS_MAX) "\n",
				data->worker_threads, config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_instance_config_parse_comma_separated_to_map(&data->websocket_topic_filters, config, "http_server_websocket_topic_filters")) != 0) {
		RRR_MSG_0("Could not parse setting http_server_websocket_topic_filters for instance %s\n",
				config->name);
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_accept_websocket_binary", do_accept_websocket_binary, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_receive_websocket_rrr_message", do_receive_websocket_rrr_message, 0);

	if (data->do_accept_websocket_binary && RRR_LL_COUNT(&data->websocket_topic_filters) == 0) {
		RRR_MSG_0("http_server_accept_websocket_binary was set in httpserver instance %s, but no websocket topics are defined in http_server_websocket_topic_filters. This is a configuration error.\n",
				config->name);
		ret = 1;
		goto out;
	}

	if (data->do_receive_websocket_rrr_message) {
		RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_server_accept_websocket_binary",
			if (data->do_accept_websocket_binary == 0) {
				RRR_MSG_0("http_server_accept_websocket_binary was explicitly set to no in httpserver instance %s while http_server_receive_websocket_rrr_message was yes, this is a configuration error.\n",
						config->name);
				ret = 1;
				goto out;
			}
		);
		data->do_accept_websocket_binary = 1;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_server_allow_origin_header", allow_origin_header);

	// Undocumented, used to test failures in clients
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_server_startup_delay_s", startup_delay_us, 0);
	data->startup_delay_us *= 1000 * 1000;
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_server_fail_once", do_fail_once, 0);

	out:
	return ret;
}

static int httpserver_start_listening (struct httpserver_data *data, struct rrr_http_server *http_server) {
	int ret = 0;

	if (data->net_transport_config.transport_type == RRR_NET_TRANSPORT_PLAIN ||
		data->net_transport_config.transport_type == RRR_NET_TRANSPORT_BOTH
	) {
		if ((ret = rrr_http_server_start_plain(http_server, data->port_plain)) != 0) {
			RRR_MSG_0("Could not start listening in plain mode on port %" PRIrrrbl " in httpserver instance %s\n",
					data->port_plain, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
	}

#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	if (data->net_transport_config.transport_type == RRR_NET_TRANSPORT_TLS ||
		data->net_transport_config.transport_type == RRR_NET_TRANSPORT_BOTH
	) {
		if ((ret = rrr_http_server_start_tls (
				http_server,
				data->port_tls,
				&data->net_transport_config,
				0
		)) != 0) {
			RRR_MSG_0("Could not start listening in TLS mode on port %" PRIrrrbl " in httpserver instance %s\n",
					data->port_tls, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
	}
#endif

	out:
	return ret;
}

struct httpserver_worker_process_field_allocate_callback_data {
	struct rrr_type_value **value_tmp;
};

static int httpserver_worker_process_field_import_message_callback (
		const void *str_a,
		rrr_length len_a,
		const void *str_b,
		rrr_length len_b,
		void *arg
) {
	struct httpserver_worker_process_field_allocate_callback_data *callback_data = arg;
	return rrr_type_value_allocate_and_import_raw (
			callback_data->value_tmp,
			&rrr_type_definition_msg,
			str_a,
			str_a + len_a,
			len_b,
			str_b,
			len_a,
			1 // <-- We only support one message per field
	);
}

struct httpserver_worker_process_field_callback {
	struct rrr_array *array;
	struct httpserver_data *parent_data;
};

static int httpserver_worker_process_field_callback (
		const struct rrr_http_field *field,
		void *arg
) {
	struct httpserver_worker_process_field_callback *callback_data = arg;

	int ret = RRR_HTTP_OK;

	int do_add_field = 0;
	struct rrr_type_value *value_tmp = NULL;
	struct rrr_nullsafe_str *name_to_use = NULL;

	if (rrr_nullsafe_str_dup(&name_to_use, field->name) != 0) {
		RRR_MSG_0("Could not duplicate name in httpserver_worker_process_field_callback\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	if (callback_data->parent_data->do_http_fields_accept_any) {
		do_add_field = 1;
	}
	else if (RRR_MAP_COUNT(&callback_data->parent_data->http_fields_accept) > 0) {
		RRR_MAP_ITERATE_BEGIN(&callback_data->parent_data->http_fields_accept);
			if (rrr_nullsafe_str_cmpto(field->name, node_tag) == 0) {
				do_add_field = 1;
				if (node->value != NULL && node->value_size > 0 && *(node->value) != '\0') {
					// Do name translation
					if (rrr_nullsafe_str_set(name_to_use, node->value, strlen(node->value)) != 0) {
						RRR_MSG_0("Could not set name in httpserver_worker_process_field_callback\n");
						ret = RRR_HTTP_HARD_ERROR;
						goto out;
					}
					RRR_LL_ITERATE_LAST();
				}
			}
		RRR_MAP_ITERATE_END();
	}

	if (do_add_field != 1) {
		goto out;
	}

	if (	rrr_nullsafe_str_isset(field->value) &&
			rrr_nullsafe_str_cmpto_case(field->content_type, RRR_MESSAGE_MIME_TYPE) == 0
	) {
		struct httpserver_worker_process_field_allocate_callback_data allocate_callback_data = {
				&value_tmp
		};
		;
		if ((ret = rrr_nullsafe_str_with_raw_do_double_const (
				field->value,
				name_to_use,
				httpserver_worker_process_field_import_message_callback,
				&allocate_callback_data
		)) != 0) {
			RRR_MSG_0("Failed to import RRR message from HTTP field\n");
			goto out;
		}

		RRR_LL_APPEND(callback_data->array, value_tmp);
		value_tmp = NULL;
	}
	else if (field->value != NULL) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,name_to_use);
		ret = rrr_array_push_value_str_with_tag_nullsafe (
				callback_data->array,
				name,
				field->value
		);
	}
	else {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(name,name_to_use);
		ret = rrr_array_push_value_str_with_tag (
				callback_data->array,
				name,
				""
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Error while pushing field to array in __rrr_http_server_worker_process_field_callback\n");
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	out:
	rrr_nullsafe_str_destroy_if_not_null(&name_to_use);
	if (value_tmp != NULL) {
		rrr_type_value_destroy(value_tmp);
	}
	return ret;
}

struct httpserver_write_message_callback_data {
	struct rrr_array *array;
	const char *topic;
};

// NOTE : Worker thread CTX in httpserver_write_message_callback
static int httpserver_write_message_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct httpserver_write_message_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	struct rrr_msg_msg *new_message = NULL;

	if (RRR_LL_COUNT(callback_data->array) > 0) {
		ret = rrr_array_new_message_from_collection (
				&new_message,
				callback_data->array,
				rrr_time_get_64(),
				callback_data->topic,
				strlen(callback_data->topic)
		);
	}
	else {
		if ((ret = rrr_msg_msg_new_empty (
				&new_message,
				MSG_TYPE_MSG,
				MSG_CLASS_DATA,
				rrr_time_get_64(),
				strlen(callback_data->topic),
				0
		)) == 0) { // Note : Check for OK
			memcpy(MSG_TOPIC_PTR(new_message), callback_data->topic, new_message->topic_length);
		}
	}

	if (ret != 0) {
		RRR_MSG_0("Could not create message in httpserver_write_message_callback\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	new_entry->message = new_message;
	new_entry->data_length = MSG_TOTAL_SIZE(new_message);
	new_message = NULL;

	out:
	rrr_msg_holder_unlock(new_entry);
	return ret;
}

struct httpserver_callback_data {
	struct httpserver_data *httpserver_data;
	struct rrr_thread_collection *threads;
};

static int httpserver_generate_unique_topic (
		char **result,
		const char *prefix,
		rrr_http_unique_id unique_id,
		const char *extra
) {
	if (rrr_asprintf(result, "%s%" PRIu64 "%s%s",
			prefix,
			unique_id,
			(extra != NULL ? "/" : ""),
			(extra != NULL ? extra : "")
	) <= 0) {
		RRR_MSG_0("Could not create topic in httpserver_generate_unique_topic\n");
		return 1;
	}
	return 0;
}

static int httpserver_receive_callback_get_fields (
		struct rrr_array *target_array,
		struct httpserver_data *data,
		const struct rrr_http_part *part
) {
	int ret = RRR_HTTP_OK;

	struct httpserver_worker_process_field_callback field_callback_data = {
			target_array,
			data
	};

	if ((ret = rrr_http_part_fields_iterate_const (
			part,
			httpserver_worker_process_field_callback,
			&field_callback_data
	)) != RRR_HTTP_OK) {
		goto out;
	}

	out:
	return ret;
}

struct receive_get_response_callback_data {
	struct rrr_msg_holder *entry;
	const char *topic_filter;
};

static int httpserver_receive_get_response_callback (
		RRR_FIFO_READ_CALLBACK_ARGS
) {
	struct receive_get_response_callback_data *callback_data = arg;
	struct rrr_msg_holder *entry = (struct rrr_msg_holder *) data;

	(void)(size);

	int ret = RRR_FIFO_SEARCH_KEEP;

	rrr_msg_holder_lock(entry);

	struct rrr_msg_msg *msg = entry->message;

	if (MSG_TOPIC_LENGTH(msg) > 0) {
		if ((ret = rrr_mqtt_topic_match_str_with_end (
				callback_data->topic_filter,
				MSG_TOPIC_PTR(msg),
				MSG_TOPIC_PTR(msg) + MSG_TOPIC_LENGTH(msg)
		)) != 0) {
			if (ret == RRR_MQTT_TOKEN_MISMATCH) {
				ret = RRR_FIFO_SEARCH_KEEP;
				goto out;
			}
			RRR_MSG_0("Error while matching topic in httpserver_receive_get_response_callback\n");
			goto out;
		}
		else {
			if (callback_data->entry != NULL) {
				RRR_BUG("BUG: Response field was not clear in httpserver_receive_get_response_callback\n");
			}

			rrr_msg_holder_incref_while_locked(entry);
			callback_data->entry = entry;
		}
	}

	ret = RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE|RRR_FIFO_SEARCH_STOP;

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static void httpserver_receive_get_response_callback_data_cleanup (void *ptr) {
	struct receive_get_response_callback_data *callback_data = ptr;

	if (callback_data->entry != NULL) {
		rrr_msg_holder_decref(callback_data->entry);
	}
}

static int httpserver_receive_callback_full_request (
		struct rrr_array *target_array,
		const struct rrr_http_part *part,
		const char *data_ptr,
		enum rrr_http_application_type next_protocol_version
) {
	int ret = 0;

	const char *body_ptr = RRR_HTTP_PART_BODY_PTR(data_ptr,part);
	size_t body_len = RRR_HTTP_PART_BODY_LENGTH(part);

	// http_method, http_endpoint, http_body, http_content_transfer_encoding, http_content_type

	const struct rrr_http_header_field *content_type = rrr_http_part_header_field_get(part, "content-type");
	const struct rrr_http_header_field *content_transfer_encoding = rrr_http_part_header_field_get(part, "content-transfer-encoding");

	ret |= rrr_array_push_value_u64_with_tag(target_array, "http_protocol", next_protocol_version);
	ret |= rrr_array_push_value_blob_with_tag_nullsafe(target_array, "http_method", part->request_method_str_nullsafe);
	ret |= rrr_array_push_value_blob_with_tag_nullsafe(target_array, "http_endpoint", part->request_uri_nullsafe);

	if (content_type != NULL && rrr_nullsafe_str_isset(content_type->value)) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,content_type->value);
		ret |= rrr_array_push_value_str_with_tag (
				target_array,
				"http_content_type",
				value
		);
	}

	if (content_transfer_encoding != NULL && rrr_nullsafe_str_isset(content_transfer_encoding->value)) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(value,content_transfer_encoding->value);
		ret |= rrr_array_push_value_str_with_tag (
				target_array,
				"http_content_transfer_encoding",
				value
		);
	}

	if (body_len > 0){
		ret |= rrr_array_push_value_blob_with_tag_with_size (
				target_array, "http_body", body_ptr, body_len
		);
	}

	if (ret != 0) {
		RRR_MSG_0("Failed to add full request fields in httpserver_receive_callback_full_request\n");
		goto out;
	}

	out:
	return ret;
}

static int httpserver_receive_get_response_extract_data (
		struct rrr_array *target,
		const struct rrr_msg_msg *msg
) {
	int ret = 0;

	if (MSG_IS_ARRAY(msg)) {
		uint16_t array_version = 0;
		if ((ret = rrr_array_message_append_to_collection(&array_version, target, msg)) != 0) {
			goto out;
		}
	}
	else if (MSG_IS_DATA(msg)) {
		if ((ret = rrr_array_push_value_blob_with_tag_with_size(target, "http_body", MSG_DATA_PTR(msg), MSG_DATA_LENGTH(msg))) != 0) {
			goto out;
		}
	}
	else {
		RRR_MSG_0("Unknown message class %u in httpserver_receive_get_response_extract_data\n", MSG_CLASS(msg));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct httpserver_response_data {
	struct rrr_array target;
	char *request_topic;
	uint64_t time_begin;
};

static int httpserver_response_data_new (
		struct httpserver_response_data **target,
		rrr_http_unique_id unique_id
) {
	int ret = 0;

	*target = NULL;

	struct httpserver_response_data *result = malloc(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in httpserver_response_data_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((ret = httpserver_generate_unique_topic (
			&result->request_topic,
			RRR_HTTPSERVER_REQUEST_TOPIC_PREFIX,
			unique_id,
			NULL
	)) != 0) {
		goto out_free;
	}

	*target = result;
	goto out;
	out_free:
		free(result);
	out:
		return ret;
}

static void httpserver_response_data_destroy (
		struct httpserver_response_data *data
) {
	RRR_FREE_IF_NOT_NULL(data->request_topic);
	rrr_array_clear(&data->target);
	free(data);
}

static void httpserver_response_data_destroy_void (
		void *data
) {
	httpserver_response_data_destroy(data);
}

static void httpserver_response_data_destroy_if_not_null_void_dbl_ptr (
		void *arg
) {
	struct httpserver_response_data **data = arg;
	if (*data == NULL) {
		return;
	}
	httpserver_response_data_destroy(*data);
}

static int httpserver_receive_callback_response_get (
		struct httpserver_data *data,
		struct httpserver_response_data *response_data
) {
	int ret = 0;

	struct receive_get_response_callback_data callback_data = {0};

	pthread_cleanup_push(httpserver_receive_get_response_callback_data_cleanup, &callback_data);

	callback_data.topic_filter = response_data->request_topic;

	if (response_data->time_begin == 0) {
		response_data->time_begin = rrr_time_get_64();
	}

	if ((ret = rrr_fifo_buffer_search (
			&data->buffer,
			httpserver_receive_get_response_callback,
			&callback_data,
			0
	)) != 0) {
		RRR_MSG_0("Error from poll in httpserver_receive_callback_get_response\n");
		goto out;
	}

	if (data->response_timeout_ms == 0) {
		// No timeout
	}
	else if (rrr_time_get_64() > response_data->time_begin + data->response_timeout_ms * 1000) {
		RRR_DBG_1("Timeout while waiting for response from senders with filter '%s' in httpserver instance %s\n",
				response_data->request_topic, INSTANCE_D_NAME(data->thread_data));
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	if (callback_data.entry != NULL) {
		RRR_DBG_3("httpserver instance %s got a response from senders with filter %s\n",
				INSTANCE_D_NAME(data->thread_data), callback_data.topic_filter);

		rrr_msg_holder_lock(callback_data.entry);
		ret = httpserver_receive_get_response_extract_data (
				&response_data->target,
				(struct rrr_msg_msg *) callback_data.entry->message
		);
		rrr_msg_holder_unlock(callback_data.entry);

		goto out;
	}
	else {
		ret = RRR_HTTP_NO_RESULT;
	}

/*		if ((ret = rrr_net_transport_ctx_check_alive(handle)) != 0) {
			RRR_DBG_1("Connection closed while waiting for response from senders in httpserver instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}*/

	out:
	pthread_cleanup_pop(1);
	return ret;

}

static int httpserver_receive_callback_response_process_string_value (
	char **target,
	const struct rrr_type_value *value
) {
	int ret = 0;

	*target = NULL;

	char *result = NULL;

	if ((ret = value->definition->to_str(&result, value)) != 0) {
		RRR_MSG_0("Failed to convert field in response from senders to string in httpserver. Data type of array field was %s.\n",
			value->definition->identifier);
		ret = 1;
		goto out;
	}
	if (strlen(result) > 255) {
		RRR_MSG_0("Invalid string field in response from senders in httpserver, length exceeded 255 bytes. Data type of array field was %s.\n",
			value->definition->identifier);
		ret = 1;
		goto out;
	}

	*target = result;
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

#define VERIFY_SINGLE_ELEMENT(var,name)     \
	do {if(var->element_count != 1){    \
		RRR_MSG_0("Field " name " in response from senders in httpserver instance %s did not contain excactly one element\n", INSTANCE_D_NAME(data->thread_data)); \
	}} while (0)

static int httpserver_receive_callback_response_process (
	struct httpserver_data *data,
	struct httpserver_response_data *response_data,
	struct rrr_http_transaction *transaction
) {
	struct rrr_http_part *part = transaction->response_part;

	const struct rrr_type_value *value_response_code = rrr_array_value_get_by_tag_const(&response_data->target, "http_response_code");
	const struct rrr_type_value *value_content_type = rrr_array_value_get_by_tag_const(&response_data->target, "http_content_type");
	const struct rrr_type_value *value_body = rrr_array_value_get_by_tag_const(&response_data->target, "http_body");

	int ret = 0;

	char *content_type_to_free = NULL;
	char *body_to_free = NULL;

	if (value_response_code != NULL) {
		VERIFY_SINGLE_ELEMENT(value_response_code, "response code");

		unsigned int response_code_to_use = 0;

		unsigned long long response_code = value_response_code->definition->to_ull(value_response_code);
		if (response_code < 100 || response_code > 599) {
			RRR_MSG_0("Warning: Invalid response code %" PRIu64 " in response from senders in httpserver instance %s. Data type of array field was %s. Defaulting to 200.\n",
				response_code, INSTANCE_D_NAME(data->thread_data), value_response_code->definition->identifier);
			response_code = 200;
		}
		response_code_to_use = response_code;

		part->response_code = response_code_to_use;
	}

	if (value_body != NULL) {
		VERIFY_SINGLE_ELEMENT(value_body, "body");

		const char *content_type_to_use = NULL;

		switch (value_body->definition->type) {
			case RRR_TYPE_VAIN:
				break;
			case RRR_TYPE_BLOB:
			case RRR_TYPE_MSG:
			case RRR_TYPE_STR:
				if (value_body->total_stored_length > 0) {
					if ((ret = rrr_http_transaction_send_body_set (
						transaction,
						value_body->data,
						value_body->total_stored_length
					)) != 0) {
						goto out;
					}
				}
				break;
			default:
				if ((ret = value_body->definition->to_str(&body_to_free, value_body)) != 0) {
					RRR_MSG_0("Failed to process body field in httpserver instance %s. Data type of array field was %s.\n",
						INSTANCE_D_NAME(data->thread_data), value_body->definition->identifier);
					goto out;
				}
				break;
		};

		switch (value_body->definition->type) {
			case RRR_TYPE_MSG:
				content_type_to_use = "application/rrr-message";
				break;
			case RRR_TYPE_BLOB:
				content_type_to_use = "application/octet-stream";
				break;
			default:
				content_type_to_use = "text/plain";
				break;
		};

		if (value_content_type != 0) {
			VERIFY_SINGLE_ELEMENT(value_content_type, "content type");
			if ((ret = httpserver_receive_callback_response_process_string_value (&content_type_to_free, value_content_type)) != 0) {
				RRR_MSG_0("Failed to process content type field in httpserver instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
				goto out;
			}
			content_type_to_use = content_type_to_free;
		}

		if (content_type_to_use != NULL) {
			if ((ret = rrr_http_part_header_field_push(part, "Content-Type", content_type_to_use)) != 0) {
				goto out;
			}
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(body_to_free);
	RRR_FREE_IF_NOT_NULL(content_type_to_free);
	return ret;
}

// NOTE : Worker thread CTX in httpserver_async_response_get
static int httpserver_async_response_get (
		RRR_HTTP_SERVER_WORKER_ASYNC_RESPONSE_GET_CALLBACK_ARGS
) {
	struct httpserver_callback_data *receive_callback_data = arg;
	struct httpserver_data *data = receive_callback_data->httpserver_data;
	struct httpserver_response_data *response_data = transaction->application_data;

	int ret = 0;

	if ((ret = httpserver_receive_callback_response_get (data, response_data)) != 0) {
		goto out;
	}
	if ((ret = httpserver_receive_callback_response_process (data, response_data, transaction)) != 0) {
		goto out;
	}

	out:
	return ret;
}

// NOTE : Worker thread CTX in httpserver_receive_callback
static int httpserver_receive_callback (
		RRR_HTTP_SERVER_WORKER_RECEIVE_CALLBACK_ARGS
) {
	struct httpserver_callback_data *receive_callback_data = arg;
	struct httpserver_data *data = receive_callback_data->httpserver_data;

	(void)(thread);
	(void)(overshoot_bytes);

	int ret = 0;

	struct httpserver_response_data *response_data = NULL;

	static int fail_once = 1;

	if ((ret = httpserver_response_data_new(&response_data, transaction->unique_id)) != 0) {
		goto out_final;
	}

	pthread_cleanup_push(httpserver_response_data_destroy_if_not_null_void_dbl_ptr, &response_data);

	if (data->do_fail_once && fail_once) {
		RRR_MSG_0("Fail once debug is active in httpserver, sending 500 to client\n");
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR;
		fail_once = 0;
		goto out;
	}

	if (transaction->request_part->request_method == RRR_HTTP_METHOD_OPTIONS) {
		// Don't receive fields, let server framework send default reply
		RRR_DBG_3("Not processing fields from OPTIONS request, server will send default response.\n");
		goto out;
	}

	if (data->do_receive_full_request) {
		if ((RRR_HTTP_PART_BODY_LENGTH(transaction->request_part) == 0 && !data->do_allow_empty_messages)) {
			RRR_DBG_3("Zero length body from HTTP client, not creating RRR full request message\n");
		}
		else if ((ret = httpserver_receive_callback_full_request (
				&response_data->target,
				transaction->request_part,
				data_ptr,
				next_protocol_version
		)) != 0) {
			goto out;
		}
	}

	if ((ret = httpserver_receive_callback_get_fields (
			&response_data->target,
			data,
			transaction->request_part
	)) != 0) {
		goto out;
	}

	struct httpserver_write_message_callback_data write_callback_data = {
			&response_data->target,
			response_data->request_topic
	};

	if (RRR_LL_COUNT(&response_data->target) == 0 && data->do_allow_empty_messages == 0) {
		RRR_DBG_3("No array values set after processing request from HTTP client, not creating RRR array message\n");
	}
	else {
		const struct sockaddr *addr;
		socklen_t addr_len;
		rrr_net_transport_ctx_connected_address_get(&addr, &addr_len, handle);

		if ((ret = rrr_message_broker_write_entry (
				INSTANCE_D_BROKER_ARGS(data->thread_data),
				addr,
				addr_len,
				RRR_IP_TCP,
				httpserver_write_message_callback,
				&write_callback_data,
				INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
		)) != 0) {
			RRR_MSG_0("Error while saving message in httpserver_receive_callback\n");
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	if (data->allow_origin_header != NULL && *(data->allow_origin_header) != '\0') {
		if ((ret = rrr_http_part_header_field_push(transaction->response_part, "Access-Control-Allow-Origin", data->allow_origin_header)) != 0) {
			RRR_MSG_0("Failed to push allow-origin header in httpserver_receive_callback\n");
			ret = 1;
			goto out;
		}
	}

	if (data->do_get_response_from_senders) {
		rrr_http_transaction_application_data_set(transaction, (void **) &response_data, httpserver_response_data_destroy_void);
		ret = RRR_HTTP_NO_RESULT;
	}

	out:
		pthread_cleanup_pop(1);
	out_final:
		return ret;
}

struct receive_raw_broker_callback_data {
	struct httpserver_data *parent_data;
	const struct rrr_nullsafe_str *data;
	const char *topic;
	int is_full_rrr_msg;
};

static int httpserver_receive_raw_broker_callback (
		struct rrr_msg_holder *entry_new,
		void *arg
) {
	struct receive_raw_broker_callback_data *write_callback_data = arg;
	struct httpserver_data *data = write_callback_data->parent_data;

	int ret = 0;

	char *topic_tmp = NULL;

	struct rrr_msg *msg_to_free = NULL;

	if (write_callback_data->is_full_rrr_msg) {
		if ((msg_to_free = malloc(rrr_nullsafe_str_len(write_callback_data->data))) == NULL) {
			RRR_MSG_0("Could not allocate memory for RRR message in httpserver_receive_raw_broker_callback\n");
			ret = RRR_HTTP_SOFT_ERROR; // Client may be at fault, don't make hard error
			goto out;
		}

		rrr_length written_size = 0;
		rrr_nullsafe_str_copyto (
				&written_size,
				msg_to_free,
				rrr_nullsafe_str_len(write_callback_data->data),
				write_callback_data->data
		);

		if (rrr_msg_head_to_host_and_verify(msg_to_free, rrr_nullsafe_str_len(write_callback_data->data))) {
			RRR_MSG_0("Received RRR message of which head verification failed in HTTP server instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		if (rrr_msg_check_data_checksum_and_length(msg_to_free, rrr_nullsafe_str_len(write_callback_data->data)) != 0) {
			RRR_MSG_0("Received RRR message CRC32 mismatch in HTTP server instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}

		{
			struct rrr_msg_msg *msg_msg = (struct rrr_msg_msg *) msg_to_free;
			if (rrr_msg_msg_to_host_and_verify(msg_msg, rrr_nullsafe_str_len(write_callback_data->data)) != 0) {
				RRR_MSG_0("Received RRR message was invalid in HTTP server instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				ret = RRR_HTTP_SOFT_ERROR;
				goto out;
			}

			if (write_callback_data->topic != NULL) {
				if (MSG_TOPIC_LENGTH(msg_msg)) {
					if (rrr_asprintf(&topic_tmp, "%s/%.*s", write_callback_data->topic, MSG_TOPIC_LENGTH(msg_msg), MSG_TOPIC_PTR(msg_msg)) <= 0) {
						RRR_MSG_0("Failed to allocate memory for topic A in httpserver_receive_raw_broker_callback\n");
						ret = RRR_HTTP_HARD_ERROR;
						goto out;
					}
				}
				else {
					if (rrr_asprintf(&topic_tmp, "%s", write_callback_data->topic) <= 0) {
						RRR_MSG_0("Failed to allocate memory for topic B in httpserver_receive_raw_broker_callback\n");
						ret = RRR_HTTP_HARD_ERROR;
						goto out;
					}
				}
			}

			if (topic_tmp != NULL) {
				if (rrr_msg_msg_topic_set(&msg_msg, topic_tmp, strlen(topic_tmp)) != 0) {
					RRR_MSG_0("Failed to set topic in httpserver_receive_raw_broker_callback\n");
					ret = RRR_HTTP_SOFT_ERROR; // Client may be at fault, don't make hard error
					goto out;
				}
				msg_to_free = (struct rrr_msg *) msg_msg;
			}
		}

		entry_new->message = msg_to_free;
		entry_new->data_length = MSG_TOTAL_SIZE(msg_to_free);

		msg_to_free = NULL;

		RRR_DBG_3("httpserver instance %s created RRR message from httpserver data of size %" PRIrrr_nullsafe_len " topic '%s'\n",
				INSTANCE_D_NAME(write_callback_data->parent_data->thread_data),
				rrr_nullsafe_str_len(write_callback_data->data),
				write_callback_data->topic
		);
	}
	else {
		if ((ret = rrr_msg_msg_new_with_data_nullsafe (
				(struct rrr_msg_msg **) &entry_new->message,
				MSG_TYPE_MSG,
				MSG_CLASS_DATA,
				rrr_time_get_64(),
				write_callback_data->topic,
				(write_callback_data->topic != NULL ? strlen(write_callback_data->topic) : 0),
				write_callback_data->data
		)) != 0) {
			RRR_MSG_0("Could not create message in httpserver_receive_raw_broker_callback\n");
			goto out;
		}

		entry_new->data_length = MSG_TOTAL_SIZE((struct rrr_msg_msg *) entry_new->message);

		RRR_DBG_3("httpserver instance %s created raw httpserver data message with data size %" PRIrrrl " topic %s\n",
				INSTANCE_D_NAME(write_callback_data->parent_data->thread_data),
				rrr_nullsafe_str_len(write_callback_data->data),
				write_callback_data->topic
		);
	}

	out:
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	RRR_FREE_IF_NOT_NULL(msg_to_free);
	rrr_msg_holder_unlock(entry_new);
	return ret;
}

// NOTE : Worker thread CTX in httpserver_receive_websocket_callback
static int httpserver_websocket_handshake_callback (
		RRR_HTTP_SERVER_WORKER_WEBSOCKET_HANDSHAKE_CALLBACK_ARGS
) {
	struct httpserver_callback_data *callback_data = arg;

	*do_websocket = 1;

	(void)(data_ptr);
	(void)(handle);
	(void)(overshoot_bytes);
	(void)(next_protocol_version);

	int ret = 0;

	char *application_topic_new = NULL;

	RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(request_uri, transaction->request_part->request_uri_nullsafe);

	if (rrr_nullsafe_str_len(transaction->request_part->request_uri_nullsafe) > sizeof(request_uri) - 1) {
		RRR_MSG_0("Received request URI for websocket request was too long (%" PRIrrrl " > %ld)",
				rrr_nullsafe_str_len(transaction->request_part->request_uri_nullsafe), (unsigned long) sizeof(request_uri) - 1);
		goto out_bad_request;
	}

	// Skip first /
	const char *topic_begin = request_uri + 1;
	if (strlen(topic_begin) == 0) {
		RRR_MSG_0("Received zero-length websocket topic from client in httpserver instance %s\n",
				INSTANCE_D_NAME(callback_data->httpserver_data->thread_data));
		goto out_bad_request;
	}

	char *questionmark = strchr(topic_begin, '?');
	if (questionmark) {
		*questionmark = '\0';
	}

	if (rrr_mqtt_topic_validate_name(topic_begin) != 0) {
		RRR_MSG_0("Received invalid websocket topic '%s' from client in httpserver instance %s\n",
				topic_begin, INSTANCE_D_NAME(callback_data->httpserver_data->thread_data));
		goto out_bad_request;
	}

	int topic_ok = 0;
	RRR_MAP_ITERATE_BEGIN(&callback_data->httpserver_data->websocket_topic_filters);
		if (rrr_mqtt_topic_match_str(topic_begin, node_tag)) {
			RRR_DBG_3("httpserver %s websocket topic '%s' matched with topic filter '%s'\n",
					INSTANCE_D_NAME(callback_data->httpserver_data->thread_data),
					topic_begin,
					node_tag);
			topic_ok = 1;
			break;
		}
		else {
			RRR_DBG_3("httpserver %s websocket topic '%s' mismatch with topic filter '%s'\n",
					INSTANCE_D_NAME(callback_data->httpserver_data->thread_data),
					topic_begin,
					node_tag);
		}
	RRR_MAP_ITERATE_END();

	if (!topic_ok) {
		goto out_not_found;
	}

	if ((application_topic_new = strdup(topic_begin)) == NULL) {
		RRR_MSG_0("Could not allocate memory for application data in httpserver_websocket_handshake_callback \n");
		ret = 1;
		goto out;
	}

	*application_topic = application_topic_new;
	application_topic_new = NULL;

	goto out;
	out_not_found:
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_NOT_FOUND;
		goto out;
	out_bad_request:
		transaction->response_part->response_code = RRR_HTTP_RESPONSE_CODE_ERROR_BAD_REQUEST;
		goto out;
	out:
		RRR_FREE_IF_NOT_NULL(application_topic_new);
		return ret;
}

static int httpserver_websocket_get_response_callback_extract_data (
		void **data,
		ssize_t *data_len,
		int *is_binary,
		struct rrr_msg_holder *entry,
		rrr_http_unique_id unique_id
) {
	int ret = 0;

	*data = NULL;
	*data_len = 0;
	*is_binary = 0;

	void *response_data = NULL;

	rrr_msg_holder_lock(entry);

	struct rrr_msg_msg *msg = entry->message;

	if (MSG_DATA_LENGTH(msg) > SSIZE_MAX) {
		RRR_MSG_0("Received websocket response from other module for unique id %" PRIu64 " exceeds maximum size %" PRIu64 ">%li\n",
				unique_id, (uint64_t) MSG_DATA_LENGTH(msg), (uint64_t) SSIZE_MAX);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out_unlock;
	}
	else if (MSG_DATA_LENGTH(msg) == 0) {
		if ((response_data = strdup("")) == NULL) {
			RRR_MSG_0("Could not allocate memory in httpserver_websocket_get_response_callback_extract_data\n");
			ret = 1;
			goto out_unlock;
		}
	}
	else {
		if ((response_data = malloc(MSG_DATA_LENGTH(msg))) == NULL) {
			RRR_MSG_0("Could not allocate memory in httpserver_websocket_get_response_callback_extract_data\n");
			ret = 1;
			goto out_unlock;
		}
		memcpy(response_data, MSG_DATA_PTR(msg), MSG_DATA_LENGTH(msg));
	}

	*data = response_data;
	*data_len = MSG_DATA_LENGTH(msg);

	response_data = NULL;

	out_unlock:
	RRR_FREE_IF_NOT_NULL(response_data);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int httpserver_websocket_get_response_callback (RRR_HTTP_SERVER_WORKER_WEBSOCKET_GET_RESPONSE_CALLBACK_ARGS) {
	struct httpserver_callback_data *httpserver_callback_data = arg;

	(void)(application_topic);

	int ret = 0;

	char *topic_filter = NULL;

	struct receive_get_response_callback_data callback_data = {0};

	pthread_cleanup_push(httpserver_receive_get_response_callback_data_cleanup, &callback_data);
	pthread_cleanup_push(rrr_http_util_dbl_ptr_free, &topic_filter);

	if ((ret = httpserver_generate_unique_topic (
			&topic_filter,
			RRR_HTTPSERVER_WEBSOCKET_TOPIC_PREFIX,
			unique_id,
			"#"
	)) != 0) {
		goto out;
	}

	callback_data.topic_filter = topic_filter;

	if ((ret = rrr_fifo_buffer_search (
			&httpserver_callback_data->httpserver_data->buffer,
			httpserver_receive_get_response_callback,
			&callback_data,
			0
	)) != 0) {
		RRR_MSG_0("Error from poll in httpserver_websocket_get_response_callback\n");
		goto out;
	}

	if (callback_data.entry != NULL) {
		if ((ret = httpserver_websocket_get_response_callback_extract_data (
			data,
			data_len,
			is_binary,
			callback_data.entry,
			unique_id
		)) != 0) {
			goto out;
		}
	}

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	return ret;
}

static int httpserver_websocket_frame_callback (RRR_HTTP_SERVER_WORKER_WEBSOCKET_FRAME_CALLBACK_ARGS) {
	struct httpserver_callback_data *callback_data = arg;
	struct httpserver_data *data = callback_data->httpserver_data;

	int ret = 0;

	char *topic = NULL;

	if ((ret = httpserver_generate_unique_topic (
			&topic,
			RRR_HTTPSERVER_WEBSOCKET_TOPIC_PREFIX,
			unique_id,
			application_topic
	)) != 0) {
		goto out;
	}

	struct receive_raw_broker_callback_data write_callback_data = {
		callback_data->httpserver_data,
		payload,
		topic,
		(is_binary && data->do_receive_websocket_rrr_message)
	};

	// To avoid extra data copying and because payload is const, validation
	// of any binary RRR message is performed in write callback

	const struct sockaddr *addr;
	socklen_t addr_len;
	rrr_net_transport_ctx_connected_address_get(&addr, &addr_len, handle);

	ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->httpserver_data->thread_data),
			addr,
			addr_len,
			RRR_IP_TCP,
			httpserver_receive_raw_broker_callback,
			&write_callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	);

	out:
		RRR_FREE_IF_NOT_NULL(topic);
		return ret;
}

static int httpserver_unique_id_generator_callback (
		RRR_HTTP_SESSION_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
) {
	struct httpserver_callback_data *data = arg;

	return rrr_message_broker_get_next_unique_id (
			unique_id,
			INSTANCE_D_BROKER_ARGS(data->httpserver_data->thread_data)
	);
}

static int httpserver_poll_callback_write (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_msg_holder *entry = arg;
	rrr_msg_holder_incref_while_locked(entry);
	*data = (char *) entry;
	*size = sizeof(*entry);
	*order = 0;
	return RRR_FIFO_OK;
}

static int httpserver_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct httpserver_data *data = thread_data->private_data;

	int ret = rrr_fifo_buffer_write(&data->buffer, httpserver_poll_callback_write, entry);
	rrr_msg_holder_unlock(entry);
	return ret;
}

// If we receive messages from senders which no worker seem to want, we must delete them
static int httpserver_housekeep_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	struct httpserver_callback_data *callback_data = arg;
	struct rrr_msg_holder *entry = (struct rrr_msg_holder *) data;

	(void)(size);

	int ret = RRR_FIFO_SEARCH_KEEP;

	rrr_msg_holder_lock(entry);

	if (entry->buffer_time == 0) {
		RRR_BUG("BUG: Buffer time was 0 for entry in httpserver_housekeep_callback\n");
	}

	uint64_t timeout = entry->buffer_time + callback_data->httpserver_data->response_timeout_ms * 1000;
	if (rrr_time_get_64() > timeout) {
		struct rrr_msg_msg *msg = entry->message;
		RRR_DBG_1("httpserver instance %s deleting message from senders of size %u which has timed out\n",
				INSTANCE_D_NAME(callback_data->httpserver_data->thread_data), MSG_TOTAL_SIZE(msg));
		ret = RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE;
	}

	rrr_msg_holder_unlock(entry);
	return ret;
}

static void *thread_entry_httpserver (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpserver_data *data = thread_data->private_data = thread_data->private_memory;

	if (thread_data->init_data.instance->misc_flags & RRR_INSTANCE_MISC_OPTIONS_DISABLE_BUFFER) {
		RRR_MSG_1("Note: httpserver instance %s has input buffer disabled, performance when data is retrieved from senders may be impacted.\n",
			INSTANCE_D_NAME(thread_data));
	}

	if (httpserver_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in httpserver instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("httpserver thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(httpserver_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (httpserver_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("httpserver started thread %p\n", thread_data);

	struct rrr_http_server *http_server = NULL;

	{
		uint64_t startup_time = rrr_time_get_64() + data->startup_delay_us;
		while (rrr_thread_signal_encourage_stop_check(thread) != 1 && startup_time > rrr_time_get_64()) {
			rrr_thread_watchdog_time_update(thread);
			RRR_DBG_1("httpserver instance %s startup delay configured, waiting...\n",
				INSTANCE_D_NAME(thread_data));
			rrr_posix_usleep(500000);
		}
	}

	if (rrr_http_server_new(&http_server, data->do_disable_http2) != 0) {
		RRR_MSG_0("Could not create HTTP server in httpserver instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	// TODO : There are occasional (?) reports from valgrind that http_server is
	//        not being freed upon program exit. This happens if a worker thread
	//        hangs (e.g. on blocking send with full pipe) while we try to exit.

	pthread_cleanup_push(rrr_http_server_destroy_void, http_server);

	if (httpserver_start_listening(data, http_server) != 0) {
		goto out_cleanup_httpserver;
	}

	unsigned int accept_count_total = 0;
	uint64_t prev_stats_time = rrr_time_get_64();

	struct httpserver_callback_data callback_data = {
			data,
			http_server->threads
	};

	struct rrr_http_server_callbacks callbacks = {
		httpserver_unique_id_generator_callback,
		&callback_data,
		(RRR_LL_COUNT(&data->websocket_topic_filters) > 0 ? httpserver_websocket_handshake_callback : NULL),
		(RRR_LL_COUNT(&data->websocket_topic_filters) > 0 ? &callback_data : NULL),
		(RRR_LL_COUNT(&data->websocket_topic_filters) > 0 ? httpserver_websocket_frame_callback : NULL),
		(RRR_LL_COUNT(&data->websocket_topic_filters) > 0 ? &callback_data : NULL),
		(RRR_LL_COUNT(&data->websocket_topic_filters) > 0 ? httpserver_websocket_get_response_callback : NULL),
		(RRR_LL_COUNT(&data->websocket_topic_filters) > 0 ? &callback_data : NULL),
		httpserver_receive_callback,
		&callback_data,
		httpserver_async_response_get,
		&callback_data
	};

	while (rrr_thread_signal_encourage_stop_check(thread) != 1) {
		rrr_thread_watchdog_time_update(thread);

		// TODO : Convert to events to prevent delay
		uint16_t amount = 100;
		if (rrr_poll_do_poll_delete (
				&amount,
				data->thread_data,
				httpserver_poll_callback,
				0
		) != 0) {
			RRR_MSG_0("Error from poll in httpserver instance %s\n", INSTANCE_D_NAME(thread_data));
			break;
		}

		if (amount == 100) {
			rrr_posix_usleep(20000); // 20ms
		}

		int accept_count = 0;

		if (rrr_http_server_tick (
				&accept_count,
				http_server,
				data->worker_threads,
				&callbacks
		) != 0) {
			RRR_MSG_0("Failure in main loop in httpserver instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		accept_count_total += accept_count;

		uint64_t time_now = rrr_time_get_64();
		if (time_now > prev_stats_time + 1000000) {
			rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 1, "accepted", accept_count_total);

			accept_count_total = 0;

			prev_stats_time = time_now;
		}

		if (rrr_fifo_buffer_search (
				&data->buffer,
				httpserver_housekeep_callback,
				&callback_data,
				0
		)) {
			break;
		}
	}

	RRR_DBG_1 ("Thread httpserver %p instance %s looping ended\n", thread, INSTANCE_D_NAME(thread_data));

	out_cleanup_httpserver:
	rrr_thread_state_set(thread, RRR_THREAD_STATE_STOPPING);
	pthread_cleanup_pop(1);

	out_message:
	RRR_DBG_1 ("Thread httpserver %p instance %s exiting\n", thread, INSTANCE_D_NAME(thread_data));

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_httpserver,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "httpserver";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
}

void unload(void) {
	RRR_DBG_1 ("Destroy httpserver module\n");
}
