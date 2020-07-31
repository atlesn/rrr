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
#include "../lib/http/http_client.h"
#include "../lib/http/http_client_config.h"
#include "../lib/http/http_query_builder.h"
#include "../lib/http/http_session.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/ip/ip_buffer_entry.h"
#include "../lib/ip/ip_buffer_entry_struct.h"
#include "../lib/ip/ip_buffer_entry_collection.h"

#define RRR_HTTPCLIENT_DEFAULT_SERVER			"localhost"
#define RRR_HTTPCLIENT_DEFAULT_PORT				0 // 0=automatic
#define RRR_HTTPCLIENT_DEFAULT_REDIRECTS_MAX	5
#define RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX		500

struct httpclient_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_http_client_data http_client_data;
	struct rrr_ip_buffer_entry_collection defer_queue;

	int do_no_data;
	int do_rrr_msg_to_array;
	int do_drop_on_error;
	rrr_setting_uint message_timeout_us;

	rrr_setting_uint redirects_max;

	struct rrr_net_transport_config net_transport_config;

	// Array fields, server name etc.
	struct rrr_http_client_config http_client_config;
};

static int httpclient_send_request_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	(void)(data);
	(void)(response_code);
	(void)(response_argument);
	(void)(chunk_idx);
	(void)(chunk_total);
	(void)(data_start);
	(void)(data_size);

	// Note : Don't mix up rrr_http_client_data and httpclient_data

	struct httpclient_data *httpclient_data = arg;

	int ret = RRR_HTTP_OK;

	if (response_code < 200 || response_code > 299) {
		RRR_BUG("BUG: Invalid response %i propagated from http framework to httpclient module\n", response_code);
	}

	RRR_DBG_1("HTTP response from server in httpclient instance %s: %i %s\n",
			INSTANCE_D_NAME(httpclient_data->thread_data),
			response_code,
			(response_argument != NULL ? response_argument : "(no response string)")
	);

	return ret;
}

static int httpclient_session_add_field (
		struct httpclient_data *data,
		struct rrr_http_session *session,
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

		ret = rrr_http_session_query_field_add (
				session,
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
			ret = rrr_http_session_query_field_add (
					session,
					tag_to_use,
					buf,
					buf_size,
					"text/plain"
			);
		}
	}
	else if (RRR_TYPE_IS_BLOB(value->definition->type)) {
		ret = rrr_http_session_query_field_add (
				session,
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

		ret = rrr_http_session_query_field_add (
				session,
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

struct httpclient_add_fields_callback_data {
	struct httpclient_data *data;
	const struct rrr_array *array;
};

static int httpclient_session_add_fields_callback (
		RRR_HTTP_CLIENT_BEFORE_SEND_CALLBACK_ARGS
) {
	struct httpclient_add_fields_callback_data *callback_data = arg;
	struct httpclient_data *data = callback_data->data;

	*query_string = NULL;

	int ret = RRR_HTTP_OK;

	if (data->do_no_data != 0 && (RRR_MAP_COUNT(&data->http_client_config.tags) + RRR_LL_COUNT(callback_data->array) > 0)) {
		RRR_BUG("BUG: HTTP do_no_data is set but tags map and array are not empty in httpclient_session_add_fields_callback\n");
	}

	if (RRR_MAP_COUNT(&data->http_client_config.tags) == 0) {
		// Add all array fields
		RRR_LL_ITERATE_BEGIN(callback_data->array, const struct rrr_type_value);
			if ((ret = httpclient_session_add_field (
					data,
					session,
					node,
					node->tag
			)) != RRR_HTTP_OK) {
				goto out;
			}
		RRR_LL_ITERATE_END();
	}
	else {
		// Add chosen array fields
		RRR_MAP_ITERATE_BEGIN(&data->http_client_config.tags);
			const struct rrr_type_value *value = rrr_array_value_get_by_tag_const(callback_data->array, node_tag);
			if (value == NULL) {
				RRR_MSG_0("Could not find array tag %s while adding HTTP query values in instance %s.\n",
						node_tag, INSTANCE_D_NAME(data->thread_data));
				goto out;
			}

			// If value is set in map, tag is to be translated
			const char *tag_to_use = (node_value != NULL && *node_value != '\0') ? node_value : node_tag;

			if ((ret = httpclient_session_add_field (
					data,
					session,
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
		if ((ret = rrr_http_session_query_field_add (
				session,
				node_tag,
				node_value,
				strlen(node_value),
				"text/plain"
		)) != RRR_HTTP_OK) {
			goto out;
		}
	RRR_MAP_ITERATE_END();

	if (RRR_DEBUGLEVEL_3) {
		RRR_MSG_3("HTTP using method %s\n", RRR_HTTP_METHOD_TO_STR(session->method));
		rrr_http_session_query_fields_dump(session);
	}

	out:
		return ret;
}

static int httpclient_reset_client_data (
		struct httpclient_data *data
) {
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
			&data->http_client_data,
			&data->http_client_config,
			http_transport_force
	) != 0) {
		RRR_MSG_0("Could not store HTTP client configuration in httpclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		return RRR_HTTP_HARD_ERROR;
	}

	return RRR_HTTP_OK;
}

static int httpclient_get_values_from_message (
		struct rrr_array *target_array,
		struct httpclient_data *data,
		const struct rrr_message *message
) {
	int ret = 0;

	if (MSG_IS_ARRAY(message)) {
		if (rrr_array_message_append_to_collection(target_array, message) != 0) {
			RRR_MSG_0("Error while converting message to collection in httpclient_get_values_from_message\n");
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
	}

	if (data->do_rrr_msg_to_array) {
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
	}

	out:
	return ret;
}

static int httpclient_send_request_locked (
		struct httpclient_data *data,
		struct rrr_ip_buffer_entry *entry
) {
	struct rrr_message *message = entry->message;
	struct rrr_array array_tmp = {0};

	array_tmp.version = RRR_ARRAY_VERSION;

	int ret = RRR_HTTP_OK;

	RRR_DBG_3("httpclient instance %s sending message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(data->thread_data), message->timestamp);

	if ((ret = httpclient_reset_client_data(data)) != RRR_HTTP_OK) {
		goto out;
	}

	(void)(message);

	if (data->message_timeout_us != 0) {
		if (rrr_time_get_64() > entry->send_time + data->message_timeout_us) {
			RRR_MSG_0("Send timeout for message in httpclient instance %s, dropping it.\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
	}

	// If tag filtering is performed, this is done in add_fields_callback. Here, all
	// values are prepared in the temporary array.
	if (data->do_no_data == 0) {
		if ((ret = httpclient_get_values_from_message(&array_tmp, data, message)) != RRR_HTTP_OK) {
			goto out;
		}
	}

	// DO NOT use unsigned here.
	long long int redirect_retry_max = data->redirects_max;

	retry:

	if (redirect_retry_max > RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX || redirect_retry_max < 0) {
		RRR_BUG("Redirect counter error in httpclient_send_request_locked, value is now %i\n", redirect_retry_max);
	}

	struct httpclient_add_fields_callback_data add_fields_callback_data = {
		data,
		&array_tmp
	};

	if ((ret = rrr_http_client_send_request (
			&data->http_client_data,
			data->http_client_config.method,
			&data->net_transport_config,
			httpclient_session_add_fields_callback,
			&add_fields_callback_data,
			httpclient_send_request_callback,
			data
	)) != RRR_HTTP_OK) {
		if (ret == RRR_HTTP_SOFT_ERROR) {
			RRR_DBG_2("HTTP request failed in httpclient instance %s, return was %i\n",
					INSTANCE_D_NAME(data->thread_data), ret);
		}
		else {
			RRR_MSG_0("HTTP request failed in httpclient instance %s, return was %i\n",
					INSTANCE_D_NAME(data->thread_data), ret);
		}

		if (data->do_drop_on_error) {
			RRR_MSG_0("Dropping message per configuration after error in httpclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_OK;
		}

		goto out;
	}

	if (data->http_client_data.do_retry != 0) {
		if (--redirect_retry_max >= 0) {
			goto retry;
		}
		else {
			RRR_MSG_0("Maximum numbers of redirects reached in httpclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int httpclient_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
//	printf ("httpclient got entry %p\n", entry);

	struct rrr_instance_thread_data *thread_data = arg;
	struct httpclient_data *data = thread_data->private_data;
	struct rrr_message *message = entry->message;

	RRR_DBG_3("httpclient instance %s received message with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	// Important : Set send_time for correct timeout behavior
	entry->send_time = rrr_time_get_64();

	int ret = RRR_FIFO_OK;

	if ((ret = httpclient_send_request_locked(data, entry)) != 0) {
		if (ret == RRR_HTTP_SOFT_ERROR) {
			RRR_MSG_0("Soft error while sending message in httpclient instance %s, deferring message\n",
					INSTANCE_D_NAME(thread_data));
			ret = 0;
			goto out_defer;
		}
		RRR_MSG_0("Hard error while sending message in httpclient instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = RRR_HTTP_HARD_ERROR;
		goto out;
	}

	goto out;
	out_defer:
		rrr_ip_buffer_entry_incref_while_locked(entry);
		RRR_LL_APPEND(&data->defer_queue, entry);
		rrr_ip_buffer_entry_unlock(entry);
		return RRR_FIFO_SEARCH_STOP;
	out:
		rrr_ip_buffer_entry_unlock(entry);
		return ret;
}

static void httpclient_data_cleanup(void *arg) {
	struct httpclient_data *data = arg;
	rrr_http_client_data_cleanup(&data->http_client_data);
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_http_client_config_cleanup(&data->http_client_config);
	rrr_ip_buffer_entry_collection_clear(&data->defer_queue);
}

static int httpclient_data_init (
		struct httpclient_data *data,
		struct rrr_instance_thread_data *thread_data
) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	if ((ret = rrr_http_client_data_init(&data->http_client_data, RRR_HTTP_CLIENT_USER_AGENT)) != 0) {
		RRR_MSG_0("Could not initialize httpclient data in httpclient_data_init\n");
		ret = 1;
		goto out;
	}

	goto out;
//	out_cleanup_data:
//		httpclient_data_cleanup(data);
	out:
		return ret;
}

static int httpclient_parse_config (
		struct httpclient_data *data,
		struct rrr_instance_config *config
) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_no_data", do_no_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_rrr_msg_to_array", do_rrr_msg_to_array, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_drop_on_error", do_drop_on_error, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_message_timeout_ms", message_timeout_us, 0);
	// Remember to mulitply to get useconds. Zero means no timeout.
	data->message_timeout_us *= 1000;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_max_redirects", redirects_max, RRR_HTTPCLIENT_DEFAULT_REDIRECTS_MAX);

	if (data->redirects_max > RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX) {
		RRR_MSG_0("Setting http_max_redirects of instance %s oustide range, maximum is %i\n",
				config->name, RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX);
		ret = 1;
		goto out;
	}

	if (rrr_http_client_config_parse (
			&data->http_client_config,
			config,
			"http",
			RRR_HTTPCLIENT_DEFAULT_SERVER,
			RRR_HTTPCLIENT_DEFAULT_PORT,
			0, // <-- Disable fixed tags and fields
			1  // <-- Enable endpoint
	) != 0) {
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
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data = thread_data->private_memory;

	if (httpclient_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize thread_data in httpclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("httpclient thread thread_data is %p\n", thread_data);

	pthread_cleanup_push(httpclient_data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (httpclient_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_poll_add_from_thread_senders (thread_data->poll, thread_data);

	RRR_DBG_1 ("httpclient started thread %p\n", thread_data);

	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		if (RRR_LL_COUNT(&data->defer_queue) > 0) {
			int ret_tmp = RRR_HTTP_OK;

			RRR_LL_ITERATE_BEGIN(&data->defer_queue, struct rrr_ip_buffer_entry);
				rrr_ip_buffer_entry_lock(node);
				if ((ret_tmp = httpclient_send_request_locked(data, node)) != RRR_HTTP_OK) {
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
				rrr_ip_buffer_entry_unlock(node);
			RRR_LL_ITERATE_END_CHECK_DESTROY(&data->defer_queue, 0; rrr_ip_buffer_entry_decref(node));

			if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
				rrr_posix_usleep(500000); // 500ms to avoid spamming server when there are errors
			}
		}
		else {
			if (rrr_poll_do_poll_delete (thread_data, thread_data->poll, httpclient_poll_callback, 50) != 0) {
				RRR_MSG_ERR("Error while polling in httpclient instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}
	}

	out_message:
	RRR_DBG_1 ("Thread httpclient %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	RRR_DBG_1("Dummy configuration test for instance %s\n", config->name);
	return 0;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_httpclient,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "httpclient";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_DEADEND;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy httpclient module\n");
}
