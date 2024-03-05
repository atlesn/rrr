/*

Read Route Record

Copyright (C) 2020-2024 Atle Solbakken atle@goliathdns.no

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
#include <strings.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/poll_helper.h"
#include "../lib/msgdb_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/array.h"
#include "../lib/helpers/string_builder.h"
#include "../lib/event/event.h"
#include "../lib/event/event_functions.h"
#include "../lib/event/event_collection.h"
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
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/helpers/nullsafe_str.h"
#include "../lib/msgdb/msgdb_client.h"
#include "../lib/random.h"
#include "../lib/stats/stats_instance.h"

#define RRR_HTTPCLIENT_DEFAULT_SERVER                    "localhost"
#define RRR_HTTPCLIENT_DEFAULT_PORT                      0 // 0=automatic
#define RRR_HTTPCLIENT_DEFAULT_REDIRECTS_MAX             5
#define RRR_HTTPCLIENT_DEFAULT_CONCURRENT_CONNECTIONS    10
#define RRR_HTTPCLIENT_DEFAULT_RESPONSE_MAX_MB           10
#define RRR_HTTPCLIENT_LIMIT_REDIRECTS_MAX               500
#define RRR_HTTPCLIENT_READ_MAX_SIZE                     1 * 1024 * 1024 * 1024 // 1 GB
#define RRR_HTTPCLIENT_DEFAULT_KEEPALIVE_MAX_S           5
#define RRR_HTTPCLIENT_SEND_CHUNK_COUNT_LIMIT            100000
#define RRR_HTTPCLIENT_DEFAULT_MSGDB_POLL_INTERVAL_S     30
#define RRR_HTTPCLIENT_MSGDB_POLL_MAX                    50000
#define RRR_HTTPCLIENT_INPUT_QUEUE_MAX                   500

struct httpclient_response_code_summary {
	uint16_t code;
	rrr_length count;
};

struct httpclient_response_code_summary_collection {
	struct httpclient_response_code_summary *codes;
	size_t size;
	size_t count;
};

struct httpclient_transaction_data {
	char *msg_topic;
	struct rrr_msg_holder *entry;
};

struct httpclient_redirect_data {
	struct rrr_http_client_request_data request_data;
	rrr_biglength remaining_redirects;
	enum rrr_http_version protocol_version;
};

struct httpclient_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_msg_holder_collection from_senders_queue;
	struct rrr_msg_holder_collection low_pri_queue;
	struct rrr_msg_holder_collection from_msgdb_queue;
	struct rrr_msg_holder_collection periodic_request_queue;

	int low_pri_queue_need_rotate;
	int from_msgdb_queue_need_rotate;
	rrr_length connection_soft_error_dropped_count;

	struct rrr_msgdb_client_conn msgdb_conn_store;
	struct rrr_msgdb_client_conn msgdb_conn_iterate;

	rrr_setting_uint response_max_mb;
	rrr_biglength response_max_size;

	int do_no_data;
	int do_rrr_msg_to_array;
	int do_drop_on_error;
	int do_receive_part_data;
#ifdef RRR_WITH_JSONC
	int do_receive_json_data;
#endif
	int do_receive_ignore_error_part_data;
	int do_receive_404_as_empty_part;
	int do_receive_structured;
	int do_low_priority_put;

	int do_endpoint_from_topic;
	int do_endpoint_from_topic_force;

	int do_meta_tags_ignore;

	char *taint_tag;
	char *report_tag;

	char *method_tag;
	int do_method_tag_force;

	char *content_type_tag;
	int do_content_type_tag_force;

	char *content_type_boundary_tag;
	int do_content_type_boundary_tag_force;

	char *format_tag;
	int do_format_tag_force;

	char *endpoint_tag;
	int do_endpoint_tag_force;

	char *server_tag;
	int do_server_tag_force;

	char *port_tag;
	int do_port_tag_force;

	char *body_tag;
	int do_body_tag_force;

	struct rrr_map meta_tags_all;

	char *http_header_accept;

	rrr_setting_uint message_queue_timeout_us;
	rrr_setting_uint message_ttl_us;
	rrr_setting_uint message_low_pri_timeout_factor;

	rrr_setting_uint redirects_max;

	struct rrr_event_collection events;
	rrr_event_handle event_msgdb_poll;
	rrr_event_handle event_queue_process;
	rrr_event_handle event_periodic_request;

	char *msgdb_socket;
	rrr_setting_uint msgdb_poll_interval_us;

	rrr_setting_uint silent_put_error_limit_us;
	rrr_setting_uint request_interval_us;

	struct httpclient_response_code_summary_collection response_code_summaries;

	struct rrr_net_transport_config net_transport_config;

	struct rrr_http_client *http_client;
	struct rrr_http_client_request_data request_data;

	rrr_http_unique_id unique_id_counter;

	struct rrr_http_client_config http_client_config;
};

static int httpclient_response_code_summary_push (
		struct httpclient_response_code_summary_collection *summaries,
		uint16_t code
) {
	struct httpclient_response_code_summary *ptr;

	if (summaries->size == summaries->count) {
		size_t size_new = summaries->size + 4;
		if ((ptr = rrr_reallocate(summaries->codes, size_new * sizeof(*ptr))) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			return 1;
		}
		summaries->size = size_new;
		summaries->codes = ptr;
	}

	ptr = summaries->codes + summaries->count++;

	memset(ptr, 0, sizeof(*ptr));

	ptr->code = (uint16_t) code;

	return 0;
}

static int httpclient_response_code_summary_consume (
		struct httpclient_response_code_summary_collection *summaries,
		uint16_t code
) {
	for (size_t i = 0; i < summaries->count; i++) {
		struct httpclient_response_code_summary *ptr = summaries->codes + i;
		if (ptr->code == code) {
			ptr->count++;
			return 1;
		}
	}

	return 0;
}

static void httpclient_check_queues_and_activate_event_as_needed (
	struct httpclient_data *data
) {
	if ( RRR_LL_COUNT(&data->from_msgdb_queue) > 0 ||
	     RRR_LL_COUNT(&data->from_senders_queue) > 0 ||
	     RRR_LL_COUNT(&data->low_pri_queue) > 0 ||
	     RRR_LL_COUNT(&data->periodic_request_queue) > 0
	) {
		if (!EVENT_PENDING(data->event_queue_process)) {
			EVENT_ADD(data->event_queue_process);
		}
	}
	else {
		EVENT_REMOVE(data->event_queue_process);
	}
}

static void httpclient_transaction_destroy (struct httpclient_transaction_data *target) {
	RRR_FREE_IF_NOT_NULL(target->msg_topic);

	// Assuming that entry has recursive lock
	rrr_msg_holder_decref(target->entry);

	rrr_free(target);
}

static int httpclient_transaction_data_new (
		struct httpclient_transaction_data **target,
		const char *topic,
		rrr_u16 topic_len,
		struct rrr_msg_holder *entry
) {
	int ret = 0;

	*target = NULL;

	struct httpclient_transaction_data *result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if ((result->msg_topic = rrr_allocate(topic_len + (rrr_biglength) 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory for topic in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	if (topic != NULL && topic_len != 0) {
		memcpy(result->msg_topic, topic, topic_len);
	}
	result->msg_topic[topic_len] = '\0';
	result->entry = entry;

	*target = result;

	goto out;
	out_free:
		rrr_free(result);
	out:
		return ret;
}

static void httpclient_transaction_destroy_void (void *target) {
	httpclient_transaction_destroy(target);
}

static int httpclient_redirect_data_new (
		struct httpclient_redirect_data **target,
		rrr_biglength remaining_redirects,
		enum rrr_http_version protocol_version
) {
	int ret = 0;

	struct httpclient_redirect_data *redirect_data;

	if ((redirect_data = rrr_allocate(sizeof(*redirect_data))) == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(redirect_data, '\0', sizeof(*redirect_data));

	redirect_data->remaining_redirects = remaining_redirects;
	redirect_data->protocol_version = protocol_version;

	*target = redirect_data;

	goto out;
//	out_free:
//		free(redirect_data);
	out:
		return ret;
}

static void httpclient_redirect_data_destroy (struct httpclient_redirect_data *redirect_data) {
	rrr_http_client_request_data_cleanup(&redirect_data->request_data);
	rrr_free(redirect_data);
}

static void httpclient_redirect_data_destroy_void (void *target) {
	httpclient_redirect_data_destroy(target);
}

struct httpclient_create_message_from_404_callback_data {
	const struct httpclient_transaction_data *transaction_data;
};

static int httpclient_create_message_from_404_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct httpclient_create_message_from_404_callback_data *callback_data = arg;

	int ret = 0;

	if ((ret = rrr_msg_msg_new_with_data (
			(struct rrr_msg_msg **) &new_entry->message,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			callback_data->transaction_data->msg_topic,
			(rrr_u16) (callback_data->transaction_data->msg_topic != NULL ? strlen(callback_data->transaction_data->msg_topic) : 0),
			NULL,
			0
	)) != 0) {
		goto out;
	}

	new_entry->data_length = MSG_TOTAL_SIZE((struct rrr_msg_msg *) new_entry->message);

	out:
	rrr_msg_holder_unlock(new_entry);
	return ret;
}

static int httpclient_final_callback_receive_404 (
		struct httpclient_data *httpclient_data,
		const struct httpclient_transaction_data *transaction_data
) {
	struct httpclient_create_message_from_404_callback_data callback_data_broker = {
		transaction_data
	};

	return rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(httpclient_data->thread_data),
			NULL,
			0,
			0,
			NULL,
			httpclient_create_message_from_404_callback,
			&callback_data_broker,
			INSTANCE_D_CANCEL_CHECK_ARGS(httpclient_data->thread_data)
	);
}

static int httpclient_create_array_message (
	struct rrr_msg_holder *new_entry,
	struct httpclient_data *httpclient_data,
	const struct rrr_http_transaction *transaction,
	const struct httpclient_transaction_data *transaction_data,
	const struct rrr_array *array
) {
	int ret = 0;

	if ((ret = rrr_array_new_message_from_array (
			(struct rrr_msg_msg **) &new_entry->message,
			array,
			rrr_time_get_64(),
			transaction_data->msg_topic,
			(transaction_data->msg_topic != NULL
				? (rrr_u16) strlen(transaction_data->msg_topic)
				: 0
			)
	)) != 0) {
		if (ret == RRR_ARRAY_SOFT_ERROR) {
			RRR_MSG_0("Response was too big in httpclient instance %s, cannot create array message. Request endpoint was '%s'.\n",
					INSTANCE_D_NAME(httpclient_data->thread_data),
					transaction->endpoint_str
			);
		}
		else {
			RRR_MSG_0("Failed to create array message in %s of httpclient instance %s\n",
					__func__, INSTANCE_D_NAME(httpclient_data->thread_data));
		}
		goto out;
	}

	new_entry->data_length = MSG_TOTAL_SIZE((struct rrr_msg_msg *) new_entry->message);

	out:
	return ret;
}

struct httpclient_create_message_from_response_data_nullsafe_callback_data {
	struct httpclient_data *httpclient_data;
	struct rrr_msg_holder *new_entry;
	const struct httpclient_transaction_data *transaction_data;
};

static int httpclient_create_message_from_response_data_nullsafe_callback (
		const void *str,
		rrr_biglength len,
		void *arg
) {
	struct httpclient_create_message_from_response_data_nullsafe_callback_data *callback_data = arg;

	int ret = 0;

	if (len > UINT32_MAX) {
		RRR_MSG_0("Data size overflow while creating message from HTTP response data in httpclient instance %s (%llu>%llu).\n",
			INSTANCE_D_NAME(callback_data->httpclient_data->thread_data),
			(unsigned long long) len,
			(unsigned long long) UINT32_MAX
		);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_msg_msg_new_with_data (
			(struct rrr_msg_msg **) &callback_data->new_entry->message,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			callback_data->transaction_data->msg_topic,
			(callback_data->transaction_data->msg_topic != NULL ? (rrr_u16) strlen(callback_data->transaction_data->msg_topic) : 0),
			str,
			(rrr_u32) len
	)) != 0) {
		goto out;
	}

	callback_data->new_entry->data_length = MSG_TOTAL_SIZE((struct rrr_msg_msg *) callback_data->new_entry->message);

	out:
	return ret;
}

struct httpclient_create_message_from_response_data_callback_data {
	struct httpclient_data *httpclient_data;
	const struct rrr_http_transaction *transaction;
	const struct httpclient_transaction_data *transaction_data;
	const struct rrr_nullsafe_str *response_data;
	const struct rrr_array *structured_data;
};

static int httpclient_create_message_from_response_data_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct httpclient_create_message_from_response_data_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	struct rrr_array array_tmp = {0};

	if (rrr_nullsafe_str_len(callback_data->response_data) > 0xffffffff) { // Eight f's
		RRR_MSG_0("HTTP length too long in %s, max is 0xffffffff\n", __func__);
		ret = RRR_MESSAGE_BROKER_DROP;
		goto out;
	}

	if (RRR_LL_COUNT(callback_data->structured_data) != 0) {
		if ((ret = rrr_array_append_from (&array_tmp, callback_data->structured_data)) != 0) {
			RRR_MSG_0("Failed to clone structured data in %s\n", __func__);
			goto out;
		}

		if (rrr_nullsafe_str_check_likely_binary (callback_data->response_data)) {
			ret = rrr_array_push_value_blob_with_tag_nullsafe (&array_tmp, "http_body", callback_data->response_data);
		}
		else {
			ret = rrr_array_push_value_str_with_tag_nullsafe (&array_tmp, "http_body", callback_data->response_data);
		}

		if (ret != 0) {
			RRR_MSG_0("Failed to push response data to array in %s\n", __func__);
			goto out;
		}

		if ((ret = httpclient_create_array_message (
				new_entry,
				callback_data->httpclient_data,
				callback_data->transaction,
				callback_data->transaction_data,
				&array_tmp
		)) != 0) {
			goto out;
		}
	}
	else {
		struct httpclient_create_message_from_response_data_nullsafe_callback_data nullsafe_callback_data = {
				callback_data->httpclient_data,
				new_entry,
				callback_data->transaction_data
		};

		if ((ret = rrr_nullsafe_str_with_raw_do_const (
				callback_data->response_data,
				httpclient_create_message_from_response_data_nullsafe_callback,
				&nullsafe_callback_data
		)) != 0) {
			RRR_MSG_0("Failed to create message in %s\n", __func__);
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	out:
	rrr_msg_holder_unlock(new_entry);
	rrr_array_clear(&array_tmp);
	return ret;
}

struct httpclient_final_callback_data {
	struct httpclient_data *httpclient_data;
};

static int httpclient_final_callback_receive_data (
		struct httpclient_data *httpclient_data,
		const struct rrr_http_transaction *transaction,
		const struct httpclient_transaction_data *transaction_data,
		const struct rrr_nullsafe_str *response_data,
		const struct rrr_array *structured_data
) {
	struct httpclient_create_message_from_response_data_callback_data callback_data_broker = {
			httpclient_data,
			transaction,
			transaction_data,
			response_data,
			structured_data
	};

	return rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(httpclient_data->thread_data),
			NULL,
			0,
			0,
			NULL,
			httpclient_create_message_from_response_data_callback,
			&callback_data_broker,
			INSTANCE_D_CANCEL_CHECK_ARGS(httpclient_data->thread_data)
	);
}

#ifdef RRR_WITH_JSONC

struct httpclient_create_message_from_json_broker_callback_data {
	struct httpclient_data *httpclient_data;
	const struct rrr_http_transaction *transaction;
	const struct httpclient_transaction_data *transaction_data;
	const struct rrr_array *array;
	const struct rrr_array *structured_data;
};

static int httpclient_create_message_from_json_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct httpclient_create_message_from_json_broker_callback_data *callback_data = arg;

	int ret = RRR_MESSAGE_BROKER_OK;

	struct rrr_array array_tmp = {0};

	const struct rrr_array *array_to_use = callback_data->array;

	if (RRR_LL_COUNT(callback_data->structured_data) > 0) {
		if ((ret = rrr_array_append_from (&array_tmp, callback_data->structured_data)) != 0) {
			RRR_MSG_0("Failed to clone structured data in %s\n", __func__);
			goto out;
		}
		if ((ret = rrr_array_append_from (&array_tmp, callback_data->array)) != 0) {
			RRR_MSG_0("Failed to clone json data in %s\n", __func__);
			goto out;
		}
		array_to_use = &array_tmp;
	}

	if ((ret = httpclient_create_array_message (
			new_entry,
			callback_data->httpclient_data,
			callback_data->transaction,
			callback_data->transaction_data,
			array_to_use
	)) != 0) {
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	rrr_msg_holder_unlock(new_entry);
	return ret;
}

struct httpclient_create_message_from_json_callback_data {
	struct httpclient_data *httpclient_data;
	const struct rrr_http_transaction *transaction;
	const struct httpclient_transaction_data *transaction_data;
	const struct rrr_array *structured_data;
};

static int httpclient_create_message_from_json_array_callback (
		const struct rrr_array *array,
		void *arg
) {
	struct httpclient_create_message_from_json_callback_data *callback_data = arg;

	struct httpclient_create_message_from_json_broker_callback_data callback_data_broker = {
			callback_data->httpclient_data,
			callback_data->transaction,
			callback_data->transaction_data,
			array,
			callback_data->structured_data
	};

	return rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(callback_data->httpclient_data->thread_data),
			NULL,
			0,
			0,
			NULL,
			httpclient_create_message_from_json_callback,
			&callback_data_broker,
			INSTANCE_D_CANCEL_CHECK_ARGS(callback_data->httpclient_data->thread_data)
	);
}

static int httpclient_create_message_from_json_nullsafe_callback (
		const void *str,
		rrr_nullsafe_len len,
		void *arg
) {
	struct httpclient_create_message_from_json_callback_data *callback_data = arg;

	int ret = 0;

	if (len > RRR_LENGTH_MAX) {
		RRR_MSG_0("Data size overflow while creating message from HTTP json response data in httpclient instance %s (%llu>%llu).\n",
			INSTANCE_D_NAME(callback_data->httpclient_data->thread_data),
			(unsigned long long) len,
			(unsigned long long) UINT32_MAX
		);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_http_util_json_to_arrays (
			str,
			rrr_length_from_biglength_bug_const(len),
			httpclient_create_message_from_json_array_callback,
			callback_data
	)) != 0) {
		// Let hard error only propagate
		if (ret == RRR_HTTP_PARSE_INCOMPLETE || ret == RRR_HTTP_PARSE_SOFT_ERR) {
			RRR_DBG_2("HTTP client instance %s: JSON parsing of data from server failed, possibly invalid data\n",
					INSTANCE_D_NAME(callback_data->httpclient_data->thread_data));
			ret = 0;
		}

		if (ret != 0) {
			RRR_MSG_0("HTTP client instance %s: JSON parsing of data from server failed with a hard error\n",
					INSTANCE_D_NAME(callback_data->httpclient_data->thread_data));
		}
	}

	out:
	return ret;
}

static int httpclient_final_callback_receive_json (
		struct httpclient_data *httpclient_data,
		const struct rrr_http_transaction *transaction,
		const struct httpclient_transaction_data *transaction_data,
		const struct rrr_nullsafe_str *response_data,
		const struct rrr_array *structured_data
) {
	struct httpclient_create_message_from_json_callback_data callback_data = {
			httpclient_data,
			transaction,
			transaction_data,
			structured_data
	};

	return rrr_nullsafe_str_with_raw_do_const (
			response_data,
			httpclient_create_message_from_json_nullsafe_callback,
			&callback_data
	);
}

#endif /* RRR_WITH_JSONC */

static int httpclient_msgdb_poll_callback (RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS) {
	struct httpclient_data *data = arg;

	int ret = 0;

	struct rrr_msg_holder *entry = NULL;
	char *topic_tmp = NULL;

	if (positive_ack) {
		goto out;
	}
	if (negative_ack) {
		RRR_MSG_0("Warning: Failed to poll from msgdb in httpclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (*msg == NULL) {
		RRR_MSG_0("Unknown response from server in %s in httpclient instance %s\n",
			__func__, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (RRR_DEBUGLEVEL_3) {
		rrr_msg_msg_topic_get(&topic_tmp, *msg);
		RRR_DBG_3("httpclient instance %s retrieved message with timestamp %" PRIu64 " topic '%s' from msgdb\n",
				INSTANCE_D_NAME(data->thread_data),
				(*msg)->timestamp,
				topic_tmp != NULL ? topic_tmp : ""
		);
	}

	if ((ret = rrr_msg_holder_new (
			&entry,
			MSG_TOTAL_SIZE(*msg),
			NULL,
			0,
			0,
			*msg
	)) != 0) {
		goto out;
	}

	*msg = NULL;

	// Important : Set queue_time for correct timeout behavior
	entry->queue_time = rrr_time_get_64();

	rrr_msg_holder_incref(entry);

	if (data->do_low_priority_put) {
		RRR_LL_APPEND(&data->low_pri_queue, entry);
		data->low_pri_queue_need_rotate = 1;
	}
	else {
		RRR_LL_APPEND(&data->from_msgdb_queue, entry);
		data->from_msgdb_queue_need_rotate = 1;
	}

	httpclient_check_queues_and_activate_event_as_needed(data);

	if ( RRR_LL_COUNT(&data->low_pri_queue) > RRR_HTTPCLIENT_MSGDB_POLL_MAX ||
	     RRR_LL_COUNT(&data->from_msgdb_queue) > RRR_HTTPCLIENT_MSGDB_POLL_MAX
	) {
		RRR_DBG_1("msgdb poll limit of %i reached in httpclient instance %s, aborting polling for now.\n",
			RRR_HTTPCLIENT_MSGDB_POLL_MAX, INSTANCE_D_NAME(data->thread_data));
		ret = RRR_READ_EOF;
		goto out;
	}

	out:
	if (entry != NULL) {
		rrr_msg_holder_decref(entry);
	}
	RRR_FREE_IF_NOT_NULL(topic_tmp);

	return ret;
}

static void httpclient_msgdb_poll (struct httpclient_data *data) {
	rrr_msgdb_client_close(&data->msgdb_conn_iterate);
	if (rrr_msgdb_helper_iterate (
			&data->msgdb_conn_iterate,
			data->msgdb_socket,
			data->thread_data,
			httpclient_msgdb_poll_callback,
			data
	) != 0) {
		RRR_MSG_0("Warning: Failed to poll message DB in httpclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
	}
}

static int httpclient_msgdb_delete_delivery_callback (RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS) {
	struct httpclient_data *data = arg;

	(void)(msg);

	if (negative_ack) {
		RRR_MSG_0("Warning: Delete from msgdb failed in httpclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
	}
	if (positive_ack) {
		// OK
	}

	return 0;
}

static void httpclient_msgdb_delete (struct httpclient_data *data, const struct rrr_msg_msg *msg) {
	if (rrr_msgdb_helper_delete (
			&data->msgdb_conn_store,
			data->msgdb_socket,
			data->thread_data,
			msg,
			httpclient_msgdb_delete_delivery_callback,
			data
	) != 0) {
		RRR_MSG_0("Warning: Failed to delete from message DB in httpclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
	}
}

static int httpclient_msgdb_store_delivery_callback (RRR_MSGDB_CLIENT_DELIVERY_CALLBACK_ARGS) {
	struct httpclient_data *data = arg;

	(void)(msg);
	(void)(positive_ack);

	if (negative_ack) {
		RRR_MSG_0("Store to msgdb failed in httpclient instance %s, not safe to continue.\n", INSTANCE_D_NAME(data->thread_data));
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
		return 1;
	}

	return 0;
}

#define HTTPCLIENT_NOTIFY_MSGDB_IS_ACTIVE() \
	(data->msgdb_socket != NULL)

#define HTTPCLIENT_NOTIFY_MSGDB_MSG_HAS_TOPIC() \
	(MSG_TOPIC_LENGTH((struct rrr_msg_msg *) entry_locked->message) > 0)

static int httpclient_msgdb_notify_send(struct httpclient_data *data, struct rrr_msg_holder *entry_locked) {
	if (!HTTPCLIENT_NOTIFY_MSGDB_IS_ACTIVE() || !HTTPCLIENT_NOTIFY_MSGDB_MSG_HAS_TOPIC()) {
		return 0;
	}

	return rrr_msgdb_helper_send_to_msgdb (
			&data->msgdb_conn_store,
			data->msgdb_socket,
			data->thread_data,
			(const struct rrr_msg_msg *) entry_locked->message,
			httpclient_msgdb_store_delivery_callback,
			data
	);
}

static void httpclient_msgdb_notify_timeout(struct httpclient_data *data, const struct rrr_msg_holder *entry_locked) {
	if (!HTTPCLIENT_NOTIFY_MSGDB_IS_ACTIVE() || !HTTPCLIENT_NOTIFY_MSGDB_MSG_HAS_TOPIC()) {
		return;
	}

	httpclient_msgdb_delete(data, entry_locked->message);
}

static void httpclient_msgdb_notify_complete(struct httpclient_data *data, const struct rrr_msg_holder *entry_locked) {
	if (!HTTPCLIENT_NOTIFY_MSGDB_IS_ACTIVE() || !HTTPCLIENT_NOTIFY_MSGDB_MSG_HAS_TOPIC()) {
		return;
	}

	httpclient_msgdb_delete(data, entry_locked->message);
}

static int httpclient_final_callback (
		RRR_HTTP_CLIENT_FINAL_CALLBACK_ARGS
) {
	struct httpclient_data *httpclient_data = arg;
	struct httpclient_transaction_data *transaction_data = transaction->application_data;

	int ret = RRR_HTTP_OK;

	struct rrr_array structured_data = {0};
	int do_print_error = 1;

	RRR_DBG_3("HTTP response %i from server in httpclient instance %s: data size %" PRIrrr_nullsafe_len " transaction age %" PRIu64 " ms transaction endpoint str %s\n",
			transaction->response_part->response_code,
			INSTANCE_D_NAME(httpclient_data->thread_data),
			rrr_nullsafe_str_len(response_data),
			rrr_http_transaction_lifetime_get(transaction) / 1000,
			transaction->endpoint_str
	);

	if (httpclient_data->do_receive_structured) {
		if ((ret = rrr_array_push_value_u64_with_tag (
				&structured_data,
				"http_response_code",
				(unsigned int) transaction->response_part->response_code
		)) != 0)  {
			RRR_MSG_0("Failed to push response code to array in %s\n", __func__);
			goto out;
		}

		const struct rrr_http_header_field *field;

		if ((field = rrr_http_part_header_field_get (transaction->response_part, "content-type")) != NULL && field->value != NULL) {
			if ((ret = rrr_array_push_value_str_with_tag_nullsafe (
					&structured_data,
					"http_content_type",
					field->value
			)) != 0) {
				RRR_MSG_0("Failed to push content type to array in %s A\n", __func__);
				goto out;
			}
		}
		else {
			if ((ret = rrr_array_push_value_str_with_tag (
					&structured_data,
					"http_content_type",
					""
			)) != 0) {
				RRR_MSG_0("Failed to push content type to array in %s B\n", __func__);
				goto out;
			}
		}
	}

	if (httpclient_data->taint_tag != NULL && *(httpclient_data->taint_tag) != '\0') {
		if ((ret = rrr_array_push_value_vain_with_tag (
				&structured_data,
				httpclient_data->taint_tag
		)) != 0) {
			RRR_MSG_0("Failed to push taint tag value to array in %s\n", __func__);
			goto out;
		}
	}

	if (httpclient_data->report_tag != NULL && *(httpclient_data->report_tag) != '\0') {
		rrr_msg_holder_lock(transaction_data->entry);
		const struct rrr_msg_msg *msg = transaction_data->entry->message;
		ret = rrr_array_message_append_to_array_by_tag(&structured_data, msg, httpclient_data->report_tag);
		rrr_msg_holder_unlock(transaction_data->entry);

		if (ret != 0) {
			RRR_MSG_0("Failed to push report tag to array in %s\n", __func__);
			goto out;
		}
	}

	// Condition must always be checked regardless of other configuration parameters
	if (transaction->response_part->response_code == 404 && httpclient_data->do_receive_404_as_empty_part) {
		RRR_DBG_3("httpclient instance %s creating empty data message for 404 response\n",
				INSTANCE_D_NAME(httpclient_data->thread_data));

		ret |= httpclient_final_callback_receive_404(httpclient_data, transaction->application_data);
	}

	if (httpclient_response_code_summary_consume (
				&httpclient_data->response_code_summaries, 
				transaction->response_part->response_code
	)) {
		do_print_error = 0;
	}

	if (transaction->response_part->response_code < 200 || transaction->response_part->response_code > 299) {
		RRR_HTTP_UTIL_SET_TMP_NAME_FROM_NULLSAFE(method,transaction->request_part->request_method_str_nullsafe);

		if (transaction->method == RRR_HTTP_METHOD_PUT && httpclient_data->silent_put_error_limit_us != 0) {
			rrr_msg_holder_lock(transaction_data->entry);

			if (rrr_time_get_64() < ((struct rrr_msg_msg *) transaction_data->entry->message)->timestamp + httpclient_data->silent_put_error_limit_us) {
				RRR_DBG_4("Error response %i for PUT query temporarily ignored per configuration\n", transaction->response_part->response_code);
				do_print_error = 0;
			}

			rrr_msg_holder_unlock(transaction_data->entry);
		}

		if (do_print_error) {
			RRR_MSG_0("Error response while fetching HTTP: %i %s (request was %s %s)%s\n",
					transaction->response_part->response_code,
					rrr_http_util_iana_response_phrase_from_status_code ((unsigned int) transaction->response_part->response_code),
					RRR_HTTP_METHOD_TO_STR_CONFORMING(transaction->method),
					transaction->endpoint_str,
					httpclient_data->do_receive_ignore_error_part_data == 0 ? " (error part data not ignored, continuing)" : ""
			);
		}

		if (httpclient_data->do_receive_ignore_error_part_data) {
			goto out;
		}
	}
	else if (transaction->method == RRR_HTTP_METHOD_PUT) {
		rrr_msg_holder_lock(transaction_data->entry);
		httpclient_msgdb_notify_complete(httpclient_data, transaction_data->entry);
		rrr_msg_holder_unlock(transaction_data->entry);
	}

	if (httpclient_data->do_receive_part_data) {
		RRR_DBG_3("httpclient instance %s creating message with HTTP response data\n",
				INSTANCE_D_NAME(httpclient_data->thread_data));

		ret |= httpclient_final_callback_receive_data (
				httpclient_data,
				transaction,
				transaction->application_data,
				response_data,
				&structured_data
		);
	}

#ifdef RRR_WITH_JSONC
	if (httpclient_data->do_receive_json_data) {
		RRR_DBG_3("httpclient instance %s creating messages with JSON data\n",
				INSTANCE_D_NAME(httpclient_data->thread_data));

		ret |= httpclient_final_callback_receive_json (
				httpclient_data,
				transaction,
				transaction->application_data,
				response_data,
				&structured_data
		);
	}
#endif /* RRR_WITH_JSONC */

	out:
	rrr_array_clear(&structured_data);
	return ret;
}

static void httpclient_requeue_entry_while_locked (
		struct httpclient_data *data,
		struct rrr_msg_holder *entry
) {
	rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&data->from_senders_queue, entry);
	httpclient_check_queues_and_activate_event_as_needed(data);
}

static int httpclient_failure_callback (
		RRR_HTTP_CLIENT_FAILURE_CALLBACK_ARGS
) {
	struct httpclient_data *httpclient_data = arg;
	struct httpclient_transaction_data *transaction_data = transaction->application_data;

	RRR_DBG_3("HTTP temporary failure from server in httpclient instance %s (%s), retry: transaction age %" PRIu64 " ms transaction endpoint str %s\n",
			error_msg,
			INSTANCE_D_NAME(httpclient_data->thread_data),
			rrr_http_transaction_lifetime_get(transaction) / 1000,
			transaction->endpoint_str
	);

	rrr_msg_holder_lock(transaction_data->entry);
	httpclient_requeue_entry_while_locked(httpclient_data, transaction_data->entry);
	rrr_msg_holder_unlock(transaction_data->entry);

	return 0;
}

static int httpclient_transaction_field_add (
		struct httpclient_data *data,
		struct rrr_http_transaction *transaction,
		const struct rrr_type_value *value,
		const char *tag_to_use
) {
	int ret = 0;

	RRR_DBG_3("HTTP add array value with tag '%s' type '%s'\n",
			(tag_to_use != NULL ? tag_to_use : "(no tag)"), value->definition->identifier);

	if ((ret = rrr_http_transaction_query_field_add (
			transaction,
			NULL,
			NULL,
			0,
			NULL,
			value
	)) != 0) {
		RRR_MSG_0("Could not add data to HTTP query in instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
		return ret;
}

static int httpclient_message_values_get (
		struct rrr_array *target_array,
		const struct rrr_msg_msg *message
) {
	int ret = 0;

	uint16_t array_version_dummy;
	if (rrr_array_message_append_to_array(&array_version_dummy, target_array, message) != 0) {
		RRR_MSG_0("Error while converting message to collection in %s\n", __func__);
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
		RRR_MSG_0("Could not create timestamp array value in %s\n", __func__);
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
			RRR_MSG_0("Could not create topic array value in %s\n", __func__);
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
			RRR_MSG_0("Could not create data array value in %s\n", __func__);
			ret = RRR_HTTP_HARD_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int httpclient_session_query_prepare_callback_process_override (
		char **result,
		rrr_length *result_length,
		struct httpclient_data *data,
		const struct rrr_array *array,
		const char *tag,
		int do_force,
		const char *debug_name
) {
	int ret = RRR_HTTP_OK;

	*result = NULL;
	*result_length = 0;

	char *data_to_free = NULL;
	rrr_length data_length = 0;

	const struct rrr_type_value *value = rrr_array_value_get_by_tag_const(array, tag);
	if (value == NULL) {
		// Use default if force is not enabled
	}
	else if (RRR_TYPE_IS_STR_EXCACT(value->definition->type)) {
		if (value->total_stored_length > 0) {
			if ((data_to_free = rrr_allocate(value->total_stored_length + 1)) == NULL) {
				RRR_MSG_0("Warning: Failed to allocate memory for data in %s\n", __func__);
				goto out_check_force;
			}
			memcpy(data_to_free, value->data, value->total_stored_length);
			data_to_free[value->total_stored_length] = '\0';
			data_length = value->total_stored_length;
		}
	}
	else {
		if (value->definition->to_str == NULL) {
			RRR_MSG_0("Warning: Received message in httpclient instance %s where the specified type of the %s tagged '%s' in the message was of type '%s' which cannot be used as a string\n",
					INSTANCE_D_NAME(data->thread_data),
					debug_name,
					tag,
					value->definition->identifier
			);
			goto out_check_force;
		}
		if (value->definition->to_str(&data_to_free, value) != 0) {
			RRR_MSG_0("Warning: Failed to convert array value tagged '%s' to string for use as %s in httpserver instance %s\n",
					tag,
					debug_name,
					INSTANCE_D_NAME(data->thread_data)
			);
			goto out_check_force;
		}

		data_length = (unsigned int) strlen(data_to_free);
	}

	out_check_force:
	if (data_to_free == NULL && do_force) {
		RRR_MSG_0("Warning: Received message in httpclient instance %s with missing/unusable %s tag '%s' (which is enforced in configuration), dropping it\n",
				INSTANCE_D_NAME(data->thread_data),
				debug_name,
				tag
		);
		ret = RRR_HTTP_SOFT_ERROR;
		goto out;
	}

	*result_length = data_length;
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
	int no_destination_override;
};

#define HTTPCLIENT_OVERRIDE_PREPARE(name)                                                \
  do {if (  data->RRR_PASTE(name,_tag) != NULL &&                                        \
        (ret = httpclient_session_query_prepare_callback_process_override (              \
            &RRR_PASTE(name,_to_free),                                                   \
            &RRR_PASTE(name,_length),                                                    \
            data,                                                                        \
            array_from_msg,                                                              \
            data->RRR_PASTE(name,_tag),                                                  \
            data->RRR_PASTE_3(do_,name,_tag_force),                                      \
            RRR_QUOTE(name)                                                              \
        )) != 0) { goto out; }} while (0)

// Use for values which should not contain NULL characters
#define HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(name)                                                                                \
    do {if (RRR_PASTE(name,_to_free) != NULL && strlen(RRR_PASTE(name,_to_free)) != RRR_PASTE(name,_length)) {                 \
        RRR_MSG_0("HTTP override value '" RRR_QUOTE(name) "' from message contained NULL characters, this is an error\n");     \
        ret = RRR_HTTP_SOFT_ERROR; goto out;                                                                                   \
    }} while(0)

static int httpclient_overrides_server_and_port_get_from_message (
		char **server_override,
		uint16_t *port_override,
		struct httpclient_data *data,
		const struct rrr_array *array_from_msg
) {
	int ret = 0;

	*server_override = NULL;
	// DO NOT set *port_ovveride to zero here, leave it as is

	rrr_length server_length = 0;
	rrr_length port_length = 0;

	char *server_to_free = NULL;
	char *port_to_free = NULL;

	HTTPCLIENT_OVERRIDE_PREPARE(server);
	HTTPCLIENT_OVERRIDE_PREPARE(port);

	HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(server);
	HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(port);

	if (port_to_free != NULL) {
		char *end = NULL;
		unsigned long long port = strtoull(port_to_free, &end, 10);
		if (end == NULL || *end != '\0' || port == 0 || port > 65535) {
			RRR_MSG_0("Warning: Invalid override port value of '%s' in message to httpclient instance %s, dropping it\n",
					port_to_free, INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_SOFT_ERROR;
			goto out;
		}
		*port_override = (uint16_t) port;
	}

	*server_override = server_to_free;
	server_to_free = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(server_to_free);
	RRR_FREE_IF_NOT_NULL(port_to_free);
	return ret;
}

static int httpclient_connection_prepare_callback (
		RRR_HTTP_CLIENT_CONNECTION_PREPARE_CALLBACK_ARGS
) {
	struct httpclient_prepare_callback_data *callback_data = arg;
	struct httpclient_data *data = callback_data->data;

	if (callback_data->no_destination_override) {
		return 0;
	}

	return httpclient_overrides_server_and_port_get_from_message (
			server_override,
			port_override,
			data,
			callback_data->array_from_msg
	);
}

static int httpclient_session_query_prepare_callback_process_endpoint_from_topic_override (
		char **target,
		struct httpclient_data *data,
		const struct rrr_msg_msg *message
) {
	int ret = 0;

	struct rrr_string_builder *string_builder = NULL;

	if (MSG_TOPIC_LENGTH(message) == 0) {
		if (data->do_endpoint_from_topic_force) {
			RRR_DBG_2("No topic was set in message received in httpclient instance %s while endpoint from topic force was enabled, dropping it\n",
				INSTANCE_D_NAME(data->thread_data));
			ret = RRR_HTTP_SOFT_ERROR;
		}
		goto out;
	}

	if ((ret = rrr_string_builder_new(&string_builder)) != 0) {
		RRR_MSG_0("Could not create string builder in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_string_builder_append(string_builder, "/")) != 0) {
		RRR_MSG_0("Failed to append to string builder in %s\n", __func__);
		goto out;
	}

	if ((ret = rrr_string_builder_append_raw(string_builder, MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message))) != 0) {
		RRR_MSG_0("Failed to append to string builder in %s\n", __func__);
		goto out;
	}

	*target = rrr_string_builder_buffer_takeover(string_builder);


	out:
	if (string_builder != NULL) {
		rrr_string_builder_destroy(string_builder);
	}
	return ret;
}

static int httpclient_choose_method (
		enum rrr_http_method *chosen_method,
		struct httpclient_data *data,
		const struct rrr_array *array_from_msg
) {
	int ret = 0;

	rrr_length method_length = 0;
	char *method_to_free = NULL;

	HTTPCLIENT_OVERRIDE_PREPARE(method);
	HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(method);

	if (method_to_free != NULL && *method_to_free != '\0') {
		*chosen_method = rrr_http_util_method_str_to_enum(method_to_free);
	}
	else {
		ret = RRR_HTTP_NO_RESULT;
	}

	out:
	RRR_FREE_IF_NOT_NULL(method_to_free);
	return ret;
}

static int httpclient_session_method_prepare_callback (
		RRR_HTTP_CLIENT_METHOD_PREPARE_CALLBACK_ARGS
) {
	struct httpclient_prepare_callback_data *callback_data = arg;
	struct httpclient_data *data = callback_data->data;
	const struct rrr_array *array_from_msg = callback_data->array_from_msg;

	return httpclient_choose_method (chosen_method, data, array_from_msg);
}

static int httpclient_session_query_prepare_callback (
		RRR_HTTP_CLIENT_QUERY_PREPARE_CALLBACK_ARGS
) {
	struct httpclient_prepare_callback_data *callback_data = arg;
	struct httpclient_data *data = callback_data->data;
	const struct rrr_msg_msg *message = callback_data->message;
	const struct rrr_array *array_from_msg = callback_data->array_from_msg;

	*query_string = NULL;
	*endpoint_override = NULL;

	int ret = RRR_HTTP_OK;

	rrr_length endpoint_length = 0;
	rrr_length body_length = 0;
	rrr_length format_length = 0;
	rrr_length content_type_length = 0;
	rrr_length content_type_boundary_length = 0;

	char *endpoint_to_free = NULL;
	char *body_to_free = NULL;
	char *format_to_free = NULL;
	char *content_type_to_free = NULL;
	char *content_type_boundary_to_free = NULL;

	struct rrr_array array_to_send_tmp = {0};

	array_to_send_tmp.version = RRR_ARRAY_VERSION;

	if (data->http_header_accept) {
		if ((ret = rrr_http_part_header_field_push(transaction->request_part, "Accept", data->http_header_accept)) != 0) {
			RRR_MSG_0("Failed to push Accept: header to request in %s\n", __func__);
			goto out;
		}
	}

	if (!callback_data->no_destination_override) {
		if (data->do_endpoint_from_topic) {
			if ((ret = httpclient_session_query_prepare_callback_process_endpoint_from_topic_override (
					&endpoint_to_free,
					data,
					message
			)) != 0) {
				goto out;
			}
		}
		else {
			HTTPCLIENT_OVERRIDE_PREPARE(endpoint);
			HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(endpoint);
		}
	}

	if (data->do_no_data == 0) {
		HTTPCLIENT_OVERRIDE_PREPARE(body);
		// No verify strlen here, data may be binary which is fine

		if ( (transaction->method == RRR_HTTP_METHOD_PUT ||
		      transaction->method == RRR_HTTP_METHOD_PATCH ||
		      transaction->method == RRR_HTTP_METHOD_POST
		) && (
		     body_to_free != NULL && body_length > 0
		)) {
			HTTPCLIENT_OVERRIDE_PREPARE(content_type);
			HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(content_type);

			if ((ret = rrr_http_transaction_send_body_set_allocated(transaction, (void **) &body_to_free, body_length)) != 0) {
				goto out;
			}

			if (content_type_to_free != NULL && content_type_length > 0) {
				if ((ret = rrr_http_transaction_request_content_type_set (transaction, content_type_to_free)) != 0
				) {
					goto out;
				}
				if (strcasecmp(content_type_to_free, "multipart/form-data") == 0) {
					if (data->content_type_boundary_tag == NULL) {
						RRR_MSG_0("Warning: Configuration http_content_type_boundary_tag is not set in the configuration for httpclient instance %s while a request has a content type of multipart/form-data. The resulting request may be malformed\n", INSTANCE_D_NAME(data->thread_data));
					}
					else {
						HTTPCLIENT_OVERRIDE_PREPARE(content_type_boundary);
						HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(content_type_boundary);
						if ((ret = rrr_http_transaction_request_content_type_directive_set (
								transaction,
								"boundary",
								content_type_boundary_to_free
						)) != 0) {
							goto out;
						}
					}
				}
			}
		}
		else {
			rrr_array_append_from(&array_to_send_tmp, callback_data->array_from_msg);

			if (data->do_rrr_msg_to_array) {
				if ((ret = httpclient_get_metadata_from_message(&array_to_send_tmp, message)) != 0) {
					goto out;
				}
			}

			HTTPCLIENT_OVERRIDE_PREPARE(format);
			HTTPCLIENT_OVERRIDE_VERIFY_STRLEN(format);

			if (format_to_free != NULL && *format_to_free != '\0') {
				rrr_http_transaction_request_body_format_set(transaction, rrr_http_util_format_str_to_enum(format_to_free));
			}
		}
	}

	if (data->do_no_data != 0 && (RRR_MAP_COUNT(&data->http_client_config.tags) + RRR_LL_COUNT(&array_to_send_tmp) > 0)) {
		RRR_BUG("BUG: HTTP do_no_data is set but tags map and array are not empty in %s\n", __func__);
	}

	if (data->do_meta_tags_ignore) {
		RRR_MAP_ITERATE_BEGIN(&data->meta_tags_all);
			rrr_array_clear_by_tag(&array_to_send_tmp, node_tag);
		RRR_MAP_ITERATE_END();
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

		const size_t node_value_length = strlen(node_value);
		if (node_value_length > RRR_LENGTH_MAX) {
			RRR_MSG_0("Length of fixed query field with tag '%s' exceeds maximum in httpclient instance %s (%llu>%llu).\n",
				node_tag,
				INSTANCE_D_NAME(data->thread_data),
				(unsigned long long) node_value_length,
				(unsigned long long) RRR_LENGTH_MAX
			);
			ret = 1;
			goto out;
		}

		if ((ret = rrr_http_transaction_query_field_add (
				transaction,
				node_tag,
				node_value,
				rrr_length_from_size_t_bug_const (strlen(node_value)),
				"text/plain",
				NULL
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
		RRR_DBG_2("HTTP client instance %s sending request from message with timestamp %" PRIu64 " endpoint %s\n",
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
		RRR_FREE_IF_NOT_NULL(body_to_free);
		RRR_FREE_IF_NOT_NULL(format_to_free);
		RRR_FREE_IF_NOT_NULL(content_type_to_free);
		RRR_FREE_IF_NOT_NULL(content_type_boundary_to_free);
		return ret;
}

static int httpclient_unique_id_generator (
		RRR_HTTP_CLIENT_UNIQUE_ID_GENERATOR_CALLBACK_ARGS
) {
	struct httpclient_data *data = arg;
	*unique_id = ++(data->unique_id_counter);
	return 0;
}

static int httpclient_request_send (
		struct httpclient_data *data,
		struct rrr_http_client_request_data *request_data,
		struct rrr_msg_holder *entry,
		rrr_biglength remaining_redirects,
		int no_destination_override
) {
	struct rrr_msg_msg *message = entry->message;

	int ret = RRR_HTTP_OK;

	struct rrr_array array_from_msg_tmp = {0};
	struct httpclient_transaction_data *transaction_data = NULL;

	array_from_msg_tmp.version = RRR_ARRAY_VERSION;

	if ((ret = httpclient_transaction_data_new (
			&transaction_data,
			MSG_TOPIC_PTR(message),
			MSG_TOPIC_LENGTH(message),
			entry
	)) != 0) {
		goto out;
	}

	rrr_msg_holder_incref_while_locked(entry);

	if (MSG_IS_ARRAY(message)) {
		if ((ret = httpclient_message_values_get(&array_from_msg_tmp, message)) != RRR_HTTP_OK) {
			goto out;
		}
	}

	struct httpclient_prepare_callback_data prepare_callback_data = {
			data,
			message,
			&array_from_msg_tmp,
			no_destination_override
	};

	// Debug message for sending a request is in query prepare callback

	ret = rrr_http_client_request_send (
			request_data,
			data->http_client,
			&data->net_transport_config,
			remaining_redirects,
			httpclient_session_method_prepare_callback,
			httpclient_connection_prepare_callback,
			httpclient_session_query_prepare_callback,
			&prepare_callback_data,
			(void **) &transaction_data,
			httpclient_transaction_destroy_void
	);

	// Do not add anything here, let return value from last function call propagate

	out:
	if (transaction_data != NULL) {
		httpclient_transaction_destroy(transaction_data);
	}
	rrr_array_clear(&array_from_msg_tmp);
	return ret;
}

static int httpclient_redirect_callback (
		RRR_HTTP_CLIENT_REDIRECT_CALLBACK_ARGS
) {
	struct httpclient_data *data = arg;
	struct httpclient_transaction_data *transaction_data = transaction->application_data;

	int ret = 0;

	struct rrr_array array_from_msg_tmp = {0};
	char *server_override = NULL;
	uint16_t port_override = 0;

	rrr_msg_holder_lock(transaction_data->entry);

	struct httpclient_redirect_data *redirect_data = NULL;

	if ((ret = httpclient_redirect_data_new (
			&redirect_data,
			transaction->remaining_redirects,
			transaction->request_part->parsed_version
	)) != 0) {
		goto out;
	}

	// Entry takes ownership of redirect data, no cleanup at function out
	rrr_msg_holder_private_data_set(transaction_data->entry, redirect_data, httpclient_redirect_data_destroy_void);

	struct rrr_msg_msg *message = transaction_data->entry->message;

	if (MSG_IS_ARRAY(message)) {
		if ((ret = httpclient_message_values_get(&array_from_msg_tmp, message)) != RRR_HTTP_OK) {
			goto out;
		}
	}

	if ((ret = httpclient_overrides_server_and_port_get_from_message (
			&server_override,
			&port_override,
			data,
			&array_from_msg_tmp
	)) != 0) {
		goto out;
	}

	// Default from config
	if ((ret = rrr_http_client_request_data_reset_from_request_data (&redirect_data->request_data, &data->request_data)) != 0) {
		goto out;
	}

	// Overrides from message excluding endpoint which is part ov the redirect
	if ((ret = rrr_http_client_request_data_reset_from_raw (
			&redirect_data->request_data,
			server_override,
			port_override
	)) != 0) {
		goto out;
	}

	// Overrides from redirect URI which may be multiple parameters
	if ((ret = rrr_http_client_request_data_reset_from_uri (&redirect_data->request_data, uri)) != 0) {
		RRR_MSG_0("Error while updating target from redirect response URI in httpclient instance %s, return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	redirect_data->request_data.protocol_version = transaction->response_part->parsed_version;

	httpclient_requeue_entry_while_locked(data, transaction_data->entry);

	out:
	rrr_msg_holder_unlock(transaction_data->entry);
	rrr_array_clear(&array_from_msg_tmp);
	RRR_FREE_IF_NOT_NULL(server_override);
	// No cleanup of redirect data, ownership taken by enty

	// Don't let soft error propagate (would cause the whole thread to shut down)
	return (ret & ~(RRR_HTTP_SOFT_ERROR));
}

static int httpclient_entry_choose_method (
		enum rrr_http_method *method,
		struct httpclient_data *data,
		struct rrr_msg_holder *entry
) {
	const struct rrr_msg_msg *message = (const struct rrr_msg_msg *) entry->message;

	int ret = 0;

	*method = data->http_client_config.method;

	struct rrr_array array_tmp = {0};

	if (data->msgdb_socket == NULL || data->method_tag == NULL || *data->method_tag == '\0') {
		goto out;
	}

	if (MSG_IS_ARRAY(message)) {
		struct rrr_type_value *value_tmp = NULL;

		if ((ret = rrr_array_message_clone_value_by_tag (
				&value_tmp,
				message,
				data->method_tag
		)) != 0) {
			goto out;
		}

		if (value_tmp != NULL) {
			RRR_LL_APPEND(&array_tmp, value_tmp);
		}
	}

	if ((ret = httpclient_choose_method(method, data, &array_tmp)) != 0) {
		if (ret == RRR_HTTP_NO_RESULT) {
			// OK, use default method
			ret = 0;
		}
		else if (ret == RRR_HTTP_SOFT_ERROR) {
			// Method tag might be enforced but is not present in message,
			// propagate return value
		}
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int httpclient_poll_callback(RRR_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct httpclient_data *data = thread_data->private_data;
	const struct rrr_msg_msg *message = entry->message;

	int ret_tmp = 0;

	// We need to sneak-peak into the message to figure out if 
	// it will become a PUT request.
	enum rrr_http_method method = 0;
	if ((ret_tmp = httpclient_entry_choose_method (&method, data, entry)) != 0) {
		if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
			// Invalid message
			goto out_ignore;
		}
		return 1;
	}

	if (method == RRR_HTTP_METHOD_PUT) {
		if (httpclient_msgdb_notify_send(data, entry) != 0) {
			return 1;
		}
	}

	if (data->taint_tag != NULL && *(data->taint_tag) != '\0') {
		if (MSG_IS_ARRAY(message) && rrr_array_message_has_tag(message, data->taint_tag)) {
			RRR_DBG_3("httpclient instance %s received tainted message (by tag '%s') with timestamp %" PRIu64 ", ignoring.\n",
					INSTANCE_D_NAME(thread_data),
					data->taint_tag,
					message->timestamp
			);
			goto out_ignore;
		}
	}

	if (RRR_DEBUGLEVEL_3) {
		char *topic_tmp = NULL;

		if (rrr_msg_msg_topic_get(&topic_tmp, message) != 0 ) {
			RRR_MSG_0("Warning: Error while getting topic from message in %s\n", __func__);
		}

		RRR_DBG_3("httpclient instance %s received message with timestamp %" PRIu64 " topic '%s'\n",
				INSTANCE_D_NAME(thread_data),
				message->timestamp,
				(topic_tmp != NULL ? topic_tmp : "(none)")
		);

		RRR_FREE_IF_NOT_NULL(topic_tmp);
	}

	// Important : Set queue_time for correct timeout behavior
	entry->queue_time = rrr_time_get_64();

	rrr_msg_holder_private_data_clear(entry);
	rrr_msg_holder_incref_while_locked(entry);

	if (method == RRR_HTTP_METHOD_PUT && data->do_low_priority_put) {
		RRR_LL_APPEND(&data->low_pri_queue, entry);
	}
	else {
		RRR_LL_APPEND(&data->from_senders_queue, entry);
	}

	out_ignore:
	rrr_msg_holder_unlock(entry);
	return 0;
}

static int httpclient_parse_config_response_codes_summary_callback (
		const char *value,
		void *arg
) {
	struct httpclient_data *data = arg;

	int ret = 0;

	char *endptr;
	unsigned long long int number = strtoull(value, &endptr, 10);

	if (*endptr != '\0') {
		RRR_MSG_0("Invalid number '%s'\n", value);
		ret = 1;
		goto out;
	}

	if (number < 100 || number > 999) {
		RRR_MSG_0("Invalid response code '%s', out of range.\n", value);
		ret = 1;
		goto out;
	}

	if ((ret = httpclient_response_code_summary_push (&data->response_code_summaries, number)) != 0) {
		goto out;
	}

	out:
	return ret;
}

#define HTTPCLIENT_OVERRIDE_TAG_GET(parameter)                                                                                                            \
    RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_" RRR_QUOTE(parameter) "_tag", RRR_PASTE(parameter,_tag));                                 \
    RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_" RRR_QUOTE(parameter) "_tag_force", RRR_PASTE_3(do_,parameter,_tag_force), 0);                        \
    do {if (data->RRR_PASTE(parameter,_tag) != NULL && (ret = rrr_map_item_add_new(&data->meta_tags_all, data->RRR_PASTE(parameter,_tag), NULL)) != 0) {  \
        RRR_MSG_0("Failed to add meta tag to map in %s\n", __func__);                                                                          \
        ret = 1; goto out;                                                                                                                                \
    }} while(0)

#define HTTPCLIENT_OVERRIDE_TAG_VALIDATE(parameter)                                                                               \
    do {if (data->RRR_PASTE_3(do_,parameter,_tag_force) != 0) {                                                                   \
        if (data->RRR_PASTE(parameter,_tag) == NULL) {                                                                            \
            RRR_MSG_0("http_" RRR_QUOTE(parameter) " was 'yes' in httpclient instance %s but no tag was specified in http_" RRR_QUOTE(parameter) "_tag\n", \
                    config->name);                                                                                                \
            ret = 1;                                                                                                              \
        }                                                                                                                         \
        if (RRR_INSTANCE_CONFIG_EXISTS("http_" RRR_QUOTE(parameter))) {                                                           \
            RRR_MSG_0("http_" RRR_QUOTE(parameter) "_tag_force was 'yes' in httpclient instance %s while http_" RRR_QUOTE(parameter) " was also set, this is a configuration error\n", \
                    config->name);                                                                                                \
            ret = 1;                                                                                                              \
        }                                                                                                                         \
        if (ret != 0) { goto out; }}} while(0)

static int httpclient_parse_config (
		struct httpclient_data *data,
		struct rrr_instance_config_data *config
) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_response_max_mb", response_max_mb, RRR_HTTPCLIENT_DEFAULT_RESPONSE_MAX_MB);
	data->response_max_size = data->response_max_mb;
	if (((ret = rrr_biglength_mul_err(&data->response_max_size, 1024 * 1024))) != 0) {
		RRR_MSG_0("Overflow in parameter 'http_response_max_mb' of httpclient instance %s, value too large\n",
				config->name);
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_no_data", do_no_data, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_rrr_msg_to_array", do_rrr_msg_to_array, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_drop_on_error", do_drop_on_error, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_part_data", do_receive_part_data, 0);
#ifdef RRR_WITH_JSONC
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_json_data", do_receive_json_data, 0);
#else
	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_receive_json_data",
		RRR_MSG_0("Parameter 'http_receive_json_data' is set in httpclient instance %s but RRR is not compiled with JSON support.\n",
			config->name);
		ret = 1;
		goto out;
	);
#endif /* RRR_WITH_JSONC */
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_ignore_error_part_data", do_receive_ignore_error_part_data, 1 /* Default is yes */);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_404_as_empty_part", do_receive_404_as_empty_part, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_receive_structured", do_receive_structured, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_low_priority_put", do_low_priority_put, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_ttl_seconds", message_ttl_us, 0);
	data->message_ttl_us *= 1000 * 1000;
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_message_timeout_ms", message_queue_timeout_us, 0);
	data->message_queue_timeout_us *= 1000;
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_silent_put_error_limit_s", silent_put_error_limit_us, 0);
	data->silent_put_error_limit_us *= 1000 * 1000;
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_request_interval_ms", request_interval_us, 0);
	data->request_interval_us *= 1000;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_low_priority_message_timeout_factor", message_low_pri_timeout_factor, 10);

	if ((ret = rrr_instance_config_traverse_split_commas_silent_fail (
			config,
			"http_response_codes_summary",
			httpclient_parse_config_response_codes_summary_callback,
			data
	)) != 0) {
		RRR_MSG_0("Failed to parse parameter 'http_response_codes_summary' in httpclient instance %s\n",
			config->name);
		ret = 1;
		goto out;
	}

	if (data->message_low_pri_timeout_factor * data->message_queue_timeout_us < data->message_queue_timeout_us) {
		RRR_MSG_0("Overflow while multiplying parameters http_message_timeout_ms and http_low_priority_message_timeout_factor in httpclient instance %s. Please reduce the values.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_max_redirects", redirects_max, RRR_HTTPCLIENT_DEFAULT_REDIRECTS_MAX);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_accept", http_header_accept);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_msgdb_socket", msgdb_socket);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("http_msgdb_poll_interval_s", msgdb_poll_interval_us, RRR_HTTPCLIENT_DEFAULT_MSGDB_POLL_INTERVAL_S);

	data->msgdb_poll_interval_us *= 1000 * 1000;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_endpoint_from_topic", do_endpoint_from_topic, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_endpoint_from_topic_force", do_endpoint_from_topic_force, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("http_meta_tags_ignore", do_meta_tags_ignore, 1); // Default YES

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_taint_tag", taint_tag);
	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("http_report_tag",
		RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("http_report_tag", report_tag);
    		if (data->report_tag != NULL && *(data->report_tag) != '\0') {
			if ((ret = rrr_map_item_add_new(&data->meta_tags_all, data->report_tag, NULL)) != 0) {
				RRR_MSG_0("Failed to add meta tag in %s\n", __func__);
				ret = 1;
				goto out;
			}
		}
	);
	HTTPCLIENT_OVERRIDE_TAG_GET(method);
	HTTPCLIENT_OVERRIDE_TAG_GET(content_type);
	HTTPCLIENT_OVERRIDE_TAG_GET(content_type_boundary);
	HTTPCLIENT_OVERRIDE_TAG_GET(format);
	HTTPCLIENT_OVERRIDE_TAG_GET(endpoint);
	HTTPCLIENT_OVERRIDE_TAG_GET(server);
	HTTPCLIENT_OVERRIDE_TAG_GET(port);
	HTTPCLIENT_OVERRIDE_TAG_GET(body);

	if (data->content_type_boundary_tag != NULL && data->content_type_tag == NULL) {
		RRR_MSG_0("Setting http_content_type_boundary_tag was set for instance %s while http_content_type_tag was not. This is an error.\n",
				config->name);
		ret = 1;
		goto out;
	}

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

	if (rrr_http_client_config_parse (
			&data->http_client_config,
			config,
			"http",
			RRR_HTTPCLIENT_DEFAULT_SERVER,
			RRR_HTTPCLIENT_DEFAULT_PORT,
			RRR_HTTPCLIENT_DEFAULT_CONCURRENT_CONNECTIONS,
			0, // <-- Disable fixed tags and fields
			1, // <-- Enable endpoint
			1  // <-- Enable body format
	) != 0) {
		ret = 1;
		goto out;
	}

	{
		if (data->do_endpoint_from_topic_force && !data->do_endpoint_from_topic) {
			RRR_MSG_0("http_endpoint_from_topic_force was 'yes' while http_endpoint_from_topic was not in httpclient instance %s, this is an invalid configuration.\n",
					config->name);
			ret = 1;
		}
		if (data->do_endpoint_from_topic && RRR_INSTANCE_CONFIG_EXISTS("http_endpoint_tag")) {
			RRR_MSG_0("http_endpoint_from_topic_force was 'yes' while http_endpoint_tag was set in httpclient instance %s, this is an invalid configuration.\n",
					config->name);
			ret = 1;
		}
		if (ret != 0) {
			goto out;
		}
	}

	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(method);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(content_type);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(content_type_boundary);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(endpoint);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(server);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(port);
	HTTPCLIENT_OVERRIDE_TAG_VALIDATE(body);

	enum rrr_net_transport_type_f allowed_transport_types = RRR_NET_TRANSPORT_F_PLAIN;
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
	allowed_transport_types |= RRR_NET_TRANSPORT_F_TLS;
#endif
#if defined(RRR_WITH_HTTP3)
	allowed_transport_types |= RRR_NET_TRANSPORT_F_QUIC;
#endif

	if (rrr_net_transport_config_parse (
			&data->net_transport_config,
			config,
			"http",
			0, // Allow multiple transport types
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_HTTP3)
			0, // Don't allow specifying certificate without transport type being TLS
#endif
			RRR_NET_TRANSPORT_NONE,
			allowed_transport_types
	) != 0) {
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void httpclient_queue_check_timeouts (
		rrr_setting_uint ttl_us,
		rrr_setting_uint timeout_us,
		struct rrr_msg_holder_collection *queue,
		struct httpclient_data *data
) {
	const uint64_t loop_begin_time = rrr_time_get_64();
	int ttl_timeout_count = 0;
	int send_timeout_count = 0;

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_msg_holder);
		rrr_msg_holder_lock(node);
		if (ttl_us != 0 && loop_begin_time > ((struct rrr_msg_msg *) node->message)->timestamp + ttl_us) {
				// Delete any message from message db upon TTL timeout
				httpclient_msgdb_notify_timeout(data, node);
				ttl_timeout_count++;
				RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (timeout_us != 0 && loop_begin_time > node->send_time + timeout_us) {
				// No msgdb notify for normal timeout, let any messages get read back into the queue again
				send_timeout_count++;
				RRR_LL_ITERATE_SET_DESTROY();
		}
		rrr_msg_holder_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, 0; rrr_msg_holder_decref(node));

	if (ttl_timeout_count > 0) {
		RRR_MSG_0("TTL timeout for %i messages in httpclient instance %s\n",
				ttl_timeout_count,
				INSTANCE_D_NAME(data->thread_data));
	}
	if (send_timeout_count > 0) {
		RRR_MSG_0("Send timeout for %i messages in httpclient instance %s\n",
				send_timeout_count,
				INSTANCE_D_NAME(data->thread_data));
	}
}

static void httpclient_queue_process (
		struct rrr_msg_holder_collection *queue,
		struct httpclient_data *data
) {
	if (RRR_LL_COUNT(queue) == 0) {
		return;
	}

	uint64_t loop_max_time = rrr_time_get_64() + 50 * 1000; // 50 ms
	int loop_max = 256;
	int count = 0;
	int ok_count = 0;
	int send_busy_count = 0;
	int error_count = 0;

	RRR_LL_ITERATE_BEGIN(queue, struct rrr_msg_holder);
		int ret_tmp = RRR_HTTP_OK;

		if ( rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data)) != 0 || 
		     rrr_time_get_64() >= loop_max_time
		) {
			RRR_LL_ITERATE_BREAK();
		}

		if (loop_max-- == 0) {
			RRR_LL_ITERATE_LAST();
		}

		rrr_msg_holder_lock(node);
		pthread_cleanup_push(rrr_msg_holder_unlock_void, node);

		struct rrr_http_client_request_data *request_data_to_use = &data->request_data;
		int no_destination_override = 0;
		rrr_biglength remaining_redirects = data->redirects_max;

		if (node->private_data) {
			struct httpclient_redirect_data *redirect_data = node->private_data;
			request_data_to_use = &redirect_data->request_data;
			remaining_redirects = redirect_data->remaining_redirects;
			no_destination_override = 1;
		}
		else {
			request_data_to_use->protocol_version = data->http_client_config.do_http_10 ? RRR_HTTP_VERSION_10 : RRR_HTTP_VERSION_11;
		}

		// Always set this, also upon redirects
		request_data_to_use->upgrade_mode = data->http_client_config.do_http_10 || data->http_client_config.do_no_http2_upgrade
			? RRR_HTTP_UPGRADE_MODE_NONE
			: RRR_HTTP_UPGRADE_MODE_HTTP2;

		if ((ret_tmp = httpclient_request_send (
				data,
				request_data_to_use,
				node,
				remaining_redirects,
				no_destination_override
		)) != RRR_HTTP_OK) {
			if (ret_tmp == RRR_HTTP_BUSY) {
				send_busy_count++;

				// These are quick errors, allow loop max to increase
				// to iterate more messages.
				loop_max++;
			}
			else {
				error_count++;

				if (ret_tmp == RRR_HTTP_SOFT_ERROR) {
					if (data->do_drop_on_error) {
						data->connection_soft_error_dropped_count++;
						RRR_LL_ITERATE_SET_DESTROY();
					}
				}
				else {
					RRR_MSG_0("Hard error from request send while iterating queue in httpclient instance %s, deleting message\n",
							INSTANCE_D_NAME(data->thread_data));
					RRR_LL_ITERATE_SET_DESTROY();
				}
			}
		}
		else {
			ok_count++;

			// Request sent, may now be removed from queue
			RRR_LL_ITERATE_SET_DESTROY();
		}

		pthread_cleanup_pop(1); // Unlock

		count++;
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, 0; rrr_msg_holder_decref(node));

	RRR_DBG_3("Iterated %i/%i messages, ok: %i, busy: %i, error: %i in httpclient instance %s\n",
			count,
			RRR_LL_COUNT(queue),
			ok_count,
			send_busy_count,
			error_count,
			INSTANCE_D_NAME(data->thread_data));
}

static int httpclient_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data;

	int ret_tmp = rrr_poll_do_poll_delete (amount, thread_data, httpclient_poll_callback);

	httpclient_check_queues_and_activate_event_as_needed(data);

	return ret_tmp;
}

static void httpclient_pause_check (RRR_EVENT_FUNCTION_PAUSE_ARGS) {
	struct rrr_instance_runtime_data *thread_data = callback_arg;
	struct httpclient_data *data = thread_data->private_data;

	if (is_paused) {
		*do_pause = RRR_LL_COUNT(&data->from_senders_queue) > (RRR_HTTPCLIENT_INPUT_QUEUE_MAX * 0.75) ? 1 : 0;
	}
	else {
		*do_pause = RRR_LL_COUNT(&data->from_senders_queue) > RRR_HTTPCLIENT_INPUT_QUEUE_MAX ? 1 : 0;
	}
}

static void httpclient_update_stats(struct httpclient_data *data) {
	struct rrr_stats_instance *stats = INSTANCE_D_STATS(data->thread_data);

	if (stats->stats_handle == 0) {
		return;
	}

	rrr_stats_instance_post_unsigned_base10_text(stats, "periodic_request_queue_count", 0, RRR_LL_COUNT(&data->periodic_request_queue));
	rrr_stats_instance_post_unsigned_base10_text(stats, "from_msgdb_queue_count", 0, RRR_LL_COUNT(&data->from_msgdb_queue));
	rrr_stats_instance_post_unsigned_base10_text(stats, "from_senders_queue_count", 0, RRR_LL_COUNT(&data->from_senders_queue));
	rrr_stats_instance_post_unsigned_base10_text(stats, "low_pri_queue_count", 0, RRR_LL_COUNT(&data->low_pri_queue));
}

static int httpclient_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1("httpclient instance %s queues: periodic %i from msgdb %i senders %i low pri %i\n",
		INSTANCE_D_NAME(thread_data),
		RRR_LL_COUNT(&data->periodic_request_queue),
		RRR_LL_COUNT(&data->from_msgdb_queue),
		RRR_LL_COUNT(&data->from_senders_queue),
		RRR_LL_COUNT(&data->low_pri_queue)
	);

	if (data->connection_soft_error_dropped_count > 0) {
		RRR_MSG_0("%" PRIrrrl " messages dropped per configuration after connection error in httpclient instance %s\n",
				data->connection_soft_error_dropped_count, INSTANCE_D_NAME(data->thread_data));
		data->connection_soft_error_dropped_count = 0;
	}

	for (size_t i = 0; i < data->response_code_summaries.count; i++) {
		struct httpclient_response_code_summary *ptr = data->response_code_summaries.codes + i;

		if (!ptr->count)
			continue;

		RRR_MSG_1("httpclient instance %s received %" PRIrrrl " responses with code %u\n",
			INSTANCE_D_NAME(thread_data),
			ptr->count,
			ptr->code
		);

		ptr->count = 0;
	}

	const rrr_setting_uint low_pri_timeout_us = data->message_low_pri_timeout_factor * data->message_queue_timeout_us;
	assert(low_pri_timeout_us >= data->message_queue_timeout_us);

	httpclient_queue_check_timeouts(data->message_ttl_us, data->message_queue_timeout_us, &data->periodic_request_queue, data);
	httpclient_queue_check_timeouts(data->message_ttl_us, data->message_queue_timeout_us, &data->from_msgdb_queue, data);
	httpclient_queue_check_timeouts(data->message_ttl_us, data->message_queue_timeout_us, &data->from_senders_queue, data);
	httpclient_queue_check_timeouts(data->message_ttl_us, low_pri_timeout_us, &data->low_pri_queue, data);

	httpclient_update_stats(data);

	if (rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(thread) != 0) {
		return RRR_EVENT_EXIT;
	}

	return 0;
}

static int httpclient_event_msgdb_poll_add (
		struct httpclient_data *data,
		int do_short_timeout
) {
	const uint64_t short_timeout_us = 100 * 1000; // 100 ms

	if (do_short_timeout && data->msgdb_poll_interval_us > short_timeout_us) {
		EVENT_INTERVAL_SET(data->event_msgdb_poll, short_timeout_us);
	}
	else {
		EVENT_INTERVAL_SET(data->event_msgdb_poll, data->msgdb_poll_interval_us);
	}

	EVENT_ADD(data->event_msgdb_poll);

	return 0;
}

static void httpclient_event_msgdb_poll (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	struct httpclient_data *data = arg;

	int do_short_timeout = 0;

	// After timer has passed and before polling, wait untill queues
	// are empty (avoid dupes). In high traffic situations, it make
	// take some time before the msgdb is polled.
	if ( rrr_http_client_active_transaction_count_get(data->http_client) == 0 &&
	     RRR_LL_COUNT(&data->periodic_request_queue) == 0 &&
	     RRR_LL_COUNT(&data->from_msgdb_queue) == 0 &&
	     RRR_LL_COUNT(&data->from_senders_queue) == 0 &&
	     RRR_LL_COUNT(&data->low_pri_queue) == 0
	) {
		httpclient_msgdb_poll(data);
	}
	else {
		do_short_timeout = 1;
	}

	if (httpclient_event_msgdb_poll_add (data, do_short_timeout) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
}

static void httpclient_event_queue_process_check_rotate (
		struct httpclient_data *data,
		int *need,
		struct rrr_msg_holder_collection *queue
) {
	if (*need && RRR_LL_COUNT(queue) > 1) {
		const int pos = rrr_rand() % RRR_LL_COUNT(queue);
		RRR_DBG_3("httpclient instance %s rotate send queue elements %i at pos %i\n",
				INSTANCE_D_NAME(data->thread_data),
				RRR_LL_COUNT(queue),
				pos
		);
		rrr_msg_holder_collection_rotate(queue, 1 /* Lock entries */, pos);
	}
	*need = 0;
}

static void httpclient_event_queue_process (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	struct httpclient_data *data = arg;

	// In high traffic situations where timeout is active, only the first
	// elements of the queue will be checked, avoid having the same
	// elements checked every time creating permanent HOL blocking if
	// stores fail. To mitigate this, rotate the lists at a random point
	// before processing.

	// Priority to the msgdb queue, runs first. Needs rotating.
	httpclient_event_queue_process_check_rotate(data, &data->from_msgdb_queue_need_rotate, &data->from_msgdb_queue);
	httpclient_queue_process(&data->from_msgdb_queue, data);

	// Normal flow when there are not errors. Need not rotating.
	httpclient_queue_process(&data->periodic_request_queue, data);
	httpclient_queue_process(&data->from_senders_queue, data);

	// Process low pri if other queues are empty. Needs rotating.
	if (RRR_LL_COUNT(&data->from_msgdb_queue) == 0 &&
	    RRR_LL_COUNT(&data->from_senders_queue) == 0 &&
	    RRR_LL_COUNT(&data->periodic_request_queue) == 0
	) {
		httpclient_event_queue_process_check_rotate(data, &data->low_pri_queue_need_rotate, &data->low_pri_queue);
		httpclient_queue_process(&data->low_pri_queue, data);
	}

	httpclient_check_queues_and_activate_event_as_needed(data);

	if (rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(INSTANCE_D_THREAD(data->thread_data)) != 0) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
}

static void httpclient_event_periodic_request (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	(void)(fd);
	(void)(flags);

	RRR_EVENT_HOOK();

	struct httpclient_data *data = arg;

	struct rrr_msg_holder *entry = NULL;
	struct rrr_msg_msg *msg = NULL;

	if (rrr_msg_msg_new_empty (
			&msg,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			0,
			0
	) != 0) {
		RRR_MSG_0("Failed to create message for periodic request in httpclient instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_holder_new (
			&entry,
			MSG_TOTAL_SIZE(msg),
			NULL,
			0,
			0,
			msg
	) != 0) {
		RRR_MSG_0("Failed to create message holder for periodic request in httpclient instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}
	msg = NULL;

	RRR_DBG_2("httpclient instance %s generating periodic request\n", INSTANCE_D_NAME(data->thread_data));

	// Important : Set queue_time for correct timeout behavior
	entry->queue_time = rrr_time_get_64();

	rrr_msg_holder_incref(entry);
	RRR_LL_APPEND(&data->periodic_request_queue, entry);

	httpclient_check_queues_and_activate_event_as_needed(data);

	out:
	if (entry != NULL)
		rrr_msg_holder_decref(entry);
	RRR_FREE_IF_NOT_NULL(msg);
}


static void httpclient_data_cleanup(void *arg) {
	struct httpclient_data *data = arg;

	rrr_event_collection_clear(&data->events);
	if (data->http_client) {
		rrr_http_client_destroy(data->http_client);
	}
	rrr_msgdb_client_close(&data->msgdb_conn_store);
	rrr_msgdb_client_close(&data->msgdb_conn_iterate);
	rrr_http_client_request_data_cleanup(&data->request_data);
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_http_client_config_cleanup(&data->http_client_config);
	rrr_msg_holder_collection_clear(&data->from_senders_queue);
	rrr_msg_holder_collection_clear(&data->low_pri_queue);
	rrr_msg_holder_collection_clear(&data->from_msgdb_queue);
	rrr_msg_holder_collection_clear(&data->periodic_request_queue);
	RRR_FREE_IF_NOT_NULL(data->taint_tag);
	RRR_FREE_IF_NOT_NULL(data->report_tag);
	RRR_FREE_IF_NOT_NULL(data->method_tag);
	RRR_FREE_IF_NOT_NULL(data->content_type_tag);
	RRR_FREE_IF_NOT_NULL(data->content_type_boundary_tag);
	RRR_FREE_IF_NOT_NULL(data->format_tag);
	RRR_FREE_IF_NOT_NULL(data->endpoint_tag);
	RRR_FREE_IF_NOT_NULL(data->server_tag);
	RRR_FREE_IF_NOT_NULL(data->port_tag);
	RRR_FREE_IF_NOT_NULL(data->body_tag);
	rrr_map_clear(&data->meta_tags_all);
	RRR_FREE_IF_NOT_NULL(data->msgdb_socket);
	RRR_FREE_IF_NOT_NULL(data->http_header_accept);
	RRR_FREE_IF_NOT_NULL(data->response_code_summaries.codes);
}

static void httpclient_data_init (
		struct httpclient_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));
}

static int httpclient_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data = thread_data->private_memory;

	httpclient_data_init(data, thread_data);

	RRR_DBG_1 ("httpclient thread thread_data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (httpclient_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("httpclient started thread %p\n", thread_data);

	{
		int has_senders = rrr_message_broker_senders_count(INSTANCE_D_BROKER_ARGS(thread_data)) > 0 ? 1 : 0;
		if (!has_senders && data->request_interval_us == 0) {
			RRR_MSG_0("httpclient instance %s has no senders specified but this requires a request interval to be set in http_request_interval_ms\n",
				INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
	}

	enum rrr_http_transport http_transport_force = RRR_HTTP_TRANSPORT_ANY;

	switch (data->net_transport_config.transport_type_f) {
		case RRR_NET_TRANSPORT_F_NONE:
			http_transport_force = RRR_HTTP_TRANSPORT_ANY;
			break;
		case RRR_NET_TRANSPORT_F_PLAIN:
			http_transport_force = RRR_HTTP_TRANSPORT_HTTP;
			break;
#if defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_LIBRESSL)
		case RRR_NET_TRANSPORT_F_TLS:
			http_transport_force = RRR_HTTP_TRANSPORT_HTTPS;
			break;
#endif
#if defined(RRR_WITH_HTTP3)
		case RRR_NET_TRANSPORT_F_QUIC:
			http_transport_force = RRR_HTTP_TRANSPORT_QUIC;
			break;
#endif
		default:
			RRR_BUG("Invalid transport type %i (verify that only one is set)\n", data->net_transport_config.transport_type_f);
			break;
	};

	if (rrr_http_client_request_data_reset (
			&data->request_data,
			http_transport_force,
			data->http_client_config.method,
			data->http_client_config.body_format,
			data->http_client_config.do_http_10 ? RRR_HTTP_UPGRADE_MODE_NONE : RRR_HTTP_UPGRADE_MODE_HTTP2,
			data->http_client_config.do_http_10 ? RRR_HTTP_VERSION_10 : RRR_HTTP_VERSION_11,
			data->http_client_config.do_plain_http2,
			RRR_HTTP_CLIENT_USER_AGENT
	) != 0) {
		RRR_MSG_0("Could not initialize http client request data in httpclient instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (rrr_http_client_request_data_reset_from_config (
			&data->request_data,
			&data->http_client_config
	) != 0) {
		RRR_MSG_0("Could not store HTTP client configuration in httpclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out_message;
	}

	{
		struct rrr_http_client_callbacks callbacks = {
			httpclient_final_callback,
			httpclient_failure_callback,
			httpclient_redirect_callback,
			NULL,
			NULL,
			httpclient_unique_id_generator,
			data
		};

		if (rrr_http_client_new (
				&data->http_client,
				INSTANCE_D_EVENTS(thread_data),
				RRR_HTTPCLIENT_DEFAULT_KEEPALIVE_MAX_S * 1000,
				RRR_HTTPCLIENT_SEND_CHUNK_COUNT_LIMIT,
				&callbacks
		) != 0) {
			goto out_message;
		}
	}

	rrr_http_client_set_response_max_size(data->http_client, data->response_max_size);

	if (data->msgdb_socket != NULL) {
		if (rrr_event_collection_push_periodic (
				&data->event_msgdb_poll,
				&data->events,
				httpclient_event_msgdb_poll,
				data,
				data->msgdb_poll_interval_us
		) != 0) {
			RRR_MSG_0("Failed to create msgdb poll event in httpclient\n");
			goto out_message;
		}

		if (httpclient_event_msgdb_poll_add (data, 0) != 0) {
			goto out_message;
		}
	}

	if (rrr_event_collection_push_periodic (
			&data->event_queue_process,
			&data->events,
			httpclient_event_queue_process,
			data,
			5000 // 5 ms
	) != 0) {
		RRR_MSG_0("Failed to create queue process event in httpclient\n");
		goto out_message;
	}

	if (data->request_interval_us > 0) {
		if (rrr_event_collection_push_periodic (
				&data->event_periodic_request,
				&data->events,
				httpclient_event_periodic_request,
				data,
				data->request_interval_us
		) != 0) {
			RRR_MSG_0("Failed to create periodic request event in httpclient\n");
			goto out_message;
		}
		EVENT_ADD(data->event_periodic_request);
	}

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS_H(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			httpclient_pause_check,
			thread_data
	);

	if (rrr_event_function_periodic_set (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000,
			httpclient_event_periodic
	) != 0) {
		RRR_MSG_0("Failed to set periodic function in httpclient instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	return 0;

	out_message:
		httpclient_data_cleanup(data);
		return 1;
}

static void httpclient_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct httpclient_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("Thread httpclient %p exiting\n", thread);

	httpclient_data_cleanup(data);

	*shutdown_complete = 1;
}

struct rrr_instance_event_functions event_functions = {
	httpclient_event_broker_data_available
};

static const char *module_name = "httpclient";

void load (struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->event_functions = event_functions;
	data->init = httpclient_init;
	data->deinit = httpclient_deinit;
}

void unload (void) {
	RRR_DBG_1 ("Destroy httpclient module\n");
}
