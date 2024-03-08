/*

Read Route Record

Copyright (C) 2018-2024 Atle Solbakken atle@goliathdns.no

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
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/mqtt/mqtt_topic.h"
#include "../lib/mqtt/mqtt_client.h"
#include "../lib/mqtt/mqtt_common.h"
#include "../lib/mqtt/mqtt_session.h"
#include "../lib/mqtt/mqtt_subscription.h"
#include "../lib/mqtt/mqtt_packet.h"
#include "../lib/mqtt/mqtt_payload.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_broker.h"
#include "../lib/threads.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/map.h"
#include "../lib/array.h"
#include "../lib/array_tree.h"
#include "../lib/event/event.h"
#include "../lib/event/event_functions.h"
#include "../lib/event/event_collection.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/gnu.h"
#include "../lib/util/utf8.h"
#include "../lib/util/linked_list.h"
#include "../lib/helpers/nullsafe_str.h"

#define RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN 1883
#define RRR_MQTT_DEFAULT_SERVER_PORT_TLS 8883
#define RRR_MQTT_DEFAULT_QOS 1
#define RRR_MQTT_DEFAULT_VERSION 4 // 3.1.1
#define RRR_MQTT_DEFAULT_RECONNECT_ATTEMPTS 20

#define RRR_MQTT_CLIENT_STATS_INTERVAL_MS 1000
#define RRR_MQTT_CLIENT_KEEP_ALIVE 30

// Number of incomplete PUBLISH QoS before we stop polling from other modules. This
// limit is needed because operation gets extremely slow when to to_remote buffer
// fills up in mqtt session_ram framework
// #define RRR_MQTT_CLIENT_INCOMPLETE_PUBLISH_QOS_LIMIT 500

// Hard limit to stop before things go really wrong
// #define RRR_MQTT_CLIENT_TO_REMOTE_BUFFER_LIMIT 2000

#define RRR_MQTT_CONNECT_ERROR_DO_RESTART	"restart"
#define RRR_MQTT_CONNECT_ERROR_DO_RETRY		"retry"

#define RRR_MQTT_CONNACK_TIMEOUT_S     3
#define RRR_MQTT_DISCONNECT_TIMEOUT_S  1

// Timeout before we send PUBLISH packets to the broker. This is to allow,
// if the broker has just been started, other clients to subscribe first
// before we send anything (to prevent it from getting deleted by the broker)
#define RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS 100

// Wait a bit prior to connecting the first time in case MQTT broker to
// connect to is run in the same RRR daemon
#define RRR_MQTT_STARTUP_CONNECT_GRACE_TIME_MS 100

// Timeout before we re-send or give up waiting for SUBACK
#define RRR_MQTT_SUBACK_RESEND_TIMEOUT_MS 1000
#define RRR_MQTT_SUBACK_RESEND_MAX 5

struct rrr_mqtt_session;
struct rrr_array_tree;

enum mqttclient_state {
	MQTTCLIENT_STATE_STARTUP_CONNECT_GRACE,
	MQTTCLIENT_STATE_DISCARD,
	MQTTCLIENT_STATE_CONNECT,
	MQTTCLIENT_STATE_CONNECT_CHECK,
	MQTTCLIENT_STATE_SUBSCRIBE,
	MQTTCLIENT_STATE_STARTUP_SEND_GRACE,
	MQTTCLIENT_STATE_PROCESS,
	MQTTCLIENT_STATE_DISCONNECT
};

struct mqttclient_data {
	struct rrr_instance_runtime_data *thread_data;

	char *server;
	char *publish_topic;
	char *version_str;
	char *client_identifier;
	char *retain_tag;

	struct rrr_mqtt_topic_token *topic_filter_command;

	char *username;
	char *password;

	char *connect_error_action;
	rrr_setting_uint connect_attempts;

	struct rrr_map publish_array_values_list;
	struct rrr_array_tree *tree;

	uint16_t server_port;
	rrr_setting_uint qos;
	rrr_setting_uint version;

	struct rrr_mqtt_subscription_collection *subscriptions;

	char *will_topic;
	uint16_t will_topic_length;
	char *will_message_str;
	struct rrr_nullsafe_str *will_message;
	rrr_setting_uint will_qos;
	int do_will_retain;

	enum rrr_instance_config_write_method publish_method;

	int do_prepend_publish_topic;
	int do_force_publish_topic;
	int do_receive_rrr_message;
	int do_receive_publish_topic;
	int do_recycle_assigned_client_identifier;
	int do_discard_on_connect_retry;

	int do_qos2_fail_once;
	int fail_once_state;

	struct rrr_mqtt_client_data *mqtt_client_data;
	struct rrr_mqtt_session *session;
	struct rrr_mqtt_property_collection connect_properties;

	int clean_start;
	int send_discouraged;

	struct rrr_msg_holder_collection input_queue;

	// State machine
	enum mqttclient_state state;
	unsigned long connect_attempt_count;
	uint64_t state_time;
	uint64_t prev_state_time;
	uint64_t poll_discard_count;

	struct rrr_net_transport_config net_transport_config;
	int transport_handle;

	uint64_t total_sent_count;
	uint64_t total_discarded_count;
};

static void mqttclient_data_cleanup(void *arg) {
	struct mqttclient_data *data = arg;
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->publish_topic);
	RRR_FREE_IF_NOT_NULL(data->version_str);
	RRR_FREE_IF_NOT_NULL(data->client_identifier);
	RRR_FREE_IF_NOT_NULL(data->retain_tag);
	RRR_FREE_IF_NOT_NULL(data->connect_error_action);
	RRR_FREE_IF_NOT_NULL(data->username);
	RRR_FREE_IF_NOT_NULL(data->password);
	RRR_FREE_IF_NOT_NULL(data->will_topic);
	RRR_FREE_IF_NOT_NULL(data->will_message_str);
	rrr_nullsafe_str_destroy_if_not_null(&data->will_message);
	rrr_mqtt_topic_token_destroy(data->topic_filter_command);
	rrr_map_clear(&data->publish_array_values_list);
	rrr_mqtt_subscription_collection_destroy(data->subscriptions);
	rrr_mqtt_property_collection_clear(&data->connect_properties);
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}
	rrr_net_transport_config_cleanup(&data->net_transport_config);
	rrr_msg_holder_collection_clear(&data->input_queue);
}

static int mqttclient_state_check (struct mqttclient_data *data, enum mqttclient_state state) {
	return data->state == state;
}

static void mqttclient_state_set (struct mqttclient_data *data, enum mqttclient_state state) {
	assert(data->state != state);
	assert(data->state_time > 0);

	data->state = state;
	data->prev_state_time = data->state_time;
	data->state_time = rrr_time_get_64();
}

static void mqttclient_state_init (struct mqttclient_data *data, enum mqttclient_state state) {
	assert(data->state_time == 0);
	assert(data->prev_state_time == 0);

	data->state = state;
	data->state_time = rrr_time_get_64();
}

static void mqttclient_state_ensure (struct mqttclient_data *data, enum mqttclient_state state) {
	if (data->state != state) {
		mqttclient_state_set(data, state);
	}
}

static int mqttclient_state_transition_timed (struct mqttclient_data *data, enum mqttclient_state state, uint64_t delta_ms) {
	if (rrr_time_get_64() - data->state_time > delta_ms * 1000) {
		mqttclient_state_set(data, state);
		return 1;
	}
	return 0;
}

static int mqttclient_subscription_push (struct rrr_mqtt_subscription_collection *target, struct mqttclient_data *data, uint8_t qos, const char *topic_str) {
	int ret = 0;

	if (rrr_mqtt_topic_filter_validate_name(topic_str) != 0) {
		ret = 1;
		goto out;
	}

	if ((ret = rrr_mqtt_subscription_collection_push_unique_str (
			target,
			topic_str,
			0,
			0,
			0,
			qos
	)) != 0) {
		if (ret == RRR_MQTT_SUBSCRIPTION_REFUSED) {
			rrr_length subscription_count = rrr_mqtt_subscription_collection_count(target);
			RRR_MSG_0("Subscription add refused, collection is possibly full. Entry count is %" PRIrrrl ".\n",
				subscription_count);
		}
		RRR_MSG_0("Could not add topic '%s' to subscription collection int mqtt client instance %s\n",
			topic_str, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int mqttclient_message_data_to_payload (
		char **result,
		rrr_u32 *result_size,
		const struct rrr_msg_msg *reading
) {
	*result = NULL;
	*result_size = 0;

	char *payload = rrr_allocate(MSG_DATA_LENGTH(reading));

	if (payload == NULL) {
		RRR_MSG_0 ("could not allocate memory for PUBLISH payload in message_data_to_payload \n");
		return 1;
	}

	memcpy(payload, MSG_DATA_PTR(reading), MSG_DATA_LENGTH(reading));

	*result = payload;
	*result_size = MSG_DATA_LENGTH(reading);

	return 0;
}

static int mqttclient_do_subscribe (struct mqttclient_data *data) {
	int ret = RRR_MQTT_OK;

	if ((ret = rrr_mqtt_client_subscribe (
			data->mqtt_client_data,
			&data->session,
			data->subscriptions
	)) != 0) {
		RRR_MSG_0("Could not subscribe to topics in MQTT client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	out:
	return ret;
}
	
static int mqttclient_publish_set_topic (
		int *do_drop,
		struct rrr_mqtt_p_publish *publish,
		struct mqttclient_data *data,
		const struct rrr_msg_msg *reading
) {
	int ret = 0;

	*do_drop = 0;

	RRR_FREE_IF_NOT_NULL(publish->topic);

	if (MSG_TOPIC_LENGTH(reading) > 0 && *((const char *) MSG_TOPIC_PTR(reading)) == '\0') {
		RRR_BUG("BUG: Topic first character value was '0' in %s\n", __func__);
	}

	if (data->do_prepend_publish_topic) {
		if (MSG_TOPIC_LENGTH(reading) == 0) {
			RRR_MSG_0("Warning: Received message to MQTT client instance %s did not have topic set, and only a prepend topic is set in configuration. Dropping message.\n",
					INSTANCE_D_NAME(data->thread_data));
			*do_drop = 1;
			goto out;
		}

		// NOTE : Locally freed variable. Memory error is printed further down if we fail.
		char *topic_tmp = rrr_allocate ((rrr_biglength) MSG_TOPIC_LENGTH(reading) + 1);
		if (topic_tmp != NULL) {
			memcpy (topic_tmp, MSG_TOPIC_PTR(reading), MSG_TOPIC_LENGTH(reading));
			*(topic_tmp + MSG_TOPIC_LENGTH(reading)) = '\0';
			rrr_asprintf(&publish->topic, "%s%s", data->publish_topic, topic_tmp);
			rrr_free(topic_tmp);
		}
	}
	else {
		if (MSG_TOPIC_LENGTH(reading) > 0 && data->do_force_publish_topic == 0) {
			publish->topic = rrr_allocate ((rrr_biglength) MSG_TOPIC_LENGTH(reading) + 1);
			if (publish->topic != NULL) {
				memcpy (publish->topic, MSG_TOPIC_PTR(reading), MSG_TOPIC_LENGTH(reading));
				*(publish->topic + MSG_TOPIC_LENGTH(reading)) = '\0';
			}
		}
		else if (data->publish_topic != NULL) {
			publish->topic = rrr_strdup(data->publish_topic);
		}
		else {
			if (data->do_force_publish_topic != 0) {
				RRR_BUG("do_force_publish_topic was 1 but topic was not set in %s\n", __func__);
			}
			RRR_MSG_0("Warning: Received message to MQTT client instance %s did not have topic set, and no default topic was defined in the configuration. Dropping message.\n",
					INSTANCE_D_NAME(data->thread_data));
			*do_drop = 1;
			goto out;
		}
	}

	if (publish->topic == NULL) {
		RRR_MSG_0("Warning: Could not allocate topic in %s of MQTT client instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int mqttclient_publish_add_payload (
		struct rrr_mqtt_p_publish *publish,
		struct mqttclient_data *data,
		const struct rrr_msg_msg *reading
) {
	int ret = 0;

	struct rrr_msg_msg *msg_copy = NULL;
	char *payload = NULL;
	rrr_u32 payload_size = 0;
	struct rrr_array array_tmp = {0};

	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->payload);
	publish->payload = NULL;

	if (data->publish_method == RRR_INSTANCE_CONFIG_WRITE_METHOD_RRR_MESSAGE) {
		if ((msg_copy = rrr_msg_msg_duplicate(reading)) == NULL) {
			RRR_MSG_0("Could not copy message in %s of mqttclient_publish instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}

		rrr_u32 msg_size = MSG_TOTAL_SIZE(msg_copy);

		msg_copy->msg_size = msg_size;

		rrr_msg_msg_prepare_for_network(msg_copy);

		rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) msg_copy);

		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&publish->properties,
				RRR_MQTT_PROPERTY_CONTENT_TYPE,
				RRR_MESSAGE_MIME_TYPE,
				strlen(RRR_MESSAGE_MIME_TYPE)
		) != 0) {
			RRR_MSG_0("Could not set content-type of publish in %s of MQTT client instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
		payload = (char *) msg_copy;
		payload_size = msg_size;
		msg_copy = NULL;
	}
	else if (data->publish_method == RRR_INSTANCE_CONFIG_WRITE_METHOD_ARRAY_VALUES) {
		if (!MSG_IS_ARRAY(reading)) {
			RRR_MSG_0("Received message was not an array while mqtt_publish_array_values was set in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}

		const struct rrr_map *tags_to_use = (RRR_LL_COUNT(&data->publish_array_values_list) > 0
				? &data->publish_array_values_list
				: NULL
		);

		uint16_t array_version_dummy;
		if (rrr_array_message_append_to_array(&array_version_dummy, &array_tmp, reading) != 0) {
			RRR_MSG_0("Could not create temporary array collection in %s of MQTT client instance %s\n",
					__func__, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}

		int found_tags = 0;

		{
			rrr_biglength payload_size_tmp = 0;
			if ((ret = rrr_array_selected_tags_export (
					&payload,
					&payload_size_tmp,
					&found_tags,
					&array_tmp,
					tags_to_use
			)) != 0) {
				RRR_MSG_0("Could not create payload data from selected array tags in MQTT client instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				ret = 1;
				goto out;
			}

			if (payload_size_tmp > UINT32_MAX) {
				RRR_MSG_0("Payload was too long while exporting array data in MQTT client instance %s (%llu > %llu)\n",
					INSTANCE_D_NAME(data->thread_data),
					(unsigned long long) payload_size_tmp,
					(unsigned long long) UINT32_MAX
				);
				ret = 1;
				goto out;
			}
			payload_size = (rrr_u32) payload_size_tmp;
		}

		if (tags_to_use != NULL && found_tags != RRR_MAP_COUNT(tags_to_use)) {
			RRR_DBG_1("Note: Only %i tags out of %i specified in configuration was found in message when sending array data in mqtt instance %s\n",
					found_tags, RRR_MAP_COUNT(&data->publish_array_values_list), INSTANCE_D_NAME(data->thread_data));
		}
	}
	else if (MSG_DATA_LENGTH(reading) > 0 && !MSG_IS_ARRAY(reading)) {
		if ((ret = mqttclient_message_data_to_payload(&payload, &payload_size, reading)) != 0) {
			RRR_MSG_0("Error while creating payload from message data in %s of MQTT client instance %s\n",
					__func__, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
	}
	else {
		if ((ret = rrr_msg_msg_to_string(&payload, reading)) != 0) {
			RRR_MSG_0("Could not convert message to string for PUBLISH payload in %s of MQTT client instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		payload_size = (rrr_u32) strlen(payload) + 1;
	}

	if (payload != NULL && payload_size > 0) {
		if (rrr_mqtt_p_payload_new_with_allocated_payload (
				&publish->payload,
				&payload, // Set to NULL if success
				payload,
				payload_size
		) != 0) {
			RRR_MSG_0("Could not set payload of PUBLISH in mqttclient_publish of MQTT client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}

		// Note: False positive here from static code analysis about memory leak of payload

		if (payload != NULL) {
			RRR_BUG("BUG: payload was not NULL after payload allocation in %s\n", __func__);
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_copy);
	rrr_array_clear (&array_tmp);
	RRR_FREE_IF_NOT_NULL(payload);
	return ret;
}

static int mqttclient_publish_handle_retain (
		int *do_no_payload,
		struct rrr_mqtt_p_publish *publish,
		struct mqttclient_data *data,
		const struct rrr_msg_msg *reading
) {
	int ret = 0;

	struct rrr_type_value *retain_value = NULL;
	char *str_tmp = NULL;

	*do_no_payload = 0;

	if (data->retain_tag == NULL || !MSG_IS_ARRAY(reading)) {
	       goto out;
	}

	if (rrr_array_message_clone_value_by_tag (
			&retain_value,
			reading,
			data->retain_tag
	) != 0) {
		RRR_MSG_0("Could not get retain tag value from message in %s of MQTT client instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (retain_value == NULL) {
		goto out;
	}

	RRR_MQTT_P_PUBLISH_SET_FLAG_RETAIN(publish, 1);

	if (retain_value->definition->to_str != NULL && retain_value->definition->to_str(&str_tmp, retain_value) != 0) {
		RRR_MSG_0("Could not get string value from retain array value in %s of MQTT client instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (str_tmp != NULL && strcmp(str_tmp, "clear") == 0) {
		*do_no_payload = 1;
		goto out;
	}

	const unsigned long long expiry_interval_s = retain_value->definition->to_ull != NULL
		? retain_value->definition->to_ull(retain_value)
		: 0
	;

#if ULLONG_MAX > UINT32_MAX
	if (expiry_interval_s > UINT32_MAX) {
		RRR_MSG_0("Expiry interval in retain tag %s of message in MQTT client instance %s exceeds maximum (value is %llu)\n",
				data->retain_tag, INSTANCE_D_NAME(data->thread_data), expiry_interval_s);
		ret = 1;
		goto out;
	}
#endif

	publish->message_expiry_interval = (uint32_t) expiry_interval_s;

	if (rrr_mqtt_property_collection_add_uint32 (
			&publish->properties,
			RRR_MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL,
			(uint32_t) expiry_interval_s
	) != 0) {
		RRR_MSG_0("Could not add expiry interval to property collection in %s of MQTT client instance %s\n",
				__func__, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

out:
	RRR_FREE_IF_NOT_NULL(str_tmp);
	if (retain_value != NULL) {
		rrr_type_value_destroy(retain_value);
	}
	return ret;
}

static int mqttclient_publish (
		struct mqttclient_data *data,
		const struct rrr_msg_msg *reading
) {
	int ret = 0;

	struct rrr_mqtt_p_publish *publish = NULL;

	RRR_DBG_3 ("MQTT client %s: Result from input queue: timestamp %" PRIu64 ", creating PUBLISH\n",
			INSTANCE_D_NAME(data->thread_data), reading->timestamp);

	if (data->mqtt_client_data->protocol_version == NULL) {
		RRR_MSG_0("Protocol version not yet set in MQTT client instance %s mqttclient_publish while sending PUBLISH\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if ((publish = (struct rrr_mqtt_p_publish *) rrr_mqtt_p_allocate (
			RRR_MQTT_P_TYPE_PUBLISH,
			data->mqtt_client_data->protocol_version
	)) == NULL) {
		RRR_MSG_0("Could not allocate PUBLISH in mqttclient_publish of MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	int do_drop = 0;
	if ((ret = mqttclient_publish_set_topic (&do_drop, publish, data, reading)) != 0 || do_drop) {
		goto out;
	}

	RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(publish, data->qos);

	int do_no_payload = 0;
	if (mqttclient_publish_handle_retain (
			&do_no_payload,
			publish,
			data,
			reading
	) != 0) {
		// Don't set error return value
		goto out;
	}

	if (!do_no_payload && mqttclient_publish_add_payload (publish, data, reading) != 0) {
		// Don't set error return value
		goto out;
	}

	RRR_DBG_2 ("|==> MQTT client %s: Send PUBLISH with topic %s payload size %" PRIrrrl " retain %u expiry interval %" PRIu32 "\n",
			INSTANCE_D_NAME(data->thread_data),
			publish->topic,
			publish->payload != NULL ? publish->payload->size : 0,
			RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(publish),
			publish->message_expiry_interval
	);

	if (rrr_mqtt_client_publish(&data->send_discouraged, data->mqtt_client_data, &data->session, publish) != 0) {
		RRR_MSG_0("Could not publish message in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	data->total_sent_count++;

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish);
	return ret;
}

static int mqttclient_process_command_subscribe_new_subscrition_callback (
		const struct rrr_mqtt_subscription *subscription,
		void *arg
) {
	struct mqttclient_data *data = arg;
	RRR_DBG_1("mqtt client instance %s new subscription '%s' from command\n", INSTANCE_D_NAME(data->thread_data), subscription->topic_filter);
	return 0;
}

static int mqttclient_process_command_get_topic_filters (
		struct rrr_mqtt_subscription_collection **target,
		struct mqttclient_data *data,
		const struct rrr_array *array
) {
	int ret = 0;

	char *topic_filter_tmp = NULL;
	struct rrr_mqtt_subscription_collection *subscriptions_tmp = NULL;

	if ((ret = rrr_mqtt_subscription_collection_new(&subscriptions_tmp)) != 0) {
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (node->definition->to_str == NULL) {
			RRR_MSG_0("Warning: A value in command message to mqtt client instance %s could not be converted to a string\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (rrr_type_value_is_tag(node, "mqtt_topic_filter")) {
			RRR_FREE_IF_NOT_NULL(topic_filter_tmp);
			if ((ret = node->definition->to_str (&topic_filter_tmp, node)) != 0) {
				goto out;
			}
			if ((ret = mqttclient_subscription_push (subscriptions_tmp, data, 0, topic_filter_tmp)) != 0) {
				goto out;
			}
		}
		else {
			RRR_MSG_0("Warning: Unknown value '%s' in command to mqtt client\n", node->tag != NULL ? node->tag : "(not tag)");
			goto out;
		}
	RRR_LL_ITERATE_END();

	*target = subscriptions_tmp;
	subscriptions_tmp = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(topic_filter_tmp);
	if (subscriptions_tmp != NULL) {
		rrr_mqtt_subscription_collection_destroy(subscriptions_tmp);
	}
	return ret;
}

static int mqttclient_process_command_subscribe (
		struct mqttclient_data *data,
		const struct rrr_array *array
) {
	int ret = 0;

	struct rrr_mqtt_subscription_collection *subscriptions_tmp = NULL;

	if ((ret = mqttclient_process_command_get_topic_filters (&subscriptions_tmp, data, array)) != 0) {
		goto out;
	}

	if ((ret = rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
			data->subscriptions,
			subscriptions_tmp,
			0,
			mqttclient_process_command_subscribe_new_subscrition_callback,
			data
	)) != 0) {
		// Failing here causes inconsistent state, must restart
		RRR_MSG_0("Failed to merge subscription collections in mqtt client instance %s, cannot continue.\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = mqttclient_do_subscribe (data)) != 0) {
		goto out;
	}

	out:
	if (subscriptions_tmp != NULL) {
		rrr_mqtt_subscription_collection_destroy(subscriptions_tmp);
	}
	return ret;
}

static int mqttclient_process_command_unsubscribe (
		struct mqttclient_data *data,
		const struct rrr_array *array
) {
	int ret = 0;

	struct rrr_mqtt_subscription_collection *subscriptions_tmp = NULL;

	if ((ret = mqttclient_process_command_get_topic_filters (&subscriptions_tmp, data, array)) != 0) {
		goto out;
	}

	if ((ret = rrr_mqtt_client_unsubscribe (
			data->mqtt_client_data,
			&data->session,
			subscriptions_tmp
	)) != 0) {
		RRR_MSG_0("Could not unsubscribe to topics in MQTT client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	if (data->version == 5) {
		// Topics are removed from requested topics when UNSUBACK arrrives
		RRR_LL_ITERATE_BEGIN(subscriptions_tmp, struct rrr_mqtt_subscription);
			RRR_DBG_1("mqtt client instance %s unsubscription '%s' requested from command (awaiting feedback)\n",
				INSTANCE_D_NAME(data->thread_data), node->topic_filter);
		RRR_LL_ITERATE_END_CHECK_DESTROY(subscriptions_tmp, 0; rrr_mqtt_subscription_destroy(node));
	}
	else {
		rrr_length removed_count = 0;
		if ((ret = rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
				data->subscriptions,
				subscriptions_tmp,
				&removed_count
		)) != 0) {
			goto out;
		}

		RRR_LL_ITERATE_BEGIN(subscriptions_tmp, struct rrr_mqtt_subscription);
			const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(node->qos_or_reason_v5);
			if (node->qos_or_reason_v5 != 0) {
				RRR_DBG_1("mqtt client instance %s unsubscription '%s' request from command failed locally with reason %s (version is 3.1.1)\n",
					INSTANCE_D_NAME(data->thread_data), node->topic_filter, reason != NULL ? reason->description : "UNKNOWN");
				RRR_LL_ITERATE_SET_DESTROY();
			}
			else {
				RRR_DBG_1("mqtt client instance %s unsubscription '%s' requested from command (version is 3.1.1, no feedback will be received)\n",
					INSTANCE_D_NAME(data->thread_data), node->topic_filter);
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY(subscriptions_tmp, 0; rrr_mqtt_subscription_destroy(node));
	}

	out:
	if (subscriptions_tmp != NULL) {
		rrr_mqtt_subscription_collection_destroy(subscriptions_tmp);
	}
	return ret;
}

static int mqttclient_process_command_disconnect (
		struct mqttclient_data *data,
		const struct rrr_array *array
) {
	const uint8_t reason_v5 = rrr_array_has_tag (array, "mqtt_disconnect_with_will")
		? RRR_MQTT_P_5_REASON_DISCONNECT_WITH_WILL
		: 0
	;

	RRR_DBG_1("mqtt client instance %s disconnect requested reason code 0x%02x\n", 
			INSTANCE_D_NAME(data->thread_data), reason_v5);

	rrr_mqtt_client_disconnect(data->mqtt_client_data, data->transport_handle, reason_v5);

	mqttclient_state_set (data, MQTTCLIENT_STATE_DISCONNECT);

	return RRR_MQTT_OK;
}

static int mqttclient_process_command (
		struct mqttclient_data *data,
		const struct rrr_msg_msg *reading
) {
	int ret = 0;

	struct rrr_array array = {0};
	char *command = NULL;

	if (!MSG_IS_ARRAY(reading)) {
		RRR_MSG_0("Warning: Received a command message in mqtt client instance %s which was not an array message.\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	uint16_t array_version_dummy;
	if ((ret = rrr_array_message_append_to_array (&array_version_dummy, &array, reading)) != 0) {
		goto out;
	}

	if (rrr_array_get_value_str_by_tag (&command, &array, "mqtt_command") != 0) {
		RRR_MSG_0("Warning: Failed to get command tag in mqtt client instance %s.\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (command == NULL) {
		RRR_MSG_0("Warning: Received a command message with missing command tag 'mqtt_command' in mqtt client instance %s.\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	rrr_array_clear_by_tag (&array, "mqtt_command");

	if (strcmp(command, "subscribe") == 0) {
		ret = mqttclient_process_command_subscribe(data, &array);
	}
	else if (strcmp(command, "unsubscribe") == 0) {
		ret = mqttclient_process_command_unsubscribe(data, &array);
	}
	else if (strcmp(command, "disconnect") == 0) {
		ret = mqttclient_process_command_disconnect(data, &array);
	}
	else {
		RRR_MSG_0("Warning: Unknown command '%s' in mqtt client instance %s\n", command, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	rrr_array_clear(&array);
	RRR_FREE_IF_NOT_NULL(command);
	if (ret != 0) {
		RRR_MSG_0("MQTT client instance %s stopping due to hard error during processing of command message\n",
				INSTANCE_D_NAME(data->thread_data));
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
	return ret;
}

static int mqttclient_process (
		struct mqttclient_data *data,
		const struct rrr_msg_holder *entry
) {
	const struct rrr_msg_msg *reading = (const struct rrr_msg_msg *) entry->message;

	int ret = 0;

	int is_command = 0;

	if (data->topic_filter_command != NULL && (ret = rrr_msg_msg_topic_match (
			&is_command,
			reading,
			data->topic_filter_command
	)) != 0) {
		goto out;
	}

	if (is_command) {
		if ((ret = mqttclient_process_command (data, reading)) != 0) {
			goto out;
		}
	}
	else {
		if ((ret = mqttclient_publish(data, reading)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int mqttclient_data_init (
		struct mqttclient_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	if (rrr_mqtt_subscription_collection_new(&data->subscriptions) != 0) {
		RRR_MSG_0("Could not create subscription collection in MQTT client mqttclient_data_init\n");
		ret = 1;
		goto out;
	}

	data->thread_data = thread_data;

	goto out;
//	out_destroy_subscription_collection:
//		rrr_mqtt_subscription_collection_destroy(data->requested_subscriptions);
	out:
		return ret;
}

static int mqttclient_parse_sub_topic (const char *topic_str, void *arg) {
	struct mqttclient_data *data = arg;

	RRR_DBG_1("mqtt client instance %s new subscription '%s' from configuration\n", INSTANCE_D_NAME(data->thread_data), topic_str);

	return mqttclient_subscription_push(data->subscriptions, data, (uint8_t) data->qos, topic_str);
}

static int mqttclient_parse_config (struct mqttclient_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("mqtt_connect_attempts", connect_attempts, RRR_MQTT_DEFAULT_RECONNECT_ATTEMPTS);
	if (data->connect_attempts < 1) {
		RRR_MSG_0("Setting mqtt_reconnect_attempts must be 1 or more in MQTT client instance %s. %" PRIrrrbl " was given.",
				config->name, data->connect_attempts);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("mqtt_qos", qos, RRR_MQTT_DEFAULT_QOS);
	if (data->qos > 2) {
		RRR_MSG_0("Setting mqtt_qos was >2 in config of instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	// Undocumented parameter. Cases QoS2 to fail upon retrieval of PUBLISH and PUBREL (one time each),
	// and mqttclient must reconnect upon which the broker should retransmit the PUBLISH.
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_qos2_fail_once", do_qos2_fail_once, 0);

	if (data->do_qos2_fail_once && data->qos != 2) {
		RRR_MSG_0("mqtt_qos2_fail_once was set to yes but mqtt_qos was not 2 in mqttclient instance %s, this is a configuration error.\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_client_identifier", client_identifier);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_retain_tag", retain_tag);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC_FILTER("mqtt_command_topic_filter", topic_filter_command);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_v5_recycle_assigned_client_identifier", do_recycle_assigned_client_identifier, 1); // Default is 1, yes

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("mqtt_will_topic", will_topic, will_topic_length);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_will_message", will_message_str);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("mqtt_will_qos", will_qos, RRR_MQTT_DEFAULT_QOS);
	if (data->will_qos > 2) {
		RRR_MSG_0("Setting mqtt_will_qos was >2 in config of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_will_retain", do_will_retain, 0);

	if (data->will_message_str != NULL) {
		if ((ret = rrr_nullsafe_str_new_or_replace_raw(&data->will_message, data->will_message_str, strlen(data->will_message_str))) != 0) {
			RRR_MSG_0("Failed to store will message in %s of %s\n", __func__, config->name);
			goto out;
		}
	}

	if (data->will_topic == NULL) {
		RRR_INSTANCE_CONFIG_IF_EXISTS_THEN (
			"mqtt_will_message",
			RRR_MSG_0("mqtt_will_message was set but mqtt_will_topic was not in mqtt client instance %s, this is a configuration error.\n", config->name); ret = 1; goto out;
		);
		RRR_INSTANCE_CONFIG_IF_EXISTS_THEN (
			"mqtt_will_qos",
			RRR_MSG_0("mqtt_will_qos was set but mqtt_will_topic was not in mqtt client instance %s, this is a configuration error.\n", config->name); ret = 1; goto out;
		);
		RRR_INSTANCE_CONFIG_IF_EXISTS_THEN (
			"mqtt_will_retain",
			RRR_MSG_0("mqtt_will_retain was set but mqtt_will_topic was not in mqtt client instance %s, this is a configuration error.\n", config->name); ret = 1; goto out;
		);
	}


	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->version_str, config, "mqtt_version")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not parse configuration parameter 'mqtt_version' of MQTT client instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->version = RRR_MQTT_DEFAULT_VERSION;
	}
	else {
		if (strcmp(data->version_str, "3.1.1") == 0) {
			data->version = 4;
		}
		else if (strcmp (data->version_str, "5") == 0) {
			data->version = 5;
		}
		else {
			RRR_MSG_0("Unknown protocol version '%s' in setting mqtt_version of instance %s. " \
					"Supported values are 3.1.1 and 5\n", data->version_str, config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->server, config, "mqtt_server")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing mqtt_server setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		data->server = rrr_strdup("localhost");
		if (data->server == NULL) {
			RRR_MSG_0("Could not allocate memory for mqtt_server in MQTT client\n");
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_instance_config_parse_array_tree_definition_from_config_silent_fail(
			&data->tree,
			config,
			"mqtt_receive_array"
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing array definition in mqtt_receive_array of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_receive_rrr_message", do_receive_rrr_message, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_receive_publish_topic", do_receive_publish_topic, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_publish_topic_force", do_force_publish_topic, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_publish_topic_prepend", do_prepend_publish_topic, 0);

	if (data->do_force_publish_topic != 0 && data->do_prepend_publish_topic != 0) {
		RRR_MSG_0("Both mqtt_publish_topic_force and mqtt_publish_topic_prepend was yes for instance %s, this is an invalid configuration.\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_publish_topic", publish_topic);

	if (data->publish_topic != NULL && rrr_mqtt_topic_validate_name(data->publish_topic) != 0) {
		RRR_MSG_0("Topic name in mqtt_publish_topic was invalid for instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (data->publish_topic == NULL && data->do_force_publish_topic != 0) {
		RRR_MSG_0("mqtt_force_publish_topic was yes but no mqtt_publish_topic was set for instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (data->publish_topic == NULL && data->do_prepend_publish_topic != 0) {
		RRR_MSG_0("mqtt_prepend_publish_topic was yes but no mqtt_publish_topic was set for instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (rrr_instance_config_traverse_split_commas_silent_fail(config, "mqtt_subscribe_topics", mqttclient_parse_sub_topic, data) != 0) {
		RRR_MSG_0("Error while parsing mqtt_subscribe_topics setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_instance_config_parse_optional_write_method (
			&data->publish_array_values_list,
			&data->publish_method,
			config,
			"mqtt_publish_rrr_message",
			"mqtt_publish_array_values"
	)) != 0) {
		goto out;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->connect_error_action, config, "mqtt_connect_error_action")) == 0) {
		if (strcasecmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RESTART) == 0) {
			// OK
		}
		else if (strcasecmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) == 0) {
			// OK
		}
		else {
			RRR_MSG_0("Unknown value for mqtt_connect_error_action (̈́'%s') in MQTT client instance %s, please refer to documentation\n",
					data->connect_error_action, config->name);
		}
	}
	else {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing mqtt_connect_error_action\n");
			ret = 1;
			goto out;
		}

		data->connect_error_action = rrr_strdup(RRR_MQTT_CONNECT_ERROR_DO_RESTART);
		if (data->connect_error_action == NULL) {
			RRR_MSG_0("Could not allocate memory for connect_error_action in MQTT client\n");
			ret = 1;
			goto out;
		}
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_discard_on_connect_retry", do_discard_on_connect_retry, 0);

	if (data->do_discard_on_connect_retry != 0 && strcasecmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) != 0) {
		RRR_MSG_0("mqtt_do_discard_on_connect_retry was 'yes' in mqttclient instance %s but mqtt_connect_error_action was not 'retry', this is an error.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_username", username);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_password", password);

	if (data->password != NULL && data->username == NULL) {
		RRR_MSG_0("mqtt_password set without mqtt_username being so in mqttclient instance %s, this in an error.\n",
				config->name);
		ret = 1;
		goto out;
	}

	if ((rrr_net_transport_config_parse (
			&data->net_transport_config,
			config,
			"mqtt",
			0, /* Don't allow multiple transports */
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
			0, /* Don't allow to set certificate without transport type being TLS */
			RRR_NET_TRANSPORT_PLAIN,
			RRR_NET_TRANSPORT_F_PLAIN|RRR_NET_TRANSPORT_F_TLS
#else
			0,
			RRR_NET_TRANSPORT_PLAIN,
			RRR_NET_TRANSPORT_F_PLAIN
#endif
	)) != 0) {
		goto out;
	}

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
	if (data->net_transport_config.transport_type_f & RRR_NET_TRANSPORT_F_TLS)
		data->net_transport_config.transport_type_p = RRR_NET_TRANSPORT_TLS;
#endif

	if ((ret = rrr_instance_config_read_optional_port_number (
			&data->server_port,
			config,
			"mqtt_server_port"
	)) != 0) {
		goto out;
	}

	if (data->server_port == 0) {
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
		data->server_port = data->net_transport_config.transport_type_p == RRR_NET_TRANSPORT_TLS
			? RRR_MQTT_DEFAULT_SERVER_PORT_TLS
			: RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN;
#else
		data->server_port = RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN;
#endif
	}

	ret = 0;

	/* On error, memory is freed by mqttclient_data_cleanup */

	out:
	return ret;
}

static int mqttclient_process_suback_unsuback (
		struct rrr_mqtt_client_data *mqttclient_data,
		struct rrr_mqtt_p_suback_unsuback *packet,
		void *arg
) {
	struct mqttclient_data *data = arg;

	(void)(mqttclient_data);

	const struct rrr_mqtt_subscription_collection *orig_collection = packet->orig_sub_usub->subscriptions;

	rrr_length new_count = packet->acknowledgements_size;
	rrr_length orig_count = (orig_collection != NULL ? rrr_mqtt_subscription_collection_count(orig_collection) : 0);

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK) {
		if (orig_count != new_count) {
			// Session framework should catch this
			RRR_BUG("Count mismatch in SUBSCRIBE and SUBACK messages in MQTT client instance %s (%i vs %i)\n",
					INSTANCE_D_NAME(data->thread_data), orig_count, new_count);
		}

		// We don't actually keep track of which subscriptions have been accepted, but only
		// print warnings about those topics which were rejected by the broker
		for (rrr_length i = 0; i < new_count; i++) {
			const struct rrr_mqtt_subscription *subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx (
					orig_collection,
					i
			);

			const uint8_t qos_or_reason_v5 = packet->acknowledgements[i];
			if (qos_or_reason_v5 > 2) {
				const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(qos_or_reason_v5);
				if (reason == NULL) {
					RRR_MSG_0("Unknown reason 0x%02x from mqtt broker in SUBACK topic index %" PRIrrrl " in MQTT client instance %s",
							qos_or_reason_v5, i, INSTANCE_D_NAME(data->thread_data));
					return 1;
				}
				RRR_MSG_0("Warning: Subscription '%s' index '%" PRIrrrl "' rejected from broker in MQTT client instance %s with reason '%s'\n",
						subscription->topic_filter,
						i,
						INSTANCE_D_NAME(data->thread_data),
						reason->description
				);
			}
			else {
				if (qos_or_reason_v5 < subscription->qos_or_reason_v5) {
					RRR_MSG_0("Warning: Subscription '%s' index '%" PRIrrrl "' assigned QoS %u from server while %u was requested in MQTT client instance %s \n",
							subscription->topic_filter,
							i,
							qos_or_reason_v5,
							subscription->qos_or_reason_v5,
							INSTANCE_D_NAME(data->thread_data)
					);
				}	
				RRR_DBG_1("mqtt client instance %s subscription '%s' index '%" PRIrrrl "' qos %u confirmed\n",
					INSTANCE_D_NAME(data->thread_data), subscription->topic_filter, i, subscription->qos_or_reason_v5);
			}
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK) {
		if (RRR_MQTT_P_IS_V5(packet)) {
			if (orig_count != new_count) {
				// Session framework should catch this
				RRR_BUG("Count mismatch in UNSUBSCRIBE and UNSUBACK messages in MQTT client instance %s (%i vs %i)\n",
						INSTANCE_D_NAME(data->thread_data), orig_count, new_count);
			}
			for (rrr_length i = 0; i < new_count; i++) {
				const struct rrr_mqtt_subscription *subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx (
						orig_collection,
						i
				);

				const uint8_t qos_or_reason_v5 = packet->acknowledgements[i];
				const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(qos_or_reason_v5);
				if (qos_or_reason_v5 != 0) {
					RRR_DBG_1("mqtt client instance %s unsubscription '%s' failed remotely with reason 0x%02x %s (version is 5)\n",
						INSTANCE_D_NAME(data->thread_data), subscription->topic_filter, qos_or_reason_v5, reason != NULL ? reason->description : "UNKNOWN");
				}
				else {
					RRR_DBG_1("mqtt client instance %s unsubscription '%s' confirmed (version is 5)\n",
						INSTANCE_D_NAME(data->thread_data), subscription->topic_filter);

					int did_remove = 0;
					if (rrr_mqtt_subscription_collection_remove_topic (
							&did_remove,
							data->subscriptions,
							subscription->topic_filter
					) != 0) {
						RRR_MSG_0("Failed to remove topic '%s' from local subscription collection upon UNSUBACK in mqtt client instance %s\n",
								subscription->topic_filter, INSTANCE_D_NAME(data->thread_data));
						return 1;
					}

					if (!did_remove) {
						// OK, possible double unsubscription
					}
				}
			}
		}
		else {
			// Can't really do anything, UNSUBACK V3.1 has no information
		}
	}
	else {
		RRR_BUG("Unknown packet of type %u received in MQTT client %s mqttclient_process_suback\n",
				RRR_MQTT_P_GET_TYPE(packet),
				INSTANCE_D_NAME(data->thread_data)
		);
	}

	return 0;
}

// Used to print informational messages only
static int mqttclient_process_parsed_packet (
		struct rrr_mqtt_client_data *mqttclient_data,
		struct rrr_mqtt_p *packet,
		void *arg
) {
	struct mqttclient_data *data = arg;

	(void)(mqttclient_data);

	if (data->do_qos2_fail_once) {
		if (data->fail_once_state == 0 && RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
			RRR_MSG_0("Fail once on PUBLISH triggered per configuration in mqttclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
			data->fail_once_state++;
			return RRR_MQTT_SOFT_ERROR;
		}
		if (data->fail_once_state == 1 && RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREL) {
			RRR_MSG_0("Fail once on PUBREL triggered per configuration in mqttclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
			data->fail_once_state++;
			return RRR_MQTT_SOFT_ERROR;
		}
	}

	if ((RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBACK ||
		RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREC) &&
		RRR_MQTT_P_GET_REASON_V5(packet) != RRR_MQTT_P_5_REASON_OK
	) {
		const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5 (RRR_MQTT_P_GET_REASON_V5(packet));

		RRR_MSG_0("A PUBLISH was rejected by the broker in mqttclient instance %s with reason '%s'\n",
				INSTANCE_D_NAME(data->thread_data),
				(reason != NULL ? reason->description : "UNKNOWN")
		);
	}

	return RRR_MQTT_OK;
}

static int mqttclient_try_create_rrr_msg_msg_with_publish_data (
		struct rrr_msg_msg **result,
		struct rrr_mqtt_p_publish *publish,
		struct mqttclient_data *data
) {
	*result = NULL;

	int ret = 0;

	if (publish->payload == NULL || publish->payload->size == 0) {
		goto out;
	}

	uint16_t topic_len = rrr_u16_from_biglength_bug_const(strlen(publish->topic));

	if (rrr_msg_msg_new_empty (
			result,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			publish->create_time,
			topic_len,
			publish->payload->size
	) != 0) {
		RRR_MSG_0("Could not initialize message_final in receive_publish of MQTT client instance %s (A)\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	memcpy(MSG_TOPIC_PTR(*result), publish->topic, topic_len);
	memcpy(MSG_DATA_PTR(*result), publish->payload->payload_start, publish->payload->size);

	out:
	return ret;
}

static int mqttclient_try_get_rrr_msg_msg_from_publish (
		struct rrr_msg_msg **result,
		struct rrr_mqtt_p_publish *publish,
		struct mqttclient_data *data
) {
	int ret = 0;

	if (publish->payload == NULL) {
		goto out;
	}

	struct rrr_msg_msg *message = (struct rrr_msg_msg *) publish->payload->payload_start;
	const rrr_length message_actual_length = publish->payload->size;

	if (message_actual_length < sizeof(struct rrr_msg)) {
		RRR_DBG_1("RRR Message of unknown length %" PRIrrrl " in MQTT client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	*result = NULL;

	rrr_length message_stated_length = 0;
	if (rrr_msg_get_target_size_and_check_checksum (
			&message_stated_length,
			(struct rrr_msg *) message,
			message_actual_length)
	) {
		RRR_DBG_1("RRR Message of size %" PRIrrrl " with corrupted header in MQTT client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (message_actual_length != message_stated_length) {
		RRR_DBG_1("RRR message_final size mismatch, have %" PRIrrrl " bytes but packet states %" PRIrrrl " in MQTT client instance %s\n",
				message_actual_length, message_stated_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_head_to_host_and_verify((struct rrr_msg *) message, message_actual_length) != 0) {
		RRR_DBG_1("RRR Message with invalid header in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_check_data_checksum_and_length((struct rrr_msg *) message, message_actual_length) != 0) {
		RRR_MSG_0("RRR message_final CRC32 mismatch in MQTT client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify(message, message_actual_length) != 0) {
		RRR_MSG_0("RRR message_final was invalid in MQTT client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	*result = rrr_allocate(message_actual_length);
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory in mqttclient_try_get_rrr_msg_msg_from_publish\n");
		ret = 1;
		goto out;
	}
	memcpy(*result, message, message_actual_length);

	out:
	return ret;
}

struct try_create_array_message_from_publish_callback_data {
	const char *topic;
	uint16_t topic_length;
	struct rrr_msg_msg **result;
};

static int __mqttclient_try_create_array_message_from_publish_callback (
		struct rrr_array *array,
		void *arg
) {
	struct try_create_array_message_from_publish_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *message = NULL;
	if ((ret = rrr_array_new_message_from_array (
			&message,
			array,
			rrr_time_get_64(),
			callback_data->topic,
			callback_data->topic_length
	)) != 0) {
		RRR_MSG_0("Could not create message in __rrr_array_tree_new_message_from_buffer_callback_intermediate return was %i\n", ret);
		return 1;
	}

	*callback_data->result = message;

	return ret;
}

static int mqttclient_try_create_array_message_from_publish (
		struct rrr_msg_msg **result,
		rrr_length *parsed_bytes,
		struct rrr_mqtt_p_publish *publish,
		rrr_length read_pos,
		struct mqttclient_data *data
) {
	int ret = 0;

	*result = NULL;
	*parsed_bytes = 0;

	if (publish->payload == NULL) {
		goto out;
	}

	if (publish->payload->size == 0) {
		RRR_MSG_0("Received PUBLISH message had zero length in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (read_pos >= publish->payload->size) {
		ret = 0;
		goto out;
	}

	struct try_create_array_message_from_publish_callback_data callback_data = {
			publish->topic,
			rrr_u16_from_biglength_bug_const(strlen(publish->topic)),
			result
	};

	if ((ret = rrr_array_tree_import_from_buffer (
			parsed_bytes,
			publish->payload->payload_start + read_pos,
			publish->payload->size - read_pos,
			data->tree,
			__mqttclient_try_create_array_message_from_publish_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_ARRAY_SOFT_ERROR) {
			RRR_MSG_0("Could not parse data array from received PUBLISH message in MQTT client instance %s, invalid data of length %" PRIrrrl "\n",
					INSTANCE_D_NAME(data->thread_data), publish->payload->size);
			ret = 0;
		}
		else if (ret == RRR_ARRAY_PARSE_INCOMPLETE) {
			RRR_MSG_0("Could not parse data array from received PUBLISH message in MQTT client instance %s, message was too short\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 0;
		}
		else {
			RRR_MSG_0("Could not parse data array from received PUBLISH message in MQTT client instance %s, hard error\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
		}
		goto out;
	}

	out:
	return ret;
}

struct receive_publish_create_entry_callback_data {
	struct mqttclient_data *data;
	const struct rrr_msg_msg *message;
};

static int mqttclient_receive_publish_create_entry_callback (struct rrr_msg_holder *entry, void *arg) {
	struct receive_publish_create_entry_callback_data *data = arg;

	int ret = 0;

	size_t msg_size = MSG_TOTAL_SIZE(data->message);

	if ((entry->message = rrr_allocate(msg_size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in mqttclient_receive_publish_create_entry_callback\n");
		ret = 1;
		goto out;
	}

	// Data must be copied to have the write happening while the locks are held
	memcpy(entry->message, data->message, msg_size);
	entry->data_length = msg_size;

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int mqttclient_receive_publish_create_and_save_entry (const struct rrr_msg_msg *message, struct mqttclient_data *data) {
	int ret = 0;

	struct receive_publish_create_entry_callback_data callback_data = {
			data,
			message
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			mqttclient_receive_publish_create_entry_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Error while writing entry to output buffer in mqttclient_receive_publish_create_entry of MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

#define WRITE_TO_BUFFER_AND_SET_TO_NULL(message)                                                                               \
    if ((ret = mqttclient_receive_publish_create_and_save_entry(message, data)) != 0) {                                        \
        goto out;                                                                                                              \
    } RRR_FREE_IF_NOT_NULL(message)

static void mqttclient_receive_publish (struct rrr_mqtt_p_publish *publish, void *arg) {
	int ret = 0;

	struct mqttclient_data *data = arg;
	struct rrr_msg_msg *message_final = NULL;

	struct rrr_mqtt_property *property = NULL;
	const char *content_type = NULL;

	RRR_DBG_2 (">==| MQTT client %s: Receive PUBLISH payload length %" PRIrrrl " topic %s retain %u\n",
			INSTANCE_D_NAME(data->thread_data),
			(publish->payload != NULL ? publish->payload->size : 0),
			(publish->topic),
			RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(publish)
	);

	if ((property = rrr_mqtt_property_collection_get_property(&publish->properties, RRR_MQTT_PROPERTY_CONTENT_TYPE, 0)) != NULL) {
		rrr_length length = 0;
		content_type = rrr_mqtt_property_get_blob(property, &length);
		if (content_type[length] != '\0') {
			RRR_BUG("Content type was not zero-terminated in MQTT client receive_publish\n");
		}
	}

	// is_rrr_msg_msg is set to 1 if we want the data to be a message. It is set to zero
	// again if the data turns out not to be a message after all. If receive_rrr_message
	// is not set, data which is not auto-detected as message (V5 only) will be wrapped
	// inside a new rrr_msg_msg. If do_receive_rrr_message is set and the data is incorrect,
	// it will be dropped.
	int is_rrr_msg_msg = data->do_receive_rrr_message;
	int expecting_rrr_msg_msg = data->do_receive_rrr_message;

	if (content_type != NULL) {
		RRR_DBG_3 ("MQTT client %s: PUBLISH content type is '%s'\n",
				INSTANCE_D_NAME(data->thread_data), content_type);

		if (strcmp (content_type, RRR_MESSAGE_MIME_TYPE) == 0) {
			is_rrr_msg_msg = 1;
		}
	}

	// Try to extract a message from the data of the publish
	if (is_rrr_msg_msg != 0) {
		if ((ret = mqttclient_try_get_rrr_msg_msg_from_publish (
				&message_final,
				publish,
				data
		)) != 0) {
			RRR_MSG_0("Error while parsing RRR message in receive_publish of MQTT client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (message_final == NULL && expecting_rrr_msg_msg != 0) {
			RRR_MSG_0("Received supposed RRR message_final turned out not to be, dropping it in MQTT client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		else if (message_final != NULL) {
			if (data->do_receive_publish_topic) {
				if (rrr_msg_msg_topic_set (
						&message_final,
						publish->topic,
						rrr_u16_from_biglength_bug_const(strlen(publish->topic))
				)) {
					RRR_MSG_0("Could not set new topic of received RRR message in mqttclient instance %s\n",
							INSTANCE_D_NAME(data->thread_data));
					ret = 1;
					goto out;
				}
			}
			goto out_write_to_buffer;
		}
	}

	// Try to create an array message with the data from the publish (if specified in configuration)
	if (data->tree != NULL) {
		int count = 0;
		rrr_length read_pos = 0;
		do {
			rrr_length parsed_bytes = 0;
			if ((ret = mqttclient_try_create_array_message_from_publish (
					&message_final,
					&parsed_bytes,
					publish,
					read_pos,
					data
			)) != 0) {
				RRR_MSG_0("Error while parsing data array from received PUBLISH in MQTT client instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				break;
			}
			if (message_final == NULL) {
				if (count == 0) {
					RRR_MSG_0("Parsing of supposed received data array failed, dropping the data in MQTT client instance %s\n",
							INSTANCE_D_NAME(data->thread_data));
				}
				break;
			}
			read_pos += parsed_bytes;
			count++;
			WRITE_TO_BUFFER_AND_SET_TO_NULL(message_final);
		} while (1);

		RRR_DBG_2("MQTT client instance %s parsed %i array records from PUBLISH message\n",
				INSTANCE_D_NAME(data->thread_data), count);
		goto out;
	}

	// Try to create a message with the data being the data of the publish. This will return
	// NULL in message_final if there is no data in the publish message.
	if ((ret = mqttclient_try_create_rrr_msg_msg_with_publish_data (
			&message_final,
			publish,
			data
	)) != 0) {
		RRR_MSG_0("Error while creating RRR message from publish data in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}
	else if (message_final != NULL) {
		RRR_DBG_2("MQTT client instance %s created message from PUBLISH message payload\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out_write_to_buffer;
	}

	const uint16_t topic_length = rrr_u16_from_biglength_bug_const(strlen(publish->topic));

	// Try to create a message with the data being the topic of the publish
	if (rrr_msg_msg_new_with_data (
			&message_final,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			publish->create_time,
			// Add termination \0 only to data of message, not topic
			publish->topic,
			topic_length,
			publish->topic,
			(rrr_u32) topic_length + 1
	) != 0) {
		RRR_MSG_0("Could not initialize message_final in receive_publish of MQTT client instance %s (B)\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}
	else {
		RRR_DBG_2("MQTT client instance %s created message from PUBLISH message topic, which was '%s'\n",
				INSTANCE_D_NAME(data->thread_data), publish->topic);
	}

	out_write_to_buffer:
	WRITE_TO_BUFFER_AND_SET_TO_NULL(message_final);

	out:
	RRR_FREE_IF_NOT_NULL(message_final);
	if (ret != 0) {
		RRR_MSG_0("MQTT client instance %s stopping due to hard error during processing of received PUBLISH\n",
				INSTANCE_D_NAME(data->thread_data));
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
}

static int mqttclient_connect_check (struct mqttclient_data *data) {
	int alive = 0;
	int send_allowed = 0;
	int close_wait = 0;

	if (rrr_mqtt_client_connection_check_alive (
			&alive,
			&send_allowed,
			&close_wait,
			data->mqtt_client_data,
			data->transport_handle
	) != 0) {
		RRR_MSG_0("Error in MQTT client instance %s while checking for connection alive\n",
				INSTANCE_D_NAME(data->thread_data));
		return 1;
	}

	assert(data->prev_state_time > 0);

	if (rrr_time_get_64() - data->prev_state_time > RRR_MQTT_CONNACK_TIMEOUT_S * 1000 * 1000) {
		RRR_MSG_0("Timeout after %llu ms while waiting for CONNACK in MQTT client instance %s\n",
			(unsigned long long) (rrr_time_get_64() - data->prev_state_time) / 1000, INSTANCE_D_NAME(data->thread_data));
		mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT);
		return 0;
	}

	if (!alive) {
		RRR_MSG_0("Connection lost while waiting for CONNACK in MQTT client instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT);
		return 0;
	}

	if (send_allowed) {
		RRR_DBG_1("MQTT client instance %s startup send grace period %i ms started\n",
				INSTANCE_D_NAME(data->thread_data),
				RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS
		);
		mqttclient_state_set(data, MQTTCLIENT_STATE_SUBSCRIBE);
		return 0;
	}

	return 0;
}
		
static int mqttclient_wait_disconnect_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mqttclient_data *data = thread_data->private_data;

	if (rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(thread) != 0) {
		return RRR_MQTT_INTERNAL_ERROR;
	}

	int alive = 0;
	int send_allowed = 0;
	int close_wait = 0;

	if (rrr_mqtt_client_connection_check_alive (
			&alive,
			&send_allowed,
			&close_wait,
			data->mqtt_client_data,
			data->transport_handle
	) != 0) {
		RRR_MSG_0("Error in MQTT client instance %s while checking for close wait\n",
				INSTANCE_D_NAME(data->thread_data));
		return RRR_MQTT_INTERNAL_ERROR;
	}

	assert(0 && "Check disconnect time not implemented");

	uint64_t timeout = /* data->disconnect_time +*/ RRR_MQTT_DISCONNECT_TIMEOUT_S * 1000 * 1000;

	if (rrr_time_get_64() > timeout) {
		RRR_MSG_0("Timeout after %i seconds while waiting for disconnection in MQTT client instance %s\n",
			RRR_MQTT_DISCONNECT_TIMEOUT_S, INSTANCE_D_NAME(data->thread_data));
		return RRR_MQTT_SOFT_ERROR;
	}

	if (!alive && !close_wait) {
		return RRR_EVENT_EXIT;
	}

	return 0;
}
		
static void mqttclient_wait_disconnect (struct mqttclient_data *data) {
	rrr_event_function_periodic_set_and_dispatch (
			INSTANCE_D_EVENTS_H(data->thread_data),
			100 * 1000, // 100 ms
			mqttclient_wait_disconnect_event_periodic
	);
}

static int mqttclient_late_client_identifier_update (struct mqttclient_data *data) {
	int ret = RRR_MQTT_OK;

	struct rrr_mqtt_session_properties properties = {0};
	char *identifier_tmp = NULL;

	if (data->do_recycle_assigned_client_identifier == 0) {
		goto out;
	}

	// Identifier already set?
	if ((data->client_identifier != NULL && *(data->client_identifier) == '\0')) {
		goto out;
	}

	if ((ret = rrr_mqtt_client_get_session_properties (
			&properties,
			data->mqtt_client_data,
			data->transport_handle
	)) != 0) {
		RRR_MSG_0("Error while getting session properties in mqttclient_late_client_identifier_update of MQTT client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	if (properties.assigned_client_identifier == NULL) {
		// No assignment from server
		goto out;
	}

	if ((ret = rrr_mqtt_property_get_blob_as_str (
			&identifier_tmp,
			properties.assigned_client_identifier
	)) != 0) {
		RRR_MSG_0("Error while getting assigned name in mqttclient_late_client_identifier_update of MQTT client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	if ((ret = rrr_mqtt_client_late_set_client_identifier (
			data->mqtt_client_data,
			identifier_tmp
	)) != 0) {
		RRR_MSG_0("Error while setting client identifier in mqttclient_late_client_identifier_update of MQTT client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		goto out;
	}

	// Configuration struct for module is not updated

	out:
	RRR_FREE_IF_NOT_NULL(identifier_tmp);
	rrr_mqtt_session_properties_clear(&properties);
	return ret;
}

static void mqttclient_discard (struct mqttclient_data *data) {
	if (mqttclient_state_transition_timed (data, MQTTCLIENT_STATE_CONNECT, 100 /* 100 ms */)) {
		return;
	}
}

static int mqttclient_connect (struct mqttclient_data *data) {
	if (data->connect_attempt_count == 0) {
		// Do this to avoid connection build-up on persistent error conditions
		rrr_mqtt_client_close_all_connections(data->mqtt_client_data);
	}

	if (data->poll_discard_count > 0) {
		RRR_DBG_1("mqttclient instance %s discarded %" PRIu64 " messages from senders upon connect retry\n",
				INSTANCE_D_NAME(data->thread_data), data->poll_discard_count);
		data->poll_discard_count = 0;
	}

	data->transport_handle = 0;
	data->session = NULL;

	if (data->connect_attempt_count >= data->connect_attempts) {
		if (strcmp (data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) == 0) {
			RRR_MSG_0("MQTT client instance %s: %lu connection attempts failed, trying again.\n",
					INSTANCE_D_NAME(data->thread_data),
					(unsigned long) data->connect_attempts
			);

			if (data->do_discard_on_connect_retry) {
				mqttclient_state_set(data, MQTTCLIENT_STATE_DISCARD);
			}

			data->connect_attempt_count = 0;

			return 0;
		}

		RRR_MSG_0("Could not connect to mqtt server '%s' port '%u' in instance %s, restarting.\n",
				data->server,
				data->server_port,
				INSTANCE_D_NAME(data->thread_data)
		);

		return 1;
	}

	RRR_DBG_1("MQTT client instance %s attempting to connect to server '%s' port '%u' username '%s' client-ID '%s' attempt %lu/%lu\n",
			INSTANCE_D_NAME(data->thread_data),
			data->server,
			data->server_port,
			(data->username != NULL ? data->username : ""),
			(data->client_identifier != NULL ? data->client_identifier : ""),
			(unsigned long) data->connect_attempt_count,
			(unsigned long) data->connect_attempts
	);

	if (rrr_mqtt_client_connect (
			&data->transport_handle,
			&data->session,
			data->mqtt_client_data,
			data->server,
			data->server_port,
			(uint8_t) data->version,
			RRR_MQTT_CLIENT_KEEP_ALIVE,
			data->clean_start != 0,
			data->username,
			data->password,
			&data->connect_properties,
			data->will_topic,
			data->will_message,
			(uint8_t) data->will_qos,
			data->do_will_retain != 0
	) != 0) {
		RRR_MSG_0("Error from rrr_mqtt_client_connect in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		return 1;
	}

	mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT_CHECK);

	return 0;
}

static void mqttclient_update_stats (
		struct mqttclient_data *data
) {
	struct rrr_stats_instance *stats = INSTANCE_D_STATS(data->thread_data);

	if (stats->stats_handle == 0) {
		return;
	}

	struct rrr_mqtt_client_stats client_stats;
	rrr_mqtt_client_get_stats (&client_stats, data->mqtt_client_data);

	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_delivered", 0, client_stats.session_stats.total_publish_delivered);

	// This is difficult to count in the MQTT-framework as the same function is used to send packets
	// regardless of their origin. We therefore count it in the module poll callback function.
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_sent", 0, data->total_sent_count);

	// These will always be zero for the client, nothing is forwarded. Keep it here nevertheless to avoid accidently activating it.
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_forwarded_in", 0, client_stats.session_stats.total_publish_forwarded_in);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_forwarded_out", 0, client_stats.session_stats.total_publish_forwarded_out);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_received", 0, client_stats.session_stats.total_publish_received);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_not_forwarded", 0, client_stats.session_stats.total_publish_not_forwarded);
}

static int mqttclient_input_queue_process (
		struct mqttclient_data *data
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&data->input_queue, struct rrr_msg_holder);
		rrr_msg_holder_lock(node);
		if ((ret = mqttclient_process(data, node)) != 0) {
			RRR_MSG_0("Failed to process message in mqttclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			RRR_LL_ITERATE_LAST();
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		rrr_msg_holder_unlock(node);
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->input_queue, 0; rrr_msg_holder_decref(node));

	return ret;
}

static int mqttclient_poll_callback (RRR_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct mqttclient_data *data = thread_data->private_data;

	RRR_LL_PUSH(&data->input_queue, entry);
	rrr_msg_holder_incref_while_locked(entry);
	rrr_msg_holder_unlock(entry);

	if (mqttclient_state_check(data, MQTTCLIENT_STATE_DISCARD)) {
		data->poll_discard_count++;
		data->poll_discard_count += (rrr_length) RRR_LL_COUNT(&data->input_queue);
		rrr_msg_holder_collection_clear(&data->input_queue);
		return 0;
	}

	if (RRR_DEBUGLEVEL_2) {
		rrr_msg_holder_lock(entry);
		const struct rrr_msg_msg *reading = entry->message;
		RRR_DBG_2 ("MQTT client %s: Result from input queue: timestamp %" PRIu64 ", added to input queue\n",
				INSTANCE_D_NAME(data->thread_data), reading->timestamp);
		rrr_msg_holder_unlock(entry);
	}

	if (mqttclient_state_check(data, MQTTCLIENT_STATE_PROCESS)) {
		if (mqttclient_input_queue_process (data) != 0) {
			mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT);
		}
	}

	return 0;
}

static int mqttclient_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	return rrr_poll_do_poll_delete (amount, thread_data, mqttclient_poll_callback);
}

static void mqttclient_event_callback_pause (RRR_EVENT_FUNCTION_PAUSE_ARGS) {
	struct rrr_thread *thread = callback_arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mqttclient_data *data = thread_data->private_data;

	(void)(data);
	(void)(is_paused);
	(void)(do_pause);

	*do_pause = !mqttclient_state_check(data, MQTTCLIENT_STATE_PROCESS) || data->send_discouraged;
}

static int mqttclient_process_check (struct mqttclient_data *data) {
	int alive = 0;
	int send_allowed = 0;
	int close_wait = 0;

	int ret_tmp;
	if ((ret_tmp = rrr_mqtt_client_connection_check_alive (
			&alive,
			&send_allowed,
			&close_wait,
			data->mqtt_client_data,
			data->transport_handle
	)) != 0) {
		// Only returns OK or INTERNAL_ERROR
		RRR_MSG_0("Error in MQTT client instance %s while checking for connection alive return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret_tmp);
		return 1;
	}

	if (!alive) {
		RRR_MSG_0("Connection lost for MQTT client instance %s, reconnecting\n",
			INSTANCE_D_NAME(data->thread_data));
		mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT);
	}
	else {
		data->send_discouraged = 0;
	}

	return 0;
}

static int mqttclient_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mqttclient_data *data = thread_data->private_data;

	printf("Periodic state %i\n", data->state);

	switch (data->state) {
		case MQTTCLIENT_STATE_STARTUP_CONNECT_GRACE:
			mqttclient_state_transition_timed (data, MQTTCLIENT_STATE_CONNECT, RRR_MQTT_STARTUP_CONNECT_GRACE_TIME_MS);
			break;
		case MQTTCLIENT_STATE_DISCARD:
			mqttclient_discard (data);
			break;
		case MQTTCLIENT_STATE_CONNECT:
			if (mqttclient_connect (data) != 0) {
				return RRR_EVENT_ERR;
			}
			data->connect_attempt_count++;
			break;
		case MQTTCLIENT_STATE_CONNECT_CHECK:
			if (mqttclient_connect_check (data) != 0) {
				return RRR_EVENT_ERR;
			}
			break;
		case MQTTCLIENT_STATE_SUBSCRIBE:
			if (mqttclient_do_subscribe(data) != 0) {
				mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT);
			}
			else {
				mqttclient_state_set(data, MQTTCLIENT_STATE_STARTUP_SEND_GRACE);
			}
			break;
		case MQTTCLIENT_STATE_STARTUP_SEND_GRACE:
			mqttclient_state_transition_timed (data, MQTTCLIENT_STATE_PROCESS, RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS);
			break;
		case MQTTCLIENT_STATE_PROCESS:
			// Successive connect attempts or re-connect does not require clean start to be set. Server
			// will respond with CONNACK with session present=0 if we need to clean up our state.
			data->clean_start = 0;
			data->connect_attempt_count = 0;

			if (mqttclient_process_check (data) != 0) {
				return RRR_EVENT_ERR;
			}

			if (mqttclient_input_queue_process (data) != 0) {
				mqttclient_state_set(data, MQTTCLIENT_STATE_CONNECT);
			}

			break;
		case MQTTCLIENT_STATE_DISCONNECT:
			assert(0 && "State disconnect not implemented");
		default:
			assert(0 && "State not implemented");
	};

	// TODO : Periodic stats every second
	//mqttclient_update_stats(data);

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(thread);

//	reconnect:

//	data->send_disabled = 1;
//	data->connect_time = 0;
//	data->disconnect_time = 0;

//	if (mqttclient_connect_loop(data, clean_start) != RRR_MQTT_OK) {
//		goto out_destroy_client;
//	}


	assert(0 && "Subscribe not implemented");


	assert(0 && "Client identifier update not implemented");

//	if ((ret_tmp = mqttclient_late_client_identifier_update(data)) != RRR_MQTT_OK) {
//		if (ret_tmp & RRR_MQTT_INTERNAL_ERROR) {
//			goto out_destroy_client;
//		}
//		goto reconnect;
//	}


//	data->send_disabled = 0;
//	if (ret_tmp != 0 || rrr_thread_signal_encourage_stop_check(thread)) {
//		goto out_destroy_client;
//	}


//	goto reconnect;
}

int mqttclient_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mqttclient_data *data = thread_data->private_data = thread_data->private_memory;

	int init_ret = 0;
	if ((init_ret = mqttclient_data_init(data, thread_data)) != 0) {
		RRR_MSG_0("Could not initialize data in MQTT client instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		goto out_message;
	}

	RRR_DBG_1 ("MQTT client instance %s thread %p, disabling processing of input queue until connection with broker is established.\n",
			INSTANCE_D_NAME(thread_data), thread);

	rrr_thread_start_condition_helper_nofork(thread);

	if (mqttclient_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for MQTT client instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_cleanup;
	}

	RRR_DBG_1 ("MQTT instance %s using '%s' as client identifier\n",
			INSTANCE_D_NAME(thread_data), (data->client_identifier != NULL ? data->client_identifier : "(auto)"));

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

//	event_enable_debug_logging(EVENT_DBG_ALL);

	struct rrr_mqtt_common_init_data init_data = {
		data->client_identifier, // May be NULL
		RRR_MQTT_COMMON_RETRY_INTERVAL_S * 1000 * 1000,
		RRR_MQTT_COMMON_CLOSE_WAIT_TIME_S * 1000 * 1000,
		RRR_MQTT_COMMON_MAX_CONNECTIONS
	};

	if (rrr_mqtt_client_new (
			&data->mqtt_client_data,
			&init_data,
			INSTANCE_D_EVENTS(thread_data),
			rrr_mqtt_session_collection_ram_new_client,
			NULL,
			mqttclient_process_suback_unsuback,
			data,
			mqttclient_process_parsed_packet,
			data,
			mqttclient_receive_publish,
			data
	) != 0) {
		RRR_MSG_0("Could not create new MQTT client\n");
		goto out_cleanup;
	}

	RRR_DBG_1 ("MQTT client started thread %p\n", thread_data);

	if (rrr_mqtt_property_collection_add_uint32 (
			&data->connect_properties,
			RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM,
			0xffff
	) != 0) {
		RRR_MSG_0("Could not set CONNECT properties in MQTT client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	if (rrr_mqtt_client_start (
			data->mqtt_client_data,
			&data->net_transport_config
	) != 0) {
		RRR_MSG_0("Could not start transport in MQTT client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	// We have do use clean start the first time we connect as the server
	// might remember packets from our last session (if any)
	data->clean_start = 1;

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS_H(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			mqttclient_event_callback_pause,
			thread
	);

	mqttclient_state_init(data, MQTTCLIENT_STATE_STARTUP_CONNECT_GRACE);

	if (rrr_event_function_periodic_set (
			INSTANCE_D_EVENTS_H(thread_data),
			100 * 1000, // 100 ms
			mqttclient_event_periodic
	) != 0) {
		RRR_MSG_0("Failed to set periodic function in mqttclient instance %s\n",
			INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	return 0;

	out_destroy_client:
		rrr_mqtt_client_destroy(data->mqtt_client_data);
	out_cleanup:
		mqttclient_data_cleanup(data);
	out_message:
		return 1;
}

void mqttclient_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mqttclient_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(strike);

	RRR_DBG_1 ("MQTT client %p instance %s exiting\n",
		thread, INSTANCE_D_NAME(thread_data));

	assert(0 && "Nice shutdown not implemented");
//	mqttclient_wait_disconnect (data);

	rrr_mqtt_client_destroy(data->mqtt_client_data);
	mqttclient_data_cleanup(data);

	*deinit_complete = 1;
}

struct rrr_instance_event_functions event_functions = {
	mqttclient_event_broker_data_available
};

static const char *module_name = "mqtt_client";

void load (struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->event_functions = event_functions;
	data->init = mqttclient_init;
	data->deinit = mqttclient_deinit;
}

void unload (void) {
	RRR_DBG_1 ("Destroy MQTT client module\n");
}

