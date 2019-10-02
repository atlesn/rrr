/*

Read Route Record

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "../lib/mqtt_topic.h"
#include "../lib/mqtt_client.h"
#include "../lib/mqtt_common.h"
#include "../lib/mqtt_session_ram.h"
#include "../lib/mqtt_subscription.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/ip.h"
#include "../lib/rrr_socket.h"
#include "../lib/utf8.h"
#include "../lib/linked_list.h"
#include "../global.h"

#define RRR_MQTT_DEFAULT_SERVER_PORT 1883
#define RRR_MQTT_DEFAULT_QOS 1
#define RRR_MQTT_DEFAULT_VERSION 4 // 3.1.1

struct mqtt_client_data {
	struct instance_thread_data *thread_data;
	struct fifo_buffer output_buffer;
	struct rrr_mqtt_client_data *mqtt_client_data;
	rrr_setting_uint server_port;
	struct rrr_mqtt_subscription_collection *subscriptions;
	struct rrr_mqtt_property_collection connect_properties;
	char *server;
	char *publish_topic;
	char *version_str;
	char *client_identifier;
	uint8_t qos;
	uint8_t version;
	int publish_vl_message;
	int receive_vl_message;
	struct rrr_mqtt_conn *connection;
};

static void data_cleanup(void *arg) {
	struct mqtt_client_data *data = arg;
	fifo_buffer_invalidate(&data->output_buffer);
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->publish_topic);
	RRR_FREE_IF_NOT_NULL(data->version_str);
	RRR_FREE_IF_NOT_NULL(data->client_identifier);
	rrr_mqtt_subscription_collection_destroy(data->subscriptions);
	rrr_mqtt_property_collection_destroy(&data->connect_properties);
}

static int data_init (
		struct mqtt_client_data *data,
		struct instance_thread_data *thread_data
) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;

	data->thread_data = thread_data;

	ret |= fifo_buffer_init(&data->output_buffer);

	if (ret != 0) {
		VL_MSG_ERR("Could not initialize fifo buffer in mqtt client data_init\n");
		goto out;
	}

	if (rrr_mqtt_subscription_collection_new(&data->subscriptions) != 0) {
		VL_MSG_ERR("Could not create subscription collection in mqtt client data_init\n");
		goto out;
	}

	out:
	if (ret != 0) {
		data_cleanup(data);
	}

	return ret;
}

static int parse_sub_topic (const char *topic_str, void *arg) {
	struct mqtt_client_data *data = arg;

	if (rrr_mqtt_topic_filter_validate_name(topic_str) != 0) {
		return 1;
	}

	if (rrr_mqtt_subscription_collection_push_unique_str (
			data->subscriptions,
			topic_str,
			0,
			0,
			0,
			data->qos
	) != 0) {
		VL_MSG_ERR("Could not add topic '%s' to subscription collection\n", topic_str);
		return 1;
	}

	return 0;
}

// TODO : Provide more configuration arguments
static int parse_config (struct mqtt_client_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	int yesno = 0;

	rrr_setting_uint mqtt_port = 0;
	rrr_setting_uint mqtt_qos = 0;

	if ((ret = rrr_instance_config_read_unsigned_integer(&mqtt_port, config, "mqtt_server_port")) == 0) {
		// OK
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		VL_MSG_ERR("Error while parsing mqtt_server_port setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		mqtt_port = RRR_MQTT_DEFAULT_SERVER_PORT;
		ret = 0;
	}
	data->server_port = mqtt_port;

	if ((ret = rrr_instance_config_read_unsigned_integer(&mqtt_qos, config, "mqtt_qos")) == 0) {
		if (mqtt_qos > 2) {
			VL_MSG_ERR("Setting mqtt_qos was >2 in config of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		VL_MSG_ERR("Error while parsing mqtt_qos setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		mqtt_qos = RRR_MQTT_DEFAULT_QOS;
		ret = 0;
	}
	data->qos = (uint8_t) mqtt_qos;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->client_identifier, config, "mqtt_client_identifier")) != 0) {
		data->client_identifier = malloc(strlen(config->name) + 1);
		if (data->client_identifier == NULL) {
			VL_MSG_ERR("Could not allocate memory in parse_config of instance %s\n", config->name);
		}
		strcpy(data->client_identifier, config->name);
	}

	if (rrr_utf8_validate(data->client_identifier, strlen(data->client_identifier)) != 0) {
		VL_MSG_ERR("Client identifier of mqtt client instance %s was not valid UTF-8\n", config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->version_str, config, "mqtt_version")) != 0) {
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
			VL_MSG_ERR("Unknown protocol version '%s' in setting mqtt_version of instance %s. " \
					"Supported values are 3.1.1 and 5\n", data->version_str, config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_instance_config_get_string_noconvert(&data->server, config, "mqtt_server")) != 0) {
		VL_MSG_ERR("Error while parsing mqtt_server setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if ((ret = (rrr_instance_config_check_yesno(&yesno, config, "mqtt_publish_rrr_message")
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Could not interpret mqtt_publish_rrr_message setting of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (yesno != 0) {
		data->publish_vl_message = 1;
	}

	if ((ret = (rrr_instance_config_check_yesno(&yesno, config, "mqtt_receive_rrr_message")
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Could not interpret mqtt_receive_rrr_message setting of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (yesno != 0) {
		data->receive_vl_message = 1;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->publish_topic, config, "mqtt_publish_topic")) == 0) {
		if (strlen(data->publish_topic) == 0) {
			VL_MSG_ERR("Topic name in mqtt_publish_topic was empty for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_mqtt_topic_validate_name(data->publish_topic) != 0) {
			VL_MSG_ERR("Topic name in mqtt_publish_topic was invalid for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_instance_config_traverse_split_commas_silent_fail(config, "mqtt_subscribe_topics", parse_sub_topic, data)) != 0) {
		VL_MSG_ERR("Error while parsing mqtt_subscribe_topics setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct mqtt_client_data *client_data = data->private_data;
	return fifo_read_clear_forward(&client_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

static int poll_keep (RRR_MODULE_POLL_SIGNATURE) {
	struct mqtt_client_data *client_data = data->private_data;
	return fifo_search(&client_data->output_buffer, callback, poll_data, wait_milliseconds);
}

static int process_suback_subscription (
		struct mqtt_client_data *data,
		struct rrr_mqtt_subscription *subscription,
		const int i,
		const uint8_t qos_or_reason_v5
) {
	int ret = 0;

	if (qos_or_reason_v5 > 2) {
		const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(qos_or_reason_v5);
		if (reason == NULL) {
			VL_MSG_ERR("Unknown reason 0x%02x from mqtt broker in SUBACK topic index %i in mqtt client instance %s",
					qos_or_reason_v5, i, INSTANCE_D_NAME(data->thread_data));
			return 1;
		}
		VL_MSG_ERR("Warning: Subscription '%s' index '%i' rejected from broker in mqtt client instance %s with reason '%s'\n",
				subscription->topic_filter,
				i,
				INSTANCE_D_NAME(data->thread_data),
				reason->description
		);
	}
	else if (qos_or_reason_v5 < subscription->qos_or_reason_v5) {
		VL_MSG_ERR("Warning: Subscription '%s' index '%i' assigned QoS %u from server while %u was requested in mqtt client instance %s \n",
				subscription->topic_filter,
				i,
				qos_or_reason_v5,
				subscription->qos_or_reason_v5,
				INSTANCE_D_NAME(data->thread_data)
		);
	}

	return ret;
}

static int process_suback(struct rrr_mqtt_client_data *mqtt_client_data, struct rrr_mqtt_p *packet, void *arg) {
	struct mqtt_client_data *data = arg;

	(void)(mqtt_client_data);

	if (RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_SUBACK) {
		VL_BUG("Unknown packet of type %u received in mqtt client process_suback\n",
				RRR_MQTT_P_GET_TYPE(packet));
	}

	struct rrr_mqtt_p_suback *suback = (struct rrr_mqtt_p_suback *) packet;

	int orig_count = rrr_mqtt_subscription_collection_count(data->subscriptions);
	int new_count = suback->acknowledgements_size;

	if (orig_count != new_count) {
		// Session framework should catch this
		VL_BUG("Count mismatch in SUBSCRIBE and SUBACK messages in mqtt client instance %s (%i vs %i)\n",
				INSTANCE_D_NAME(data->thread_data), orig_count, new_count);
	}

	for (int i = 0; i < new_count; i++) {
		struct rrr_mqtt_subscription *subscription;
		subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx (
				data->subscriptions,
				i
		);
		if (process_suback_subscription(data, subscription, i, suback->acknowledgements[i]) != 0) {
			return 1;
		}
	}

	return 0;
}

static int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct mqtt_client_data *private_data = thread_data->private_data;
	struct rrr_mqtt_p_publish *publish = NULL;
	struct vl_message *reading = (struct vl_message *) data;

	(void)(size);

	char *payload = NULL;
	ssize_t payload_size = 0;
	int ret = 0;

	VL_DEBUG_MSG_2 ("mqtt client %s: Result from buffer: measurement %" PRIu64 " size %lu, creating PUBLISH\n",
			INSTANCE_D_NAME(thread_data), reading->data_numeric, size);

	if (private_data->mqtt_client_data->protocol_version == NULL) {
		VL_MSG_ERR("Protocol version not yet set in mqtt client instance %s poll_callback while sending PUBLISH\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	publish = (struct rrr_mqtt_p_publish *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBLISH, private_data->mqtt_client_data->protocol_version);
	if (publish == NULL) {
		VL_MSG_ERR("Could not allocate PUBLISH in poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->payload);
	publish->payload = NULL;

	RRR_FREE_IF_NOT_NULL(publish->topic);

	if (MSG_TOPIC_LENGTH(reading) > 0) {
		publish->topic = malloc (MSG_TOPIC_LENGTH(reading) + 1);
		if (publish->topic != NULL) {
			memcpy (publish->topic, MSG_TOPIC_PTR(reading), MSG_TOPIC_LENGTH(reading));
			*(publish->topic + MSG_TOPIC_LENGTH(reading)) = '\0';
		}
	}
	else if (private_data->publish_topic != NULL) {
		publish->topic = strdup(private_data->publish_topic);
	}
	else {
		VL_MSG_ERR("Warning: Received message to MQTT client instance %s did not have topic set, and no default topic was defined in the configuration. Dropping message.\n",
				INSTANCE_D_NAME(thread_data));
		ret = 0;
		goto out_free;
	}

	if (publish->topic == NULL) {
		VL_MSG_ERR("Could not allocate topic in mqtt client poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	publish->qos = private_data->qos;

	if (private_data->publish_vl_message != 0) {
		ssize_t network_size = MSG_TOTAL_SIZE(reading);

		reading->network_size = network_size;

		message_prepare_for_network(reading);

		rrr_socket_msg_checksum_and_to_network_endian((struct rrr_socket_msg *) reading);

		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&publish->properties,
				RRR_MQTT_PROPERTY_CONTENT_TYPE,
				RRR_MESSAGE_MIME_TYPE,
				strlen(RRR_MESSAGE_MIME_TYPE)
		) != 0) {
			VL_MSG_ERR("Could not set content-type of publish in mqtt client poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}
		payload = data;
		payload_size = network_size;
		data = NULL;
	}
	else if (MSG_DATA_LENGTH(reading) > 0) {
		payload = malloc(MSG_DATA_LENGTH(reading));
		if (payload == NULL) {
			VL_MSG_ERR("could not allocate memory for PUBLISH payload A in mqtt client poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}
		payload_size = MSG_DATA_LENGTH(reading);
		memcpy(payload, MSG_DATA_PTR(reading), MSG_DATA_LENGTH(reading));
	}
	else {
		if ((ret = message_to_string(&payload, reading)) != 0) {
			VL_MSG_ERR("could not convert message to string for PUBLISH payload in mqtt client poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			goto out_free;
		}
		payload_size = strlen(payload) + 1;
	}

	if (payload != NULL) {
		if (rrr_mqtt_p_payload_new_with_allocated_payload(&publish->payload, payload, payload, payload_size) != 0) {
			VL_MSG_ERR("Could not set payload of PUBLISH in mqtt client poll_callback of mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}
		payload = NULL;
	}

	if (rrr_mqtt_client_publish(private_data->mqtt_client_data, private_data->connection, publish) != 0) {
		VL_MSG_ERR("Could not publish message in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	out_free:
	RRR_FREE_IF_NOT_NULL(data);
	RRR_FREE_IF_NOT_NULL(payload);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish);

	return ret;
}

static int __try_create_vl_message_with_publish_data (
		struct vl_message **result,
		struct rrr_mqtt_p_publish *publish,
		struct mqtt_client_data *data
) {
	*result = NULL;

	int ret = 0;

	if (publish->payload == NULL) {
		goto out;
	}

	RRR_MQTT_P_LOCK(publish->payload);

	if (publish->payload->length == 0) {
		goto out_unlock_payload;
	}

	ssize_t topic_len = strlen(publish->topic);

	if (message_new_empty (
			result,
			MSG_TYPE_MSG,
			0,
			MSG_CLASS_POINT,
			publish->create_time,
			publish->create_time,
			0,
			topic_len,
			publish->payload->length
	) != 0) {
		VL_MSG_ERR("Could not initialize message_final in receive_publish of mqtt client instance %s (A)\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out_unlock_payload;
	}

	memcpy(MSG_TOPIC_PTR(*result), publish->topic, topic_len);
	memcpy(MSG_DATA_PTR(*result), publish->payload->payload_start, publish->payload->length);

	out_unlock_payload:
	RRR_MQTT_P_UNLOCK(publish->payload);

	out:
	return ret;
}

static int __try_get_vl_message_from_publish (
		struct vl_message **result,
		struct rrr_mqtt_p_publish *publish,
		struct mqtt_client_data *data
) {
	int ret = 0;

	if (publish->payload == NULL) {
		goto out_nolock;
	}

	ssize_t message_actual_length = publish->payload->length;
	ssize_t message_stated_length = 0;
	struct vl_message *message = (struct vl_message *) publish->payload->payload_start;

	*result = NULL;

	RRR_MQTT_P_LOCK(publish->payload);

	if (message_actual_length < (ssize_t) sizeof(struct rrr_socket_msg)) {
		VL_DEBUG_MSG_1("RRR Message of unknown length %li in mqtt client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_socket_msg_get_target_size_and_check_checksum (
			&message_stated_length,
			(struct rrr_socket_msg *) message,
			message_actual_length)
	) {
		VL_DEBUG_MSG_1("RRR Message of size %li with corrupted header in mqtt client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (message_actual_length != message_stated_length) {
		VL_DEBUG_MSG_1("RRR message_final size mismatch, have %li bytes but packet states %li in mqtt client instance %s\n",
				message_actual_length, message_stated_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_socket_msg_head_to_host_and_verify((struct rrr_socket_msg *) message, message_actual_length) != 0) {
		VL_DEBUG_MSG_1("RRR Message with invalid header in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_socket_msg_check_data_checksum_and_length((struct rrr_socket_msg *) message, message_actual_length) != 0) {
		VL_MSG_ERR("RRR message_final CRC32 mismatch in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (message_to_host_and_verify(message, message_actual_length) != 0) {
		VL_MSG_ERR("RRR message_final was invalid in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	*result = malloc(message_actual_length);
	if (*result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __try_get_vl_message_from_publish\n");
		ret = 1;
		goto out;
	}
	memcpy(*result, message, message_actual_length);

	out:
	RRR_MQTT_P_UNLOCK(publish->payload);

	out_nolock:
	return ret;
}

static int receive_publish (struct rrr_mqtt_p_publish *publish, void *arg) {
	int ret = 0;

	struct mqtt_client_data *data = arg;
	struct vl_message *message_final = NULL;

	struct rrr_mqtt_property *property = NULL;
	const char *content_type = NULL;

	VL_DEBUG_MSG_2 ("mqtt client %s: Receive PUBLISH payload length %li\n",
			INSTANCE_D_NAME(data->thread_data), publish->payload->length);

	if ((property = rrr_mqtt_property_collection_get_property(&publish->properties, RRR_MQTT_PROPERTY_CONTENT_TYPE, 0)) != NULL) {
		ssize_t length = 0;
		content_type = rrr_mqtt_property_get_blob(property, &length);
		if (content_type[length] != '\0') {
			VL_BUG("Content type was not zero-terminated in mqtt client receive_publish\n");
		}
	}

	// is_vl_message is set to 1 if we want the data to be a message. It is set to zero
	// again if the data turns out not to be a message after all. If receive_vl_message
	// is not set, data which is not auto-detected as message (V5 only) will be wrapped
	// inside a new vl_message. If receive_vl_message is set and the data is incorrect,
	// it will be dropped.
	int is_vl_message = data->receive_vl_message;
	int expecting_vl_message = data->receive_vl_message;

	if (content_type != NULL && strcmp (content_type, RRR_MESSAGE_MIME_TYPE) == 0) {
		is_vl_message = 1;
	}

	// Try to extract a message from the data of the publish
	if (is_vl_message != 0) {
		if ((ret = __try_get_vl_message_from_publish (
				&message_final,
				publish,
				data
		)) != 0) {
			VL_MSG_ERR("Error while parsing RRR message in receive_publish of mqtt client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (message_final == NULL && expecting_vl_message != 0) {
			VL_MSG_ERR("Received supposed RRR message_final turned out not to be, dropping it in mqtt client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		else if (message_final != NULL) {
			goto out_write_to_buffer;
		}
	}

	// Try to create a message with the data being the data of the publish
	if ((ret = __try_create_vl_message_with_publish_data (
			&message_final,
			publish,
			data
	)) != 0) {
		VL_MSG_ERR("Error while creating RRR message from publish data in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}
	else if (message_final != NULL) {
		goto out_write_to_buffer;
	}

	// Try to create a message with the data being the topic of the publish
	if (message_new_with_data (
			&message_final,
			MSG_TYPE_MSG,
			0,
			MSG_CLASS_POINT,
			publish->create_time,
			publish->create_time,
			0,
			publish->topic,
			strlen(publish->topic) + 1,
			publish->topic,
			strlen(publish->topic) + 1
	) != 0) {
		VL_MSG_ERR("Could not initialize message_final in receive_publish of mqtt client instance %s (B)\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

 	out_write_to_buffer:
 	fifo_buffer_write(&data->output_buffer, (char*) message_final, sizeof(*message_final));
 	message_final = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message_final);
	return ret;
}

static void *thread_entry_mqtt_client (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct mqtt_client_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	int init_ret = 0;
	if ((init_ret = data_init(data, thread_data)) != 0) {
		VL_MSG_ERR("Could not initalize data in mqtt client instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("mqtt client thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parse failed for mqtt client instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	struct rrr_mqtt_common_init_data init_data = {
		INSTANCE_D_NAME(thread_data),
		RRR_MQTT_COMMON_RETRY_INTERVAL,
		RRR_MQTT_COMMON_CLOSE_WAIT_TIME,
		RRR_MQTT_COMMON_MAX_CONNECTIONS
	};

	if (rrr_mqtt_client_new (
			&data->mqtt_client_data,
			&init_data,
			rrr_mqtt_session_collection_ram_new,
			NULL,
			process_suback,
			data
		) != 0) {
		VL_MSG_ERR("Could not create new mqtt client\n");
		goto out_message;
	}

	pthread_cleanup_push(rrr_mqtt_client_destroy_void, data->mqtt_client_data);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE);

	if (poll_collection_count(&poll) == 0) {
		if (data->publish_topic != NULL) {
			VL_MSG_ERR("Warning: mqtt client instance %s has publish topic set but there are not senders specified in configuration\n",
					INSTANCE_D_NAME(thread_data));
		}
	}

	VL_DEBUG_MSG_1 ("mqtt client started thread %p\n", thread_data);

	if (rrr_mqtt_property_collection_add_uint32(
			&data->connect_properties,
			RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM,
			0xffff
	) != 0) {
		VL_MSG_ERR("Could not set CONNECT properties in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	reconnect:
	for (int i = 20; i >= 0 && thread_check_encourage_stop(thread_data->thread) != 1; i--) {
		VL_DEBUG_MSG_1("MQTT client instance %s attempting to connect to server '%s' port '%llu'\n",
				INSTANCE_D_NAME(thread_data), data->server, data->server_port);
		if (rrr_mqtt_client_connect (
				&data->connection,
				data->mqtt_client_data,
				data->server,
				data->server_port,
				data->version,
				RRR_MQTT_CLIENT_KEEP_ALIVE,
				0, // <-- Clean start
				&data->connect_properties
		) != 0) {
			if (i == 0) {
				VL_MSG_ERR("Could not connect to mqtt server '%s' port %llu in instance %s\n",
						data->server, data->server_port, INSTANCE_D_NAME(thread_data));
				goto out_destroy_client;
			}
			usleep (100000);
		}
		else {
			break;
		}
	}

	int subscriptions_sent = 0;
	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		// TODO : Figure out what to do with data from local senders

		int alive = 0;
		int send_allowed = 0;
		if (rrr_mqtt_client_connection_check_alive(&alive, &send_allowed, data->mqtt_client_data, data->connection)) {
			VL_MSG_ERR("Error in mqtt client instance %s while checking for connection alive\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		if (alive == 0) {
			VL_DEBUG_MSG_1("Connection lost for mqtt client instance %s, reconnecting\n",
					INSTANCE_D_NAME(thread_data));
			goto reconnect;
		}

		if (send_allowed != 0) {
			if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
				break;
			}

			if (subscriptions_sent == 0) {
				if (rrr_mqtt_client_subscribe (
						data->mqtt_client_data,
						data->connection,
						data->subscriptions
				) != 0) {
					VL_MSG_ERR("Could not subscribe to topics in mqtt client instance %s\n",
							INSTANCE_D_NAME(thread_data));
					goto reconnect;
				}
				subscriptions_sent = 1;
			}
		}

		if (rrr_mqtt_client_synchronized_tick(data->mqtt_client_data) != 0) {
			VL_MSG_ERR("Error int mqtt client instance %s while running tasks\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		if (rrr_mqtt_client_iterate_and_clear_local_delivery(data->mqtt_client_data, receive_publish, data) != 0) {
			VL_MSG_ERR("Error while iterating local delivery queue in mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		usleep (5000); // 50 ms
	}

	out_destroy_client:
		pthread_cleanup_pop(1);
	out_message:
		VL_DEBUG_MSG_1 ("Thread mqtt client %p exiting\n", thread_data->thread);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_exit(0);
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_mqtt_client,
		NULL,
		poll_keep,
		NULL,
		poll_delete,
		NULL,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "mqtt_client";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = VL_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy mqtt client module\n");
}

