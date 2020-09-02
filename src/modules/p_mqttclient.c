/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "../lib/mqtt/mqtt_topic.h"
#include "../lib/mqtt/mqtt_client.h"
#include "../lib/mqtt/mqtt_common.h"
#include "../lib/mqtt/mqtt_session.h"
#include "../lib/mqtt/mqtt_subscription.h"
#include "../lib/mqtt/mqtt_packet.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_broker.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/map.h"
#include "../lib/array.h"
#include "../lib/array_tree.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/net_transport/net_transport_config.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/gnu.h"
#include "../lib/util/utf8.h"
#include "../lib/util/linked_list.h"

//#define RRR_MQTT_FREEZE_TEST_ENABLE
//#define RRR_BENCHMARK_ENABLE
#include "../lib/benchmark.h"

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
#define RRR_MQTT_CLIENT_INCOMPLETE_PUBLISH_QOS_LIMIT 500

// Hard limit to stop before things go really wrong
#define RRR_MQTT_CLIENT_TO_REMOTE_BUFFER_LIMIT 2000

#define RRR_MQTT_CONNECT_ERROR_DO_RESTART	"restart"
#define RRR_MQTT_CONNECT_ERROR_DO_RETRY		"retry"

// Timeout before we send PUBLISH packets to the broker. This is to allow,
// if the broker has just been started, other clients to subscribe first
// before we send anything (to prevent it from getting deleted by the broker)
#define RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS 1000

// Timeout before we re-send or give up waiting for SUBACK
#define RRR_MQTT_SUBACK_RESEND_TIMEOUT_MS 1000
#define RRR_MQTT_SUBACK_RESEND_MAX 5

// TODO : Clean this up

struct rrr_mqtt_session;
struct rrr_array_tree;

struct mqtt_client_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_fifo_buffer output_buffer;
	struct rrr_mqtt_client_data *mqtt_client_data;
	int transport_handle;
	struct rrr_mqtt_session *session;
	rrr_setting_uint server_port;
	struct rrr_mqtt_subscription_collection *requested_subscriptions;
	struct rrr_mqtt_property_collection connect_properties;

	char *server;
	char *publish_topic;
	char *version_str;
	char *client_identifier;
	char *publish_values_from_array;
	struct rrr_map publish_values_from_array_list;
	struct rrr_array_tree *tree;

	rrr_setting_uint qos;
	rrr_setting_uint version;

	int do_prepend_publish_topic;
	int do_force_publish_topic;
	int do_publish_rrr_message;
	int do_receive_rrr_message;
	int do_debug_unsubscribe_cycle;
	int do_recycle_assigned_client_identifier;
	int do_discard_on_connect_retry;

	char *connect_error_action;
	rrr_setting_uint connect_attempts;

	unsigned int received_suback_packet_id;
	unsigned int received_unsuback_packet_id;
	uint64_t total_sent_count;
	uint64_t total_usleep_count;
	uint64_t total_ticks_count;
	uint64_t total_discarded_count;
	char *username;
	char *password;

	struct rrr_net_transport_config net_transport_config;
};

static void mqttclient_data_cleanup(void *arg) {
	struct mqtt_client_data *data = arg;
	rrr_fifo_buffer_clear(&data->output_buffer);
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->publish_topic);
	RRR_FREE_IF_NOT_NULL(data->version_str);
	RRR_FREE_IF_NOT_NULL(data->client_identifier);
	RRR_FREE_IF_NOT_NULL(data->publish_values_from_array);
	RRR_FREE_IF_NOT_NULL(data->connect_error_action);
	RRR_FREE_IF_NOT_NULL(data->username);
	RRR_FREE_IF_NOT_NULL(data->password);
	rrr_map_clear(&data->publish_values_from_array_list);
	rrr_mqtt_subscription_collection_destroy(data->requested_subscriptions);
	rrr_mqtt_property_collection_clear(&data->connect_properties);
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}
	rrr_net_transport_config_cleanup(&data->net_transport_config);
}

static int mqttclient_data_init (
		struct mqtt_client_data *data,
		struct rrr_instance_runtime_data *thread_data
) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;

	data->thread_data = thread_data;

	if ((ret = rrr_fifo_buffer_init(&data->output_buffer)) != 0) {
		RRR_MSG_0("Could not initialize fifo buffer in mqtt client mqttclient_data_init\n");
		goto out;
	}

	if (rrr_mqtt_subscription_collection_new(&data->requested_subscriptions) != 0) {
		RRR_MSG_0("Could not create subscription collection in mqtt client mqttclient_data_init\n");
		goto out_destroy_fifo_buffer;
	}

	goto out;
//	out_destroy_subscription_collection:
//		rrr_mqtt_subscription_collection_destroy(&data->requested_subscriptions);
	out_destroy_fifo_buffer:
		rrr_fifo_buffer_clear(&data->output_buffer);
		rrr_fifo_buffer_destroy(&data->output_buffer);
	out:
		return ret;
}

static int mqttclient_parse_sub_topic (const char *topic_str, void *arg) {
	struct mqtt_client_data *data = arg;

	if (rrr_mqtt_topic_filter_validate_name(topic_str) != 0) {
		return 1;
	}

	if (rrr_mqtt_subscription_collection_push_unique_str (
			data->requested_subscriptions,
			topic_str,
			0,
			0,
			0,
			data->qos
	) != 0) {
		RRR_MSG_0("Could not add topic '%s' to subscription collection\n", topic_str);
		return 1;
	}

	return 0;
}

static int mqttclient_parse_publish_value_tag (const char *value, void *arg) {
	struct mqtt_client_data *data = arg;

	int ret = 0;

	struct rrr_map_item *node = malloc(sizeof(*node));
	if (node == NULL) {
		RRR_MSG_0("Could not allocate memory in mqttclient_parse_publish_value_tag\n");
		ret = 1;
		goto out;
	}
	memset(node, '\0', sizeof(*node));

	node->tag = strdup(value);
	if (node->tag == NULL) {
		RRR_MSG_0("Could not allocate memory for data in mqttclient_parse_publish_value_tag\n");
		ret = 1;
		goto out;
	}

	RRR_LL_APPEND(&data->publish_values_from_array_list, node);
	node = NULL;

	out:
	if (node != NULL) {
		rrr_map_item_destroy(node);
	}
	return ret;
}

static int mqttclient_parse_config (struct mqtt_client_data *data, struct rrr_instance_config_data *config) {
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

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_client_identifier", client_identifier);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_v5_recycle_assigned_client_identifier", do_recycle_assigned_client_identifier, 1); // Default is 1, yes

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

		data->server = strdup("localhost");
		if (data->server == NULL) {
			RRR_MSG_0("Could not allocate memory for mqtt_server in mqtt client\n");
			ret = 1;
			goto out;
		}
	}

	int publish_rrr_message_was_present = 0;

	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN("mqtt_publish_rrr_message", publish_rrr_message_was_present = 1);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_publish_rrr_message", do_publish_rrr_message, 0);

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

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->publish_values_from_array, config, "mqtt_publish_array_values")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing mqtt_publish_values_from_array\n");
			ret = 1;
			goto out;
		}
	}
	else {
		if (strlen(data->publish_values_from_array) == 0) {
			RRR_MSG_0("Parameter in mqtt_publish_values_from_array was empty for instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		if (publish_rrr_message_was_present != 0 && data->do_publish_rrr_message == 1) {
			RRR_MSG_0("Cannot have mqtt_publish_values_from_array set while mqtt_publish_rrr_message is 'yes'\n");
			ret = 1;
			goto out;
		}

		data->do_publish_rrr_message = 0;

		if (*data->publish_values_from_array == '*') {
			// OK, publish full raw array
		}
		else if (rrr_instance_config_traverse_split_commas_silent_fail(
				config,
				"mqtt_publish_array_values",
				mqttclient_parse_publish_value_tag,
				data
		) != 0) {
			RRR_MSG_0("Error while parsing mqtt_publish_values_from_array setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->connect_error_action, config, "mqtt_connect_error_action")) == 0) {
		if (strcasecmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RESTART) == 0) {
			// OK
		}
		else if (strcasecmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) == 0) {
			// OK
		}
		else {
			RRR_MSG_0("Unknown value for mqtt_connect_error_action (̈́'%s') in mqtt client instance %s, please refer to documentation\n",
					data->connect_error_action, config->name);
		}
	}
	else {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing mqtt_connect_error_action\n");
			ret = 1;
			goto out;
		}

		data->connect_error_action = strdup(RRR_MQTT_CONNECT_ERROR_DO_RESTART);
		if (data->connect_error_action == NULL) {
			RRR_MSG_0("Could not allocate memory for connect_error_action in mqtt client\n");
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

	if ((rrr_net_transport_config_parse(
			&data->net_transport_config,
			config,
			"mqtt",
			0,
			RRR_NET_TRANSPORT_PLAIN
	)) != 0) {
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT("mqtt_server_port", server_port, (
			data->net_transport_config.transport_type == RRR_NET_TRANSPORT_TLS
				? RRR_MQTT_DEFAULT_SERVER_PORT_TLS
				: RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN
	));

	// Undocumented parameter. Causes client to send UNSUBSCRIBE, wait for UNSUBACK and then
	// subscribe to all topics once more.
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("mqtt_client_debug_unsubscribe_cycle", do_debug_unsubscribe_cycle, 0);
	if (data->do_debug_unsubscribe_cycle != 0 && rrr_mqtt_subscription_collection_count(data->requested_subscriptions) == 0) {
		RRR_MSG_0("debug_unsubscribe_cycle set without any subscriptions in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	ret = 0;

	/* On error, memory is freed by mqttclient_data_cleanup */

	out:
	return ret;
}

static int mqttclient_process_unsuback (
		struct mqtt_client_data *data,
		const struct rrr_mqtt_subscription *subscription,
		const uint8_t reason_v5
) {
	const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(reason_v5);

	if (reason == NULL) {
		RRR_MSG_0("Unknown reason %u received in UNSUBACK in mqtt client instance %s\n",
				reason_v5,
				INSTANCE_D_NAME(data->thread_data)
		);
		return 1;
	}

	if (reason_v5 != RRR_MQTT_P_5_REASON_OK) {
		RRR_MSG_0("Warning: UNSUBSCRIBE rejected for topic '%s' with reason %u '%s' in mqtt client instance %s",
				subscription->topic_filter,
				reason_v5,
				reason->description,
				INSTANCE_D_NAME(data->thread_data)
		);
	}

	return 0;
}

static int mqttclient_process_suback (
		struct mqtt_client_data *data,
		const struct rrr_mqtt_subscription *subscription,
		const int i,
		const uint8_t qos_or_reason_v5
) {
	int ret = 0;

	if (qos_or_reason_v5 > 2) {
		const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5(qos_or_reason_v5);
		if (reason == NULL) {
			RRR_MSG_0("Unknown reason 0x%02x from mqtt broker in SUBACK topic index %i in mqtt client instance %s",
					qos_or_reason_v5, i, INSTANCE_D_NAME(data->thread_data));
			return 1;
		}
		RRR_MSG_0("Warning: Subscription '%s' index '%i' rejected from broker in mqtt client instance %s with reason '%s'\n",
				subscription->topic_filter,
				i,
				INSTANCE_D_NAME(data->thread_data),
				reason->description
		);
	}
	else if (qos_or_reason_v5 < subscription->qos_or_reason_v5) {
		RRR_MSG_0("Warning: Subscription '%s' index '%i' assigned QoS %u from server while %u was requested in mqtt client instance %s \n",
				subscription->topic_filter,
				i,
				qos_or_reason_v5,
				subscription->qos_or_reason_v5,
				INSTANCE_D_NAME(data->thread_data)
		);
	}

	return ret;
}

static int mqttclient_process_suback_unsuback (
		struct rrr_mqtt_client_data *mqtt_client_data,
		struct rrr_mqtt_p_suback_unsuback *packet,
		void *arg
) {
	struct mqtt_client_data *data = arg;

	(void)(mqtt_client_data);

	struct rrr_mqtt_p_suback_unsuback *ack = (struct rrr_mqtt_p_suback_unsuback *) packet;

	int new_count = ack->acknowledgements_size;
	const struct rrr_mqtt_subscription_collection *orig_collection = ack->orig_sub_usub->subscriptions;
	int orig_count = (orig_collection != NULL ? rrr_mqtt_subscription_collection_count(orig_collection) : 0);

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK) {
		if (orig_count != new_count) {
			// Session framework should catch this
			RRR_BUG("Count mismatch in SUBSCRIBE and SUBACK messages in mqtt client instance %s (%i vs %i)\n",
					INSTANCE_D_NAME(data->thread_data), orig_count, new_count);
		}

		// We don't actually keep track of which subscriptions have been accepted, but only
		// print warnings about those topics which were rejected by the broker
		for (int i = 0; i < new_count; i++) {
			const struct rrr_mqtt_subscription *subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx (
					orig_collection,
					i
			);
			if (mqttclient_process_suback(data, subscription, i, ack->acknowledgements[i]) != 0) {
				return 1;
			}
		}

		data->received_suback_packet_id = RRR_MQTT_P_GET_IDENTIFIER(ack);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK) {
		if (RRR_MQTT_P_IS_V5(packet)) {
			if (orig_count != new_count) {
				// Session framework should catch this
				RRR_BUG("Count mismatch in SUBSCRIBE and SUBACK messages in mqtt client instance %s (%i vs %i)\n",
						INSTANCE_D_NAME(data->thread_data), orig_count, new_count);
			}
			for (int i = 0; i < new_count; i++) {
				const struct rrr_mqtt_subscription *subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx (
						orig_collection,
						i
				);
				if (mqttclient_process_unsuback(data, subscription, ack->acknowledgements[i]) != 0) {
					return 1;
				}
			}
		}
		else {
			// Can't really do anything, UNSUBACK V3.1 has no information
		}
		data->received_unsuback_packet_id = RRR_MQTT_P_GET_IDENTIFIER(ack);
	}
	else {
		RRR_BUG("Unknown packet of type %u received in mqtt client %s mqttclient_process_suback\n",
				RRR_MQTT_P_GET_TYPE(packet),
				INSTANCE_D_NAME(data->thread_data)
		);
	}

	return 0;
}

// Used to print informational messages only
static int mqttclient_process_parsed_packet (
		struct rrr_mqtt_client_data *mqtt_client_data,
		struct rrr_mqtt_p *packet,
		void *arg
) {
	struct mqtt_client_data *data = arg;

	(void)(mqtt_client_data);

//	printf ("mqttclient parsed packet of type %s\n", RRR_MQTT_P_GET_TYPE_NAME(packet));

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

static int mqttclient_message_data_to_payload (
		char **result,
		ssize_t *result_size,

		struct rrr_msg_msg *reading
) {
	*result = NULL;
	*result_size = 0;

	char *payload = malloc(MSG_DATA_LENGTH(reading));

	if (payload == NULL) {
		RRR_MSG_0 ("could not allocate memory for PUBLISH payload in message_data_to_payload \n");
		return 1;
	}

	memcpy(payload, MSG_DATA_PTR(reading), MSG_DATA_LENGTH(reading));

	*result = payload;
	*result_size = MSG_DATA_LENGTH(reading);

	return 0;
}

static int mqttclient_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct mqtt_client_data *private_data = thread_data->private_data;
	struct rrr_mqtt_p_publish *publish = NULL;
	struct rrr_msg_msg *reading = (struct rrr_msg_msg *) entry->message;

	char *payload = NULL;
	ssize_t payload_size = 0;
	int ret = 0;

	struct rrr_array array_tmp = {0};

	RRR_DBG_2 ("mqtt client %s: Result from buffer: timestamp %" PRIu64 ", creating PUBLISH\n",
			INSTANCE_D_NAME(thread_data), reading->timestamp);

	if (private_data->mqtt_client_data->protocol_version == NULL) {
		RRR_MSG_0("Protocol version not yet set in mqtt client instance %s mqttclient_poll_callback while sending PUBLISH\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	publish = (struct rrr_mqtt_p_publish *) rrr_mqtt_p_allocate(RRR_MQTT_P_TYPE_PUBLISH, private_data->mqtt_client_data->protocol_version);
	if (publish == NULL) {
		RRR_MSG_0("Could not allocate PUBLISH in mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish->payload);
	publish->payload = NULL;

	RRR_FREE_IF_NOT_NULL(publish->topic);

	if (MSG_TOPIC_LENGTH(reading) > 0 && *((const char *) MSG_TOPIC_PTR(reading)) == '\0') {
		RRR_BUG("BUG: Topic first character value was '0' in mqttclient_poll_callback\n");
	}

	if (private_data->do_prepend_publish_topic) {
		if (MSG_TOPIC_LENGTH(reading) == 0) {
			RRR_MSG_0("Warning: Received message to MQTT client instance %s did not have topic set, and only a prepend topic is set in configuration. Dropping message.\n",
					INSTANCE_D_NAME(thread_data));
			ret = 0;
			goto out_free;
		}

		// NOTE : Locally freed variable. Memory error is printed further down if we fail.
		char *topic_tmp = malloc (MSG_TOPIC_LENGTH(reading) + 1);
		if (topic_tmp != NULL) {
			memcpy (topic_tmp, MSG_TOPIC_PTR(reading), MSG_TOPIC_LENGTH(reading));
			*(topic_tmp + MSG_TOPIC_LENGTH(reading)) = '\0';
			rrr_asprintf(&publish->topic, "%s%s", private_data->publish_topic, topic_tmp);
			free(topic_tmp);
		}
	}
	else {
		if (MSG_TOPIC_LENGTH(reading) > 0 && private_data->do_force_publish_topic == 0) {
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
			if (private_data->do_force_publish_topic != 0) {
				RRR_BUG("do_force_publish_topic was 1 but topic was not set in mqttclient_poll_callback of mqttclient\n");
			}
			RRR_MSG_0("Warning: Received message to MQTT client instance %s did not have topic set, and no default topic was defined in the configuration. Dropping message.\n",
					INSTANCE_D_NAME(thread_data));
			ret = 0;
			goto out_free;
		}
	}

	if (publish->topic == NULL) {
		RRR_MSG_0("Could not allocate topic in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(publish, private_data->qos);

	if (private_data->do_publish_rrr_message != 0) {
		ssize_t msg_size = MSG_TOTAL_SIZE(reading);

		reading->msg_size = msg_size;

		rrr_msg_msg_prepare_for_network(reading);

		rrr_msg_checksum_and_to_network_endian((struct rrr_msg *) reading);

		if (rrr_mqtt_property_collection_add_blob_or_utf8 (
				&publish->properties,
				RRR_MQTT_PROPERTY_CONTENT_TYPE,
				RRR_MESSAGE_MIME_TYPE,
				strlen(RRR_MESSAGE_MIME_TYPE)
		) != 0) {
			RRR_MSG_0("Could not set content-type of publish in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}
		payload = entry->message;
		payload_size = msg_size;
		entry->message = NULL;
	}
	else if (private_data->publish_values_from_array != NULL) {
		if (!MSG_IS_ARRAY(reading)) {
			RRR_MSG_0("Received message was not an array while mqtt_publish_values_from_array was set in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}

		const struct rrr_map *tags_to_use = (*(private_data->publish_values_from_array) == '*'
				? NULL
				: &private_data->publish_values_from_array_list
		);

		if (rrr_array_message_append_to_collection(&array_tmp, reading) != 0) {
			RRR_MSG_0("Could not create temporary array collection in mqttclient_poll_callback of mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}

		int found_tags = 0;
		if ((ret = rrr_array_selected_tags_export (
				&payload,
				&payload_size,
				&found_tags,
				&array_tmp,
				tags_to_use
		)) != 0) {
			RRR_MSG_0("Could not create payload data from selected array tags in mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}

		if (tags_to_use != NULL && found_tags != RRR_MAP_COUNT(&private_data->publish_values_from_array_list)) {
			RRR_DBG_1("Note: Only %i tags out of %i specified in configuration was found in message when sending array data in mqtt instance %s\n",
					found_tags, RRR_MAP_COUNT(&private_data->publish_values_from_array_list), INSTANCE_D_NAME(thread_data));
		}
	}
	else if (MSG_DATA_LENGTH(reading) > 0) {
		if ((ret = mqttclient_message_data_to_payload(&payload, &payload_size, reading)) != 0) {
			RRR_MSG_0("Error while creating payload from message data in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_free;
		}
	}
	else {
		if ((ret = rrr_msg_msg_to_string(&payload, reading)) != 0) {
			RRR_MSG_0("could not convert message to string for PUBLISH payload in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			goto out_free;
		}
		payload_size = strlen(payload) + 1;
	}

	if (payload != NULL) {
		if (rrr_mqtt_p_payload_new_with_allocated_payload (
				&publish->payload,
				&payload, // Set to NULL if success
				payload,
				payload_size
		) != 0) {
			RRR_MSG_0("Could not set payload of PUBLISH in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}
	}

	RRR_DBG_2 ("mqtt client %s: PUBLISH with topic %s\n",
			INSTANCE_D_NAME(thread_data), publish->topic);

	if (rrr_mqtt_client_publish(private_data->mqtt_client_data, &private_data->session, publish) != 0) {
		RRR_MSG_0("Could not publish message in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	private_data->total_sent_count++;

	out_free:
	rrr_array_clear (&array_tmp);
	rrr_msg_holder_unlock(entry);
	RRR_FREE_IF_NOT_NULL(payload);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish);

	return ret;
}

static int mqttclient_try_create_rrr_msg_msg_with_publish_data (
		struct rrr_msg_msg **result,
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

	if (rrr_msg_msg_new_empty (
			result,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			publish->create_time,
			topic_len,
			publish->payload->length
	) != 0) {
		RRR_MSG_0("Could not initialize message_final in receive_publish of mqtt client instance %s (A)\n",
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

static int mqttclient_try_get_rrr_msg_msg_from_publish (
		struct rrr_msg_msg **result,
		struct rrr_mqtt_p_publish *publish,
		struct mqtt_client_data *data
) {
	int ret = 0;

	if (publish->payload == NULL) {
		goto out_nolock;
	}

	struct rrr_msg_msg *message = (struct rrr_msg_msg *) publish->payload->payload_start;
	rrr_length message_actual_length = 0;

	{
		rrr_slength message_actual_length_signed = publish->payload->length;
		if (message_actual_length_signed < 0) {
			RRR_BUG("BUG: message_actual_length was < 0 in mqttclient_try_get_rrr_msg_msg_from_publish\n");
		}
		if (message_actual_length_signed > RRR_LENGTH_MAX) {
			RRR_MSG_0("Received RRR message in publish was too long in mqttclient instance %s: %" PRIrrrsl " > %u\n",
					INSTANCE_D_NAME(data->thread_data), message_actual_length_signed, RRR_LENGTH_MAX);
		}
		message_actual_length = (rrr_length) message_actual_length_signed;
	}

	if (message_actual_length < sizeof(struct rrr_msg)) {
		RRR_DBG_1("RRR Message of unknown length %" PRIrrrl " in mqtt client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	*result = NULL;

	RRR_MQTT_P_LOCK(publish->payload);

	rrr_length message_stated_length = 0;
	if (rrr_msg_get_target_size_and_check_checksum (
			&message_stated_length,
			(struct rrr_msg *) message,
			message_actual_length)
	) {
		RRR_DBG_1("RRR Message of size %" PRIrrrl " with corrupted header in mqtt client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (message_actual_length != message_stated_length) {
		RRR_DBG_1("RRR message_final size mismatch, have %" PRIrrrl " bytes but packet states %" PRIrrrl " in mqtt client instance %s\n",
				message_actual_length, message_stated_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_head_to_host_and_verify((struct rrr_msg *) message, message_actual_length) != 0) {
		RRR_DBG_1("RRR Message with invalid header in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_check_data_checksum_and_length((struct rrr_msg *) message, message_actual_length) != 0) {
		RRR_MSG_0("RRR message_final CRC32 mismatch in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_msg_msg_to_host_and_verify(message, message_actual_length) != 0) {
		RRR_MSG_0("RRR message_final was invalid in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	*result = malloc(message_actual_length);
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory in mqttclient_try_get_rrr_msg_msg_from_publish\n");
		ret = 1;
		goto out;
	}
	memcpy(*result, message, message_actual_length);

	out:
	RRR_MQTT_P_UNLOCK(publish->payload);

	out_nolock:
	return ret;
}

struct try_create_array_message_from_publish_callback_data {
	const char *topic;
	ssize_t topic_length;
	struct rrr_msg_msg **result;
};

static int __mqttclient_try_create_array_message_from_publish_callback (
		struct rrr_array *array,
		void *arg
) {
	struct try_create_array_message_from_publish_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *message = NULL;
	if ((ret = rrr_array_new_message_from_collection (
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
		ssize_t *parsed_bytes,
		struct rrr_mqtt_p_publish *publish,
		ssize_t read_pos,
		struct mqtt_client_data *data
) {
	int ret = 0;

	*result = NULL;
	*parsed_bytes = 0;

	if (publish->payload == NULL) {
		goto out_nolock;
	}

	RRR_MQTT_P_LOCK(publish->payload);

	if (publish->payload->length == 0) {
		RRR_MSG_0("Received PUBLISH message had zero length in MQTT client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (read_pos >= publish->payload->length) {
		ret = 0;
		goto out;
	}

	struct try_create_array_message_from_publish_callback_data callback_data = {
			publish->topic,
			strlen(publish->topic),
			result
	};

	if ((ret = rrr_array_tree_import_from_buffer (
			parsed_bytes,
			publish->payload->payload_start + read_pos,
			publish->payload->length - read_pos,
			data->tree,
			__mqttclient_try_create_array_message_from_publish_callback,
			&callback_data
	)) != 0) {
		if (ret == RRR_ARRAY_SOFT_ERROR) {
			RRR_MSG_0("Could not parse data array from received PUBLISH message in MQTT client instance %s, invalid data of length %li\n",
					INSTANCE_D_NAME(data->thread_data), publish->payload->length);
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
	RRR_MQTT_P_UNLOCK(publish->payload);

	out_nolock:
	return ret;
}

struct receive_publish_create_entry_callback_data {
	struct mqtt_client_data *data;
	const struct rrr_msg_msg *message;
};

static int mqttclient_receive_publish_create_entry_callback (struct rrr_msg_holder *entry, void *arg) {
	struct receive_publish_create_entry_callback_data *data = arg;

	int ret = 0;

	size_t msg_size = MSG_TOTAL_SIZE(data->message);

	if ((entry->message = malloc(msg_size)) == NULL) {
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

static int mqttclient_receive_publish_create_and_save_entry (const struct rrr_msg_msg *message, struct mqtt_client_data *data) {
	int ret = 0;

	struct receive_publish_create_entry_callback_data callback_data = {
			data,
			message
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER(data->thread_data),
			INSTANCE_D_HANDLE(data->thread_data),
			NULL,
			0,
			0,
			mqttclient_receive_publish_create_entry_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error while writing entry to output buffer in mqttclient_receive_publish_create_entry of mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

#define WRITE_TO_BUFFER_AND_SET_TO_NULL(message)								\
	if ((ret = mqttclient_receive_publish_create_and_save_entry(message, data)) != 0) {	\
		goto out;																\
	}	RRR_FREE_IF_NOT_NULL(message)

static int mqttclient_receive_publish (struct rrr_mqtt_p_publish *publish, void *arg) {
	int ret = 0;

	struct mqtt_client_data *data = arg;
	struct rrr_msg_msg *message_final = NULL;

	struct rrr_mqtt_property *property = NULL;
	const char *content_type = NULL;

	RRR_DBG_2 ("mqtt client %s: Receive PUBLISH payload length %li topic %s\n",
			INSTANCE_D_NAME(data->thread_data), (publish->payload != NULL ? publish->payload->length : 0), (publish->topic));

	if ((property = rrr_mqtt_property_collection_get_property(&publish->properties, RRR_MQTT_PROPERTY_CONTENT_TYPE, 0)) != NULL) {
		ssize_t length = 0;
		content_type = rrr_mqtt_property_get_blob(property, &length);
		if (content_type[length] != '\0') {
			RRR_BUG("Content type was not zero-terminated in mqtt client receive_publish\n");
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
		RRR_DBG_2 ("mqtt client %s: Received PUBLISH content type is '%s'\n",
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
			RRR_MSG_0("Error while parsing RRR message in receive_publish of mqtt client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (message_final == NULL && expecting_rrr_msg_msg != 0) {
			RRR_MSG_0("Received supposed RRR message_final turned out not to be, dropping it in mqtt client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		else if (message_final != NULL) {
			goto out_write_to_buffer;
		}
	}

	// Try to create an array message with the data from the publish (if specified in configuration)
	if (data->tree != NULL) {
		int count = 0;
		ssize_t read_pos = 0;
		do {
			ssize_t parsed_bytes = 0;
			if ((ret = mqttclient_try_create_array_message_from_publish (
					&message_final,
					&parsed_bytes,
					publish,
					read_pos,
					data
			)) != 0) {
				RRR_MSG_0("Error while parsing data array from received PUBLISH in mqtt client instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				break;
			}
			if (message_final == NULL) {
				if (count == 0) {
					RRR_MSG_0("Parsing of supposed received data array failed, dropping the data in mqtt client instance %s\n",
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
		RRR_MSG_0("Error while creating RRR message from publish data in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}
	else if (message_final != NULL) {
		RRR_DBG_2("MQTT client instance %s created message from PUBLISH message payload\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out_write_to_buffer;
	}

	// Try to create a message with the data being the topic of the publish
	if (rrr_msg_msg_new_with_data (
			&message_final,
			MSG_TYPE_MSG,
			MSG_CLASS_DATA,
			publish->create_time,
			publish->topic,
			strlen(publish->topic) + 1,
			publish->topic,
			strlen(publish->topic) + 1
	) != 0) {
		RRR_MSG_0("Could not initialize message_final in receive_publish of mqtt client instance %s (B)\n",
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
	return ret;
}

static int mqttclient_do_subscribe (struct mqtt_client_data *data) {
	if (data->received_suback_packet_id != 0) {
		RRR_BUG("received_suback_packet_id was not 0 in mqtt client do_subscribe\n");
	}

	int ret = RRR_MQTT_OK;

	if ((ret = rrr_mqtt_client_subscribe (
			data->mqtt_client_data,
			&data->session,
			data->requested_subscriptions
	)) != 0) {
		RRR_MSG_0("Could not subscribe to topics in mqtt client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		return ret;
	}

	return ret;
}

static int mqttclient_do_unsubscribe (struct mqtt_client_data *data) {
	if (data->received_unsuback_packet_id != 0) {
		RRR_BUG("received_unsuback_packet_id was not 0 in mqtt client do_subscribe\n");
	}

	int ret = RRR_MQTT_OK;

	if ((ret = rrr_mqtt_client_unsubscribe (
			data->mqtt_client_data,
			&data->session,
			data->requested_subscriptions
	)) != 0) {
		RRR_MSG_0("Could not unsubscribe to topics in mqtt client instance %s return was %i\n",
				INSTANCE_D_NAME(data->thread_data), ret);
		return ret;
	}
	return ret;
}

static int mqttclient_wait_send_allowed (struct mqtt_client_data *data) {
	int ret = RRR_MQTT_SOFT_ERROR; // Default is soft failure

	while (rrr_thread_check_encourage_stop(INSTANCE_D_THREAD(data->thread_data)) != 1) {
		int alive = 0;
		int send_allowed = 0;

		if ((ret = rrr_mqtt_client_connection_check_alive (
				&alive,
				&send_allowed,
				data->mqtt_client_data,
				data->transport_handle
		)) != 0) {
			RRR_MSG_0("Error in mqtt client instance %s while checking for connection alive\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		struct rrr_mqtt_session_iterate_send_queue_counters counters = {0};
		int something_happened = 0;
		if ((ret = rrr_mqtt_client_synchronized_tick(&counters, &something_happened, data->mqtt_client_data)) != 0) {
			RRR_MSG_0("Error in mqtt client instance %s while running tasks\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (alive != 1) {
			ret = RRR_MQTT_SOFT_ERROR;
			goto out;
		}

		if (send_allowed != 0) {
			ret = RRR_MQTT_OK;
			goto out;
		}

		if (something_happened == 0) {
			rrr_posix_usleep (50000); // 50 ms
		}
	}

	out:
	return ret;
}

static int mqttclient_late_client_identifier_update (struct mqtt_client_data *data) {
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

	// Make sure CONNACK has arrived
	if ((ret = mqttclient_wait_send_allowed(data)) != 0) {
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

static int mqttclient_subscription_loop (struct mqtt_client_data *data) {
	int ret = RRR_MQTT_OK;

	uint64_t subscription_sent_time = 0;
	int subscription_send_attempts = 0;
	int subscription_done = 0;

	uint64_t unsubscription_sent_time = 0;
	int unsubscription_send_attempts = 0;
	int unsubscription_done = 0;

	if (rrr_mqtt_subscription_collection_count(data->requested_subscriptions) == 0) {
		goto out;
	}

	// Subscription loop
	while (rrr_thread_check_encourage_stop(INSTANCE_D_THREAD(data->thread_data)) != 1) {
		// This will also do sending/receiving
		if ((ret = mqttclient_wait_send_allowed(data)) != 0) {
			goto out;
		}

		if (subscription_done == 0) {
			if (subscription_sent_time == 0) {
				data->received_suback_packet_id = 0;
				if ((ret = mqttclient_do_subscribe(data)) != 0) {
					goto out;
				}
				subscription_send_attempts++;
				subscription_sent_time = rrr_time_get_64();
			}
			else if (data->received_suback_packet_id != 0) {
				subscription_done = 1;
			}
			else if (rrr_time_get_64() > subscription_sent_time + (RRR_MQTT_SUBACK_RESEND_TIMEOUT_MS * 1000)) {
				if (subscription_send_attempts > RRR_MQTT_SUBACK_RESEND_MAX) {
					RRR_MSG_0("MQTT client %s giving up waiting for SUBACK\n", INSTANCE_D_NAME(data->thread_data));
					ret = RRR_MQTT_SOFT_ERROR;
					goto out;
				}

				subscription_sent_time = 0;
				RRR_MSG_0("MQTT client %s timeout while waiting for SUBACK, retry\n", INSTANCE_D_NAME(data->thread_data));
			}
		}
		else if (data->do_debug_unsubscribe_cycle != 0 && unsubscription_done == 0) {
			if (unsubscription_sent_time == 0) {
				data->received_unsuback_packet_id = 0;
				if ((ret = mqttclient_do_unsubscribe(data)) != 0) {
					goto out;
				}
				unsubscription_send_attempts++;
				unsubscription_sent_time = rrr_time_get_64();
			}
			else if (data->received_unsuback_packet_id != 0) {
				unsubscription_done = 1;

				// Subscribe once again
				subscription_done = 0;
				subscription_sent_time = 0;
			}
			else if (rrr_time_get_64() > unsubscription_sent_time + (RRR_MQTT_SUBACK_RESEND_TIMEOUT_MS * 1000)) {
				if (unsubscription_send_attempts > RRR_MQTT_SUBACK_RESEND_MAX) {
					RRR_MSG_0("MQTT client %s giving up waiting for SUBACK\n", INSTANCE_D_NAME(data->thread_data));
					ret = RRR_MQTT_SOFT_ERROR;
					goto out;
				}

				unsubscription_sent_time = 0;
				RRR_MSG_0("MQTT client %s timeout while waiting for SUBACK, retry\n", INSTANCE_D_NAME(data->thread_data));
			}
		}
		else {
			break;
		}
	}

	out:
	return ret;
}

static int mqttclient_connect_loop (struct mqtt_client_data *data, int clean_start) {
	int ret = RRR_MQTT_SOFT_ERROR;

	int i_first = data->connect_attempts;
	if (i_first < 1 || (uint64_t) i_first != (uint64_t) data->connect_attempts) {
		i_first = 0x7fffffff; // One 7, seven f's
		RRR_MSG_0("Warning: Connection attempt parameter overflow for mqtt client instance %s, changed to %i\n",
				INSTANCE_D_NAME(data->thread_data), i_first);
	}

	int is_retry = 0;

	reconnect:

	if (is_retry != 0 && data->do_discard_on_connect_retry) {
		int discarded_count = 0;

		if (rrr_poll_do_poll_discard (&discarded_count, data->thread_data, &data->thread_data->poll) != 0) {
			RRR_MSG_0("Polling from senders failed while discarding messages upon connect retry in mqttclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = RRR_MQTT_INTERNAL_ERROR;
			goto out;
		}

		data->total_discarded_count += discarded_count;

		if (discarded_count > 0) {
			RRR_DBG_1("mqttclient instance %s discarded %i messages from senders upon connect retry\n",
					INSTANCE_D_NAME(data->thread_data), discarded_count);
		}
	}

	data->transport_handle = 0;
	data->session = NULL;

	for (int i = i_first; i >= 0 && rrr_thread_check_encourage_stop(INSTANCE_D_THREAD(data->thread_data)) != 1; i--) {
		rrr_thread_update_watchdog_time(INSTANCE_D_THREAD(data->thread_data));

		RRR_DBG_1("MQTT client instance %s attempting to connect to server '%s' port '%" PRIrrrbl "' username '%s' client-ID '%s' attempt %i/%i\n",
				INSTANCE_D_NAME(data->thread_data),
				data->server,
				data->server_port,
				(data->username != NULL ? data->username : ""),
				(data->client_identifier != NULL ? data->client_identifier : ""),
				i,
				i_first
		);

		if ((ret = rrr_mqtt_client_connect (
				&data->transport_handle,
				&data->session,
				data->mqtt_client_data,
				data->server,
				data->server_port,
				data->version,
				RRR_MQTT_CLIENT_KEEP_ALIVE,
				clean_start,
				data->username,
				data->password,
				&data->connect_properties
		)) != 0) {
			if (ret & RRR_MQTT_INTERNAL_ERROR) {
				RRR_MSG_0("Internal error from rrr_mqtt_client_connect in MQTT client instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				goto out;
			}
			if (i == 0) {
				if (strcmp (data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) == 0) {
					RRR_MSG_0("MQTT client instance %s: %i connection attempts failed, trying again. Return was %i.\n",
							INSTANCE_D_NAME(data->thread_data),
							i_first,
							ret
					);
					ret = RRR_MQTT_OK;
					is_retry = 1;
					goto reconnect;
				}

				RRR_MSG_0("Could not connect to mqtt server '%s' port %" PRIrrrbl " in instance %s, restarting. Return was %i.\n",
						data->server,
						data->server_port,
						INSTANCE_D_NAME(data->thread_data),
						ret
				);

				ret = RRR_MQTT_SOFT_ERROR;
				break;
			}
			rrr_posix_usleep (100 * 1000);
		}
		else {
			ret = RRR_MQTT_OK;
			break;
		}
	}

	out:
	return ret;
}

static void mqttlient_update_stats (
		struct mqtt_client_data *data,
		struct rrr_stats_instance *stats,
		int to_remote_buffer_size,
		int to_remote_unacknowledged_publish
) {

	if (stats->stats_handle == 0) {
		return;
	}

	struct rrr_mqtt_client_stats client_stats;
	rrr_mqtt_client_get_stats (&client_stats, data->mqtt_client_data);

	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_delivered", 0, client_stats.session_stats.total_publish_delivered);

	// This is difficult to count in the MQTT-framework as the same function is used to send packets
	// regardless of their origin. We therefore count it in the module poll callback function.
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_sent", 0, data->total_sent_count);

	rrr_stats_instance_post_unsigned_base10_text(stats, "total_usleep", 0, data->total_usleep_count);
	rrr_stats_instance_post_unsigned_base10_text(stats, "total_ticks", 0, data->total_ticks_count);

	rrr_stats_instance_post_unsigned_base10_text(stats, "to_remote_buffer", 0, to_remote_buffer_size);
	rrr_stats_instance_post_unsigned_base10_text(stats, "to_remote_unack", 0, to_remote_unacknowledged_publish);

	// These will always be zero for the client, nothing is forwarded. Keep it here nevertheless to avoid accidently activating it.
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_forwarded", 0, client_stats.session_stats.total_publish_forwarded);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_received", 0, client_stats.session_stats.total_publish_received);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_not_forwarded", 0, client_stats.session_stats.total_publish_not_forwarded);
}

static void mqttclient_exit_message (void *arg) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	RRR_DBG_1 ("Thread mqtt client %p instance %s loop ended\n",
			thread, INSTANCE_D_NAME(thread_data));
}

static void mqttclient_poststop (const struct rrr_thread *thread) {
	// We only have this to show that poststop is called when we do freeze testing
	RRR_DBG_1 ("Thread mqtt client %p in poststop\n", thread);

#ifdef RRR_MQTT_FREEZE_TEST_ENABLE
	printf("** FREEZE TEST POSTSTOP START %p *********************\n", thread);
#endif /* RRR_MQTT_FREEZE_TEST_ENABLE */
}

static void *thread_entry_mqtt_client (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct mqtt_client_data *data = thread_data->private_data = thread_data->private_memory;

	int init_ret = 0;
	if ((init_ret = mqttclient_data_init(data, thread_data)) != 0) {
		RRR_MSG_0("Could not initialize data in mqtt client instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	RRR_BENCHMARK_INIT(mqtt_client_deliver);
	RRR_BENCHMARK_INIT(mqtt_client_sleep);
	RRR_BENCHMARK_INIT(mqtt_client_tick);

	RRR_DBG_1 ("mqtt client thread data is %p\n", thread_data);

	pthread_cleanup_push(mqttclient_data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (mqttclient_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for mqtt client instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	RRR_DBG_1 ("MQTT instance %s using '%s' as client identifier\n",
			INSTANCE_D_NAME(thread_data), (data->client_identifier != NULL ? data->client_identifier : "(auto)"));

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	struct rrr_mqtt_common_init_data init_data = {
		data->client_identifier, // May be NULL
		RRR_MQTT_COMMON_RETRY_INTERVAL,
		RRR_MQTT_COMMON_CLOSE_WAIT_TIME,
		RRR_MQTT_COMMON_MAX_CONNECTIONS
	};

	if (rrr_mqtt_client_new (
			&data->mqtt_client_data,
			&init_data,
			rrr_mqtt_session_collection_ram_new,
			NULL,
			mqttclient_process_suback_unsuback,
			data,
			mqttclient_process_parsed_packet,
			data
		) != 0) {
		RRR_MSG_0("Could not create new mqtt client\n");
		goto out_message;
	}

	pthread_cleanup_push(rrr_mqtt_client_destroy_void, data->mqtt_client_data);
	pthread_cleanup_push(rrr_mqtt_client_notify_pthread_cancel_void, data->mqtt_client_data);

	// This is done in mqttclient so to allow the message gets printed during when freeze test is enabled
	pthread_cleanup_push(mqttclient_exit_message, thread);

	int no_senders = 0;
	if (rrr_poll_collection_count(&thread_data->poll) == 0) {
		no_senders = 1;
		if (data->publish_topic != NULL) {
			RRR_MSG_0("Warning: mqtt client instance %s has publish topic set but there are not senders specified in configuration\n",
					INSTANCE_D_NAME(thread_data));
		}
	}

	RRR_DBG_1 ("mqtt client started thread %p\n", thread_data);

	if (rrr_mqtt_property_collection_add_uint32 (
			&data->connect_properties,
			RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM,
			0xffff
	) != 0) {
		RRR_MSG_0("Could not set CONNECT properties in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	if (rrr_mqtt_client_start (
			data->mqtt_client_data,
			&data->net_transport_config
	) != 0) {
		RRR_MSG_0("Could not start transport in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	// We have do use clean start the first time we connect as the server
	// might remember packets from our last session (if any)
	int clean_start = 1;

	reconnect:

	// Do this to avoid connection build-up on persistent error conditions
	rrr_mqtt_client_close_all_connections(data->mqtt_client_data);

	if (rrr_thread_check_encourage_stop(thread) == 1) {
		goto out_destroy_client;
	}

	int ret_tmp = 0;

	if (mqttclient_connect_loop(data, clean_start) != RRR_MQTT_OK) {
		goto out_destroy_client;
	}

	if ((ret_tmp = mqttclient_subscription_loop(data)) != RRR_MQTT_OK) {
		if (ret_tmp & RRR_MQTT_INTERNAL_ERROR) {
			goto out_destroy_client;
		}
		goto reconnect;
	}

	if ((ret_tmp = mqttclient_late_client_identifier_update(data)) != RRR_MQTT_OK) {
		if (ret_tmp & RRR_MQTT_INTERNAL_ERROR) {
			goto out_destroy_client;
		}
		goto reconnect;
	}

	uint64_t startup_time = rrr_time_get_64() + RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS * 1000;

	RRR_DBG_1("MQTT client %s startup send grace period %i ms started\n",
			INSTANCE_D_NAME(data->thread_data),
			RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS
	);

	// Successive connect attempts or re-connect does not require clean start to be set. Server
	// will respond with CONNACK with session present=0 if we need to clean up our state.
	clean_start = 0;

	// Main loop

	// Defaults to 1, is set to 0 when to many PUBLISH are undelivered
	int poll_allowed = 1;

	unsigned int consecutive_nothing_happened = 0;

#ifdef RRR_MQTT_FREEZE_TEST_ENABLE
	uint64_t freeze_start_time = rrr_time_get_64() + 500000; // 500ms
	uint64_t freeze_end_time = rrr_time_get_64() + 10000000; // 8s
#endif

	uint64_t prev_stats_time = rrr_time_get_64();

	while (rrr_thread_check_encourage_stop(thread) != 1) {
		uint64_t time_now = rrr_time_get_64();
		rrr_thread_update_watchdog_time(thread);

		int alive = 0;
		int send_allowed = 0;

		if ((ret_tmp = rrr_mqtt_client_connection_check_alive (
				&alive,
				&send_allowed,
				data->mqtt_client_data,
				data->transport_handle
		)) != 0) {
			// Only returns OK or INTERNAL_ERROR
			RRR_MSG_0("Error in mqtt client instance %s while checking for connection alive return was %i\n",
					INSTANCE_D_NAME(thread_data), ret_tmp);
			goto out_destroy_client;
		}

		if (alive == 0) {
			RRR_MSG_0("Connection lost for mqtt client instance %s, reconnecting\n",
				INSTANCE_D_NAME(thread_data));
			goto reconnect;
		}

		int something_happened = 0;

		struct rrr_mqtt_session_iterate_send_queue_counters counters = {0};

		RRR_BENCHMARK_IN(mqtt_client_tick);
		ret_tmp = rrr_mqtt_client_synchronized_tick(&counters, &something_happened, data->mqtt_client_data);
		RRR_BENCHMARK_OUT(mqtt_client_tick);
		if (ret_tmp != RRR_MQTT_OK) {
			if ((ret_tmp & RRR_MQTT_INTERNAL_ERROR) != 0) {
				RRR_MSG_0("Error in mqtt client instance %s while running tasks return was %i\n",
						INSTANCE_D_NAME(thread_data), ret_tmp);
				break;
			}
			goto reconnect;
		}


		if (counters.incomplete_qos_publish_counter > RRR_MQTT_CLIENT_INCOMPLETE_PUBLISH_QOS_LIMIT ||
			counters.buffer_size > RRR_MQTT_CLIENT_TO_REMOTE_BUFFER_LIMIT
		) {
			if (poll_allowed == 1) {
				RRR_DBG_2("Polling disabled in MQTT client instance %s, %u PUBLISH with QOS undelivered as this time with buffer size %u\n",
						INSTANCE_D_NAME(thread_data),
						counters.incomplete_qos_publish_counter,
						counters.buffer_size
				);
			}
			poll_allowed = 0;
		}
		else if (poll_allowed == 0) {
			if (counters.incomplete_qos_publish_counter < (RRR_MQTT_CLIENT_INCOMPLETE_PUBLISH_QOS_LIMIT / 2) &&
				counters.buffer_size < (RRR_MQTT_CLIENT_TO_REMOTE_BUFFER_LIMIT / 2)
			) {
				RRR_DBG_2("Polling re-enabled in MQTT client instance %s\n", INSTANCE_D_NAME(thread_data));
				poll_allowed = 1;
			}
		}

		RRR_BENCHMARK_IN(mqtt_client_deliver);
		ret_tmp = rrr_mqtt_client_iterate_and_clear_local_delivery(data->mqtt_client_data, mqttclient_receive_publish, data);
		RRR_BENCHMARK_OUT(mqtt_client_deliver);
		if (ret_tmp != RRR_MQTT_OK) {
			if ((ret_tmp & RRR_MQTT_INTERNAL_ERROR) != 0) {
				RRR_MSG_0("Error while iterating local delivery queue in mqtt client instance %s return was %i\n",
						INSTANCE_D_NAME(thread_data), ret_tmp);
				break;
			}
			goto reconnect;
		}

		// When adjusting sleep algorithm, test throughput properly afterwards with different configurations

		int poll_sleep = 0;

		if (something_happened == 0) {
			if (++consecutive_nothing_happened > 100) {
				poll_sleep = 30;
			}
		}
		else {
			consecutive_nothing_happened = 0;
		}

		if (poll_allowed == 1 && (time_now > startup_time)) {
			if (poll_sleep > 0) {
				data->total_usleep_count++;
			}

			if (no_senders) {
				rrr_posix_usleep(10000); // 10ms
			}
			else {
				RRR_BENCHMARK_IN(mqtt_client_sleep);
				if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, mqttclient_poll_callback, poll_sleep) != 0) {
					RRR_MSG_0("Error while polling from senders in MQTT client instance %s\n", INSTANCE_D_NAME(thread_data));
					break;
				}
				RRR_BENCHMARK_OUT(mqtt_client_sleep);
			}
		}

		data->total_ticks_count++;

		if (time_now > (prev_stats_time + RRR_MQTT_CLIENT_STATS_INTERVAL_MS * 1000)) {
			mqttlient_update_stats (
					data,
					INSTANCE_D_STATS(thread_data),
					counters.buffer_size,
					counters.incomplete_qos_publish_counter
			);
			prev_stats_time = rrr_time_get_64();
		}

#ifdef RRR_MQTT_FREEZE_TEST_ENABLE
		if (rrr_time_get_64() > freeze_start_time) {
			printf("** FREEZE TEST START %p ******************************\n", thread);
			while (rrr_time_get_64() < freeze_end_time) {
				rrr_slow_noop();
				// Freeze :-)
			}
			// Watchdog will send pthread_cancel while we are in the loop.
			// We should jump directly to first pthread cleanup pop now
			pthread_testcancel();
			printf("** FREEZE TEST END %p (this should not print) ********\n", thread);
		}
#endif
	}

	out_destroy_client:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
	out_message:
		RRR_DBG_1 ("Thread mqtt client %p instance %s exiting\n",
				thread, INSTANCE_D_NAME(thread_data));
		pthread_cleanup_pop(1);
		RRR_BENCHMARK_DUMP(mqtt_client_tick);
		RRR_BENCHMARK_DUMP(mqtt_client_sleep);
		RRR_BENCHMARK_DUMP(mqtt_client_deliver);
		pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mqtt_client,
		mqttclient_poststop,
		NULL,
		NULL
};

static const char *module_name = "mqtt_client";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = RRR_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	RRR_DBG_1 ("Destroy mqtt client module\n");
}

