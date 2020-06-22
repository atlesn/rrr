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

#include "../lib/mqtt_topic.h"
#include "../lib/mqtt_client.h"
#include "../lib/mqtt_common.h"
#include "../lib/mqtt_session_ram.h"
#include "../lib/mqtt_subscription.h"
#include "../lib/mqtt_packet.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/message_broker.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/ip.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/rrr_socket.h"
#include "../lib/utf8.h"
#include "../lib/linked_list.h"
#include "../lib/map.h"
#include "../lib/array.h"
#include "../lib/stats_instance.h"
#include "../lib/log.h"

#define RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN 1883
#define RRR_MQTT_DEFAULT_SERVER_PORT_TLS 8883
#define RRR_MQTT_DEFAULT_QOS 1
#define RRR_MQTT_DEFAULT_VERSION 4 // 3.1.1
#define RRR_MQTT_DEFAULT_RECONNECT_ATTEMPTS 20
#define RRR_MQTT_CLIENT_STATS_INTERVAL_MS 1000

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

struct mqtt_client_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_fifo_buffer output_buffer;
	struct rrr_mqtt_client_data *mqtt_client_data;
	int transport_handle;
	struct rrr_mqtt_session *session;
	rrr_setting_uint server_port;
	struct rrr_mqtt_subscription_collection *requested_subscriptions;
	struct rrr_mqtt_property_collection connect_properties;
	char *server;
	char *publish_topic;
	int force_publish_topic;
	char *version_str;
	char *client_identifier;
	char *publish_values_from_array;
	struct rrr_map publish_values_from_array_list;
	struct rrr_array array_definition;
	uint8_t qos;
	uint8_t version;
	int publish_rrr_message;
	int receive_rrr_message;
	char *connect_error_action;
	rrr_setting_uint connect_attempts;
	int debug_unsubscribe_cycle;
	unsigned int received_suback_packet_id;
	unsigned int received_unsuback_packet_id;
	uint64_t total_sent_count;
	uint64_t total_usleep_count;
	uint64_t total_ticks_count;
	char *username;
	char *password;
	char *tls_certificate_file;
	char *tls_key_file;
	char *tls_ca_file;
	char *tls_ca_path;
	char *transport_type;
	int do_transport_tls;
	int do_transport_plain;
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
	RRR_FREE_IF_NOT_NULL(data->tls_certificate_file);
	RRR_FREE_IF_NOT_NULL(data->tls_key_file);
	RRR_FREE_IF_NOT_NULL(data->tls_ca_file);
	RRR_FREE_IF_NOT_NULL(data->tls_ca_path);
	RRR_FREE_IF_NOT_NULL(data->transport_type);
	rrr_map_clear(&data->publish_values_from_array_list);
	rrr_mqtt_subscription_collection_destroy(data->requested_subscriptions);
	rrr_mqtt_property_collection_destroy(&data->connect_properties);
	rrr_array_clear(&data->array_definition);
}

static int mqttclient_data_init (
		struct mqtt_client_data *data,
		struct rrr_instance_thread_data *thread_data
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
		// TODO: implement
		//rrr_fifo_buffer_destroy(&data->output_buffer);
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

// TODO : Provide more configuration arguments
static int mqttclient_parse_config (struct mqtt_client_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	int yesno = 0;

	rrr_setting_uint mqtt_qos = 0;
	rrr_setting_uint mqtt_connect_attempts = 0;

	if ((ret = rrr_instance_config_read_unsigned_integer(&mqtt_connect_attempts, config, "mqtt_connect_attempts")) == 0) {
		if (mqtt_connect_attempts < 1) {
			RRR_MSG_0("Setting mqtt_reconnect_attempts must be 1 or more in MQTT client instance %s. %llu was given.",
					config->name, mqtt_connect_attempts);
			ret = 1;
			goto out;
		}
	}
	else if (ret == RRR_SETTING_NOT_FOUND) {
		mqtt_connect_attempts = RRR_MQTT_DEFAULT_RECONNECT_ATTEMPTS;
		ret = 0;
	}
	else {
		RRR_MSG_0("Error while parsing mqtt_reconnect_attempts setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	data->connect_attempts = mqtt_connect_attempts;

	if ((ret = rrr_instance_config_read_unsigned_integer(&mqtt_qos, config, "mqtt_qos")) == 0) {
		if (mqtt_qos > 2) {
			RRR_MSG_0("Setting mqtt_qos was >2 in config of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing mqtt_qos setting of instance %s\n", config->name);
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
			RRR_MSG_0("Could not allocate memory in mqttclient_parse_config of instance %s\n", config->name);
		}
		strcpy(data->client_identifier, config->name);
	}

	if (rrr_utf8_validate(data->client_identifier, strlen(data->client_identifier)) != 0) {
		RRR_MSG_0("Client identifier of mqtt client instance %s was not valid UTF-8\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_DBG_2 ("MQTT instance %s using '%s' as client identifier\n",
			config->name, data->client_identifier);

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
	data->publish_rrr_message = 1;
	if ((ret = (rrr_instance_config_check_yesno(&yesno, config, "mqtt_publish_rrr_message")
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not interpret mqtt_publish_rrr_message setting of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else {
		if (yesno == 0) {
			data->publish_rrr_message = 0;
		}
		publish_rrr_message_was_present = 1;
	}


	if ((ret = (rrr_instance_config_check_yesno(&yesno, config, "mqtt_publish_topic_force")
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not interpret mqtt_publish_topic_force setting of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (yesno > 0) {
		data->force_publish_topic = 1;
	}

	if ((ret = rrr_instance_config_parse_array_definition_from_config_silent_fail (
			&data->array_definition,
			config,
			"mqtt_receive_array"
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing array definition in mqtt_receive_array of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_array_count(&data->array_definition) == 0) {
			RRR_MSG_0("No items specified in array definition in mqtt_receive_array of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->receive_rrr_message = 0;
	if ((ret = (rrr_instance_config_check_yesno(&yesno, config, "mqtt_receive_rrr_message")
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not interpret mqtt_receive_rrr_message setting of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (yesno > 0) {
		if (rrr_array_count(&data->array_definition) > 0) {
			RRR_MSG_0("mqtt_receive_rrr_message was set to yes but mqtt_receive_array_definition was also specified for instance %s, cannot have both.\n", config->name);
			ret = 1;
			goto out;
		}
		data->receive_rrr_message = 1;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->publish_topic, config, "mqtt_publish_topic")) == 0) {
		if (strlen(data->publish_topic) == 0) {
			RRR_MSG_0("Topic name in mqtt_publish_topic was empty for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_mqtt_topic_validate_name(data->publish_topic) != 0) {
			RRR_MSG_0("Topic name in mqtt_publish_topic was invalid for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (ret == RRR_SETTING_NOT_FOUND && data->force_publish_topic != 0) {
		RRR_MSG_0("mqtt_force_publish_topic was yes but no mqtt_publish_topic was set for instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_instance_config_traverse_split_commas_silent_fail(config, "mqtt_subscribe_topics", mqttclient_parse_sub_topic, data)) != 0) {
		RRR_MSG_0("Error while parsing mqtt_subscribe_topics setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->publish_values_from_array, config, "mqtt_publish_array_values")) == 0) {
		if (strlen(data->publish_values_from_array) == 0) {
			RRR_MSG_0("Parameter in mqtt_publish_values_from_array was empty for instance %s\n", config->name);
			ret = 1;
			goto out;
		}

		if (publish_rrr_message_was_present != 0 && data->publish_rrr_message == 1) {
			RRR_MSG_0("Cannot have mqtt_publish_values_from_array set while mqtt_publish_rrr_message is 'yes'\n");
			ret = 1;
			goto out;
		}

		data->publish_rrr_message = 0;

		if (*data->publish_values_from_array == '*') {
			// OK, publish full raw array
		}
		else if ((ret = rrr_instance_config_traverse_split_commas_silent_fail(config, "mqtt_publish_array_values", mqttclient_parse_publish_value_tag, data)) != 0) {
			RRR_MSG_0("Error while parsing mqtt_publish_values_from_array setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing mqtt_publish_values_from_array\n");
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->connect_error_action, config, "mqtt_connect_error_action")) == 0) {
		if (strcmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RESTART) == 0) {
		}
		else if (strcmp(data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) == 0) {
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

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_username", username);
	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_password", password);

	if (data->password != NULL && data->username == NULL) {
		RRR_MSG_0("mqtt_password set without mqtt_username being so, this in an error.\n");
		ret = 1;
		goto out;
	}

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_certificate_file", tls_certificate_file);
	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_key_file", tls_key_file);

	if (	(data->tls_certificate_file != NULL && data->tls_key_file == NULL) ||
			(data->tls_certificate_file == NULL && data->tls_key_file != NULL)
	) {
		RRR_MSG_0("Only one of mqtt_certificate_file and mqtt_key_file was specified, either both or none are required in mqttclient instance %s",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_ca_file", tls_ca_file);
	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_ca_path", tls_ca_path);
	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("mqtt_transport_type", transport_type);

	if (data->transport_type != NULL) {
		if (strcasecmp(data->transport_type, "plain") == 0) {
			data->do_transport_plain = 1;
		}
		else if (strcasecmp(data->transport_type, "tls") == 0) {
			data->do_transport_tls = 1;
		}
		else {
			RRR_MSG_0("Unknown value '%s' for mqtt_transport_type in mqttclient instance %s\n",
					data->transport_type, config->name);
			ret = 1;
			goto out;
		}
	}
	else {
		data->do_transport_plain = 1;
	}

	// Note : It's allowed not to specify a certificate
	if (data->tls_certificate_file != NULL && data->do_transport_tls == 0) {
		RRR_MSG_0("TLS certificate specified in mqtt_certificate_file but mqtt_transport_type was not 'tls' for mqttclient instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_SETTINGS_PARSE_OPTIONAL_PORT("mqtt_server_port", server_port, (
			data->do_transport_tls
				? RRR_MQTT_DEFAULT_SERVER_PORT_TLS
				: RRR_MQTT_DEFAULT_SERVER_PORT_PLAIN
	));

	// Undocumented parameter. Causes client to send UNSUBSCRIBE, wait for UNSUBACK and then
	// subscribe to all topics once more.
	if ((ret = (rrr_instance_config_check_yesno(&yesno, config, "mqtt_client_debug_unsubscribe_cycle")
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not interpret mqtt_client_debug_unsubscribe_cycle setting of instance %s, must be 'yes' or 'no'\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else if (yesno > 0) {
		data->debug_unsubscribe_cycle = 1;
		if (rrr_mqtt_subscription_collection_count(data->requested_subscriptions) == 0) {
			RRR_MSG_0("debug_unsubscribe_cycle set without any subscriptions in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
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

		struct rrr_message *reading
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
	struct mqtt_client_data *private_data = thread_data->private_data;
	struct rrr_mqtt_p_publish *publish = NULL;
	struct rrr_message *reading = (struct rrr_message *) entry->message;

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

	if (MSG_TOPIC_LENGTH(reading) > 0 && private_data->force_publish_topic == 0) {
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
		if (private_data->force_publish_topic != 0) {
			RRR_BUG("force_publish_topic was 1 but topic was not set in mqttclient_poll_callback of mqttclient\n");
		}
		RRR_MSG_0("Warning: Received message to MQTT client instance %s did not have topic set, and no default topic was defined in the configuration. Dropping message.\n",
				INSTANCE_D_NAME(thread_data));
		ret = 0;
		goto out_free;
	}

	if (publish->topic == NULL) {
		RRR_MSG_0("Could not allocate topic in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out_free;
	}

	publish->qos = private_data->qos;

	if (private_data->publish_rrr_message != 0) {
		ssize_t msg_size = MSG_TOTAL_SIZE(reading);

		reading->msg_size = msg_size;

		rrr_message_prepare_for_network(reading);

		rrr_socket_msg_checksum_and_to_network_endian((struct rrr_socket_msg *) reading);

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

		if (rrr_array_message_to_collection(&array_tmp, reading) != 0) {
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
		if ((ret = rrr_message_to_string(&payload, reading)) != 0) {
			RRR_MSG_0("could not convert message to string for PUBLISH payload in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
			goto out_free;
		}
		payload_size = strlen(payload) + 1;
	}

	if (payload != NULL) {
		if (rrr_mqtt_p_payload_new_with_allocated_payload(&publish->payload, payload, payload, payload_size) != 0) {
			RRR_MSG_0("Could not set payload of PUBLISH in mqtt client mqttclient_poll_callback of mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_free;
		}
		payload = NULL;
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
	rrr_ip_buffer_entry_unlock(entry);
	RRR_FREE_IF_NOT_NULL(payload);
	RRR_MQTT_P_DECREF_IF_NOT_NULL(publish);

	return ret;
}

static int mqttclient_try_create_rrr_message_with_publish_data (
		struct rrr_message **result,
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

	if (rrr_message_new_empty (
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

static int mqttclient_try_get_rrr_message_from_publish (
		struct rrr_message **result,
		struct rrr_mqtt_p_publish *publish,
		struct mqtt_client_data *data
) {
	int ret = 0;

	if (publish->payload == NULL) {
		goto out_nolock;
	}

	ssize_t message_actual_length = publish->payload->length;
	ssize_t message_stated_length = 0;
	struct rrr_message *message = (struct rrr_message *) publish->payload->payload_start;

	*result = NULL;

	RRR_MQTT_P_LOCK(publish->payload);

	if (message_actual_length < (ssize_t) sizeof(struct rrr_socket_msg)) {
		RRR_DBG_1("RRR Message of unknown length %li in mqtt client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_socket_msg_get_target_size_and_check_checksum (
			&message_stated_length,
			(struct rrr_socket_msg *) message,
			message_actual_length)
	) {
		RRR_DBG_1("RRR Message of size %li with corrupted header in mqtt client instance %s\n",
				message_actual_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (message_actual_length != message_stated_length) {
		RRR_DBG_1("RRR message_final size mismatch, have %li bytes but packet states %li in mqtt client instance %s\n",
				message_actual_length, message_stated_length, INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_socket_msg_head_to_host_and_verify((struct rrr_socket_msg *) message, message_actual_length) != 0) {
		RRR_DBG_1("RRR Message with invalid header in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_socket_msg_check_data_checksum_and_length((struct rrr_socket_msg *) message, message_actual_length) != 0) {
		RRR_MSG_0("RRR message_final CRC32 mismatch in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (rrr_message_to_host_and_verify(message, message_actual_length) != 0) {
		RRR_MSG_0("RRR message_final was invalid in mqtt client instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	*result = malloc(message_actual_length);
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory in mqttclient_try_get_rrr_message_from_publish\n");
		ret = 1;
		goto out;
	}
	memcpy(*result, message, message_actual_length);

	out:
	RRR_MQTT_P_UNLOCK(publish->payload);

	out_nolock:
	return ret;
}

static int mqttclient_try_create_array_message_from_publish (
		struct rrr_message **result,
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

	if ((ret = rrr_array_new_message_from_buffer (
			result,
			parsed_bytes,
			publish->payload->payload_start + read_pos,
			publish->payload->length - read_pos,
			publish->topic,
			strlen(publish->topic),
			&data->array_definition
	)) != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			RRR_MSG_0("Could not parse data array from received PUBLISH message in MQTT client instance %s, invalid data of length %i\n",
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
	const struct rrr_message *message;
};

static int mqttclient_receive_publish_create_entry_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
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
	rrr_ip_buffer_entry_unlock(entry);
	return ret;
}

static int mqttclient_receive_publish_create_and_save_entry (const struct rrr_message *message, struct mqtt_client_data *data) {
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
	struct rrr_message *message_final = NULL;

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

	// is_rrr_message is set to 1 if we want the data to be a message. It is set to zero
	// again if the data turns out not to be a message after all. If receive_rrr_message
	// is not set, data which is not auto-detected as message (V5 only) will be wrapped
	// inside a new rrr_message. If receive_rrr_message is set and the data is incorrect,
	// it will be dropped.
	int is_rrr_message = data->receive_rrr_message;
	int expecting_rrr_message = data->receive_rrr_message;

	if (content_type != NULL) {
		RRR_DBG_2 ("mqtt client %s: Received PUBLISH content type is '%s'\n",
				INSTANCE_D_NAME(data->thread_data), content_type);

		if (strcmp (content_type, RRR_MESSAGE_MIME_TYPE) == 0) {
			is_rrr_message = 1;
		}
	}

	// Try to extract a message from the data of the publish
	if (is_rrr_message != 0) {
		if ((ret = mqttclient_try_get_rrr_message_from_publish (
				&message_final,
				publish,
				data
		)) != 0) {
			RRR_MSG_0("Error while parsing RRR message in receive_publish of mqtt client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}

		if (message_final == NULL && expecting_rrr_message != 0) {
			RRR_MSG_0("Received supposed RRR message_final turned out not to be, dropping it in mqtt client instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		else if (message_final != NULL) {
			goto out_write_to_buffer;
		}
	}

	// Try to create an array message with the data from the publish (if specified in configuration)
	if (rrr_array_count(&data->array_definition) > 0) {
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
	if ((ret = mqttclient_try_create_rrr_message_with_publish_data (
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
	if (rrr_message_new_with_data (
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

	if (rrr_mqtt_client_subscribe (
			data->mqtt_client_data,
			&data->session,
			data->requested_subscriptions
	) != 0) {
		RRR_MSG_0("Could not subscribe to topics in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		return 1;
	}
	return 0;
}

static int mqttclient_do_unsubscribe (struct mqtt_client_data *data) {
	if (data->received_unsuback_packet_id != 0) {
		RRR_BUG("received_unsuback_packet_id was not 0 in mqtt client do_subscribe\n");
	}

	if (rrr_mqtt_client_unsubscribe (
			data->mqtt_client_data,
			&data->session,
			data->requested_subscriptions
	) != 0) {
		RRR_MSG_0("Could not unsubscribe to topics in mqtt client instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		return 1;
	}
	return 0;
}

static int mqttclient_subscription_loop (struct mqtt_client_data *data) {
	uint64_t subscription_sent_time = 0;
	int subscription_send_attempts = 0;
	int subscription_done = 0;

	uint64_t unsubscription_sent_time = 0;
	int unsubscription_send_attempts = 0;
	int unsubscription_done = 0;

	if (rrr_mqtt_subscription_collection_count(data->requested_subscriptions) == 0) {
		return 0;
	}

	// Subscription loop
	while (rrr_thread_check_encourage_stop(data->thread_data->thread) != 1) {
		int alive = 0;
		int send_allowed = 0;

		if (rrr_mqtt_client_connection_check_alive (
				&alive,
				&send_allowed,
				data->mqtt_client_data,
				data->transport_handle
		)) {
			RRR_MSG_0("Error in mqtt client instance %s while checking for connection alive\n",
					INSTANCE_D_NAME(data->thread_data));
			return 1;
		}

		if (alive != 1) {
			return 1;
		}

		if (subscription_done == 0) {
			if (subscription_sent_time == 0) {
				if (send_allowed != 0) {
					data->received_suback_packet_id = 0;
					if (mqttclient_do_subscribe(data) != 0) {
						return 1;
					}
					subscription_send_attempts++;
					subscription_sent_time = rrr_time_get_64();
				}
			}
			else if (data->received_suback_packet_id != 0) {
				subscription_done = 1;
			}
			else if (rrr_time_get_64() > subscription_sent_time + (RRR_MQTT_SUBACK_RESEND_TIMEOUT_MS * 1000)) {
				if (subscription_send_attempts > RRR_MQTT_SUBACK_RESEND_MAX) {
					RRR_MSG_0("MQTT client %s giving up waiting for SUBACK\n", INSTANCE_D_NAME(data->thread_data));
					return 1;
				}

				subscription_sent_time = 0;
				RRR_MSG_0("MQTT client %s timeout while waiting for SUBACK, retry\n", INSTANCE_D_NAME(data->thread_data));
			}
		}
		else if (data->debug_unsubscribe_cycle != 0 && unsubscription_done == 0) {
			if (unsubscription_sent_time == 0) {
				if (send_allowed != 0) {
					data->received_unsuback_packet_id = 0;
					if (mqttclient_do_unsubscribe(data) != 0) {
						return 1;
					}
					unsubscription_send_attempts++;
					unsubscription_sent_time = rrr_time_get_64();
				}
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
					return 1;
				}

				unsubscription_sent_time = 0;
				RRR_MSG_0("MQTT client %s timeout while waiting for SUBACK, retry\n", INSTANCE_D_NAME(data->thread_data));
			}
		}
		else {
			break;
		}

		int something_happened = 0;
		if (rrr_mqtt_client_synchronized_tick(&something_happened, data->mqtt_client_data) != 0) {
			RRR_MSG_0("Error in mqtt client instance %s while running tasks\n",
					INSTANCE_D_NAME(data->thread_data));
			return 1;
		}

		if (something_happened == 0) {
			rrr_posix_usleep (50000); // 50 ms
		}
	}

	return 0;
}

static int mqttclient_connect_loop (struct mqtt_client_data *data, int clean_start) {
	int i_first = data->connect_attempts;
	if (i_first < 1 || (uint64_t) i_first != (uint64_t) data->connect_attempts) {
		i_first = 0x7fffffff; // One 7, seven f's
		RRR_MSG_0("Warning: Connection attempt parameter overflow for mqtt client instance %s, changed to %i\n",
				INSTANCE_D_NAME(data->thread_data), i_first);
	}

	reconnect:

	data->transport_handle = 0;
	data->session = NULL;

	for (int i = i_first; i >= 0 && rrr_thread_check_encourage_stop(data->thread_data->thread) != 1; i--) {
		rrr_thread_update_watchdog_time(data->thread_data->thread);

		RRR_DBG_1("MQTT client instance %s attempting to connect to server '%s' port '%llu' attempt %i/%i\n",
				INSTANCE_D_NAME(data->thread_data), data->server, data->server_port, i, i_first);

		if (rrr_mqtt_client_connect (
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
		) != 0) {
			if (i == 0) {
				if (strcmp (data->connect_error_action, RRR_MQTT_CONNECT_ERROR_DO_RETRY) == 0) {
					RRR_MSG_0("MQTT client instance %s: %i connection attempts failed, trying again.\n",
							INSTANCE_D_NAME(data->thread_data),
							i_first
					);
					goto reconnect;
				}

				RRR_MSG_0("Could not connect to mqtt server '%s' port %llu in instance %s, restarting.\n",
						data->server, data->server_port, INSTANCE_D_NAME(data->thread_data));

				return 1;
			}
			rrr_posix_usleep (100 * 1000);
		}
		else {
			break;
		}
	}

	return 0;
}

static void mqttlient_update_stats (
		struct mqtt_client_data *data,
		struct rrr_stats_instance *stats
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

	// These will always be zero for the client, nothing is forwarded. Keep it here nevertheless to avoid accidently activating it.
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_forwarded", 0, client_stats.session_stats.total_publish_forwarded);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_received", 0, client_stats.session_stats.total_publish_received);
	// rrr_stats_instance_post_unsigned_base10_text(stats, "total_publish_not_forwarded", 0, client_stats.session_stats.total_publish_not_forwarded);
}

static void *thread_entry_mqtt_client (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct mqtt_client_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll;

	int init_ret = 0;
	if ((init_ret = mqttclient_data_init(data, thread_data)) != 0) {
		RRR_MSG_0("Could not initalize data in mqtt client instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	RRR_DBG_1 ("mqtt client thread data is %p\n", thread_data);

	rrr_poll_collection_init(&poll);
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll);
	pthread_cleanup_push(mqttclient_data_cleanup, data);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (mqttclient_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for mqtt client instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	// TODO : Support zero-byte client identifier
	struct rrr_mqtt_common_init_data init_data = {
		data->client_identifier,
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

	rrr_poll_add_from_thread_senders(&poll, thread_data);

	if (rrr_poll_collection_count(&poll) == 0) {
		if (data->publish_topic != NULL) {
			RRR_MSG_0("Warning: mqtt client instance %s has publish topic set but there are not senders specified in configuration\n",
					INSTANCE_D_NAME(thread_data));
		}
	}

	RRR_DBG_1 ("mqtt client started thread %p\n", thread_data);

	if (rrr_mqtt_property_collection_add_uint32(
			&data->connect_properties,
			RRR_MQTT_PROPERTY_RECEIVE_MAXIMUM,
			0xffff
	) != 0) {
		RRR_MSG_0("Could not set CONNECT properties in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	if (data->do_transport_plain && rrr_mqtt_client_start_plain(data->mqtt_client_data) != 0) {
		RRR_MSG_0("Could not start plain network transport in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}
	else if (data->do_transport_tls && rrr_mqtt_client_start_tls(
			data->mqtt_client_data,
			data->tls_certificate_file,
			data->tls_key_file,
			data->tls_ca_file,
			data->tls_ca_path
	) != 0) {
		RRR_MSG_0("Could not start tls network transport in mqtt client instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	if ((data->do_transport_plain ^ data->do_transport_tls) != 1) {
		RRR_BUG("BUG: No transport or both transports started in mqttclient, configuration parse bug\n");
	}

	// We have do use clean start the first time we connect as the server
	// might remember packets from our last session (if any)
	int clean_start = 1;

	reconnect:

	if (mqttclient_connect_loop(data, clean_start) != 0) {
		goto out_destroy_client;
	}

	if (mqttclient_subscription_loop(data) != 0) {
		goto out_destroy_client;
	}

	uint64_t startup_time = rrr_time_get_64() + RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS * 1000;

	RRR_DBG_1("MQTT client %s startup send grace period %i ms started\n",
			INSTANCE_D_NAME(data->thread_data),
			RRR_MQTT_STARTUP_SEND_GRACE_TIME_MS
	);

	// Successive connect attempts or re-connect does not require clean start to be set. Server
	// will respond with CONNACK with session present=0 if we need to clean up our state.
	clean_start = 0;

	RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES;

	// Main loop
	uint64_t prev_stats_time = rrr_time_get_64();
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		uint64_t time_now = rrr_time_get_64();
		rrr_thread_update_watchdog_time(thread_data->thread);

		int alive = 0;
		int send_allowed = 0;
		if (rrr_mqtt_client_connection_check_alive(
				&alive,
				&send_allowed,
				data->mqtt_client_data,
				data->transport_handle
		)) {
			RRR_MSG_ERR("Error in mqtt client instance %s while checking for connection alive\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_client;
		}

		if (alive == 0) {
			RRR_MSG_0("Connection lost for mqtt client instance %s, reconnecting\n",
				INSTANCE_D_NAME(thread_data));
			goto reconnect;
		}

		int something_happened = 0;

		if (rrr_mqtt_client_synchronized_tick(&something_happened, data->mqtt_client_data) != 0) {
			RRR_MSG_ERR("Error in mqtt client instance %s while running tasks\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_client;
		}

		if (rrr_mqtt_client_iterate_and_clear_local_delivery(data->mqtt_client_data, mqttclient_receive_publish, data) != 0) {
			RRR_MSG_ERR("Error while iterating local delivery queue in mqtt client instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_client;
		}

		if (something_happened == 0) {
			data->total_usleep_count++;
			rrr_posix_usleep (50000); // 50 ms
			if (startup_time == 0 || rrr_time_get_64() > startup_time) {
				rrr_poll_do_poll_delete (thread_data, &poll, mqttclient_poll_callback, 0);

				startup_time = 0;
			}
		}
		data->total_ticks_count++;

		if (time_now > (prev_stats_time + RRR_MQTT_CLIENT_STATS_INTERVAL_MS * 1000)) {
			mqttlient_update_stats(data, stats);
			prev_stats_time = rrr_time_get_64();
		}
	}

	out_destroy_client:
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
	out_message:
		RRR_DBG_1 ("Thread mqtt client %p exiting\n", thread_data->thread);
//		pthread_cleanup_pop(1);
		RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
		pthread_cleanup_pop(1);
		pthread_cleanup_pop(1);
		pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_mqtt_client,
		NULL,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "mqtt_client";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
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

