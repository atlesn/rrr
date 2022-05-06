/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <stdio.h>

#include "../build_timestamp.h"
#include "main.h"
#include "lib/allocator.h"
#include "lib/common.h"
#include "lib/version.h"
#include "lib/log.h"
#include "lib/rrr_strerror.h"
#include "lib/cmdlineparser/cmdline.h"
#include "lib/mqtt/mqtt_client.h"
#include "lib/mqtt/mqtt_subscription.h"
#include "lib/mqtt/mqtt_packet.h"
#include "lib/socket/rrr_socket.h"
#include "lib/net_transport/net_transport_config.h"
#include "lib/util/rrr_time.h"
#include "lib/util/arguments.h"
#include "lib/messages/msg.h"
#include "lib/messages/msg_msg.h"
#include "lib/messages/msg_dump.h"

#define RRR_MQTT_SUB_TOPICS_MAX 64
#define RRR_MQTT_DISCONNECT_TIMEOUT_S 5

RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("rrr_sub");

static const struct cmd_arg_rule cmd_rules[] = {
        {CMD_ARG_FLAG_NO_FLAG_MULTI,   '\0',   "topic",                "[TOPIC]..."},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'B',    "broker",               "[-B|--broker]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'P',    "port",                 "[-P|--port]"},
	{CMD_ARG_FLAG_HAS_ARGUMENT,    'Q',    "qos",                  "[-Q|--qos]"},
	{0,                            '3',    "protocol-v3",          "[-3|--protocol-v3]"},
	{0,                            '5',    "protocol-v5",          "[-5|--protocol-v5]"},
        {0,                            'l',    "loglevel-translation", "[-l|--loglevel-translation]"},
        {0,                            'b',    "banner",               "[-b|--banner]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'e',    "environment-file",     "[-e|--environment-file[=]ENVIRONMENT FILE]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'd',    "debuglevel",           "[-d|--debuglevel[=]DEBUG FLAGS]"},
        {CMD_ARG_FLAG_HAS_ARGUMENT,    'D',    "debuglevel-on-exit",   "[-D|--debuglevel-on-exit[=]DEBUG FLAGS]"},
        {0,                            'h',    "help",                 "[-h|--help]"},
        {0,                            'v',    "version",              "[-v|--version]"},
        {0,                            '\0',    NULL,                  NULL}
};

struct rrr_sub_data {
	struct rrr_mqtt_subscription_collection topics;
	char *broker;
	uint16_t port;

	uint8_t use_v3;
	uint8_t use_v5;

	uint8_t ban_v5;

	uint8_t qos;

	struct rrr_mqtt_property_collection connect_properties;
	struct rrr_mqtt_client_data *mqtt_client;

	int transport_handle;
	struct rrr_mqtt_session *session;

	uint64_t disconnect_time;
	uint64_t subscriptions_send_time;
};

static void __rrr_sub_data_cleanup (
		struct rrr_sub_data *data
) {
	RRR_FREE_IF_NOT_NULL(data->broker);
	rrr_mqtt_client_destroy(data->mqtt_client);
	rrr_mqtt_subscription_collection_clear(&data->topics);
	rrr_mqtt_property_collection_clear(&data->connect_properties);
}

static int __rrr_sub_suback_unsuback_handler (struct rrr_mqtt_client_data *client, struct rrr_mqtt_p_suback_unsuback *packet, void *arg) {
	struct rrr_sub_data *data = arg;

	(void)(client);
	(void)(packet);
	(void)(data);

	return RRR_MQTT_OK;
}

static int __rrr_sub_packet_parsed_handler (struct rrr_mqtt_client_data *client, struct rrr_mqtt_p *packet, void *arg) {
	struct rrr_sub_data *data = arg;

	(void)(client);
	(void)(packet);
	(void)(data);

	return RRR_MQTT_OK;
}

static void __rrr_sub_receive_publish (struct rrr_mqtt_p_publish *publish, void *arg) {
	struct rrr_sub_data *data = arg;

	(void)(data);

	struct rrr_msg *msg_tmp = NULL;
	rrr_length msg_target_size = 0;

	RRR_DBG_2("> Received PUBLISH with topic %s\n", publish->topic);

	if (rrr_msg_get_target_size_and_check_checksum (
			&msg_target_size,
			(const struct rrr_msg *) publish->payload->payload_start,
			publish->payload->length
	) == 0) {
		if (msg_target_size != publish->payload->length) {
			RRR_DBG_2("> Incorrect size or incomplete RRR message, ignoring\n");
			goto out;
		}

		if ((msg_tmp = rrr_allocate(publish->payload->length)) == NULL) {
			RRR_MSG_0("Warning: Failed to allocate %" PRIrrrl " bytes in %s\n", publish->payload->length, __func__);
			goto out;
		}
		memcpy(msg_tmp, publish->payload->payload_start, publish->payload->length);

		if (rrr_msg_dump_to_host_and_dump(msg_tmp, publish->payload->length) != 0) {
			RRR_MSG_0("Failed to dump RRR message\n");
		}
	}
	else if (publish->payload->length > 0) {
		rrr_log_printn_plain(publish->payload->payload_start, publish->payload->length);
		rrr_log_printn_plain("\n", 1);
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_tmp);
}

static int __rrr_sub_init (
		struct rrr_sub_data *data,
		struct cmd_data *cmd,
		struct rrr_event_queue *events,
		struct rrr_mqtt_common_init_data *mqtt_init_data
) {
	int ret = 0;

	// Broker address
	if ((data->broker = strdup(cmd_exists(cmd, "broker", 0)
		? cmd_get_value(cmd, "broker", 0)
		: "localhost"
	)) == NULL) {
		RRR_MSG_0("Failed to allocate memory for broker in %s\n", __func__);
		ret = 1;
		goto out;
	}

	// Broker port
	if ((ret = rrr_arguments_parse_port (
			&data->port,
			cmd,
			"port",
			1883
	)) != 0) {
		goto out;
	}

	// QoS
	if (cmd_exists(cmd, "qos", 0)) {
		if (cmd_exists(cmd, "qos", 1)) {
			RRR_MSG_0("Multiple --qos arguments was specified\n");
			ret = 1;
			goto out;
		}

		const char *qos = cmd_get_value(cmd, "qos", 0);
		if (strcmp(qos, "2") == 0) {
			data->qos = 2;
		}
		else if (strcmp(qos, "1") == 0) {
			data->qos = 1;
		}
		else if (strcmp(qos, "0") == 0) {
			data->qos = 0;
		}
		else {
			RRR_MSG_0("Invalid value '%s' for argument --qos given\n", qos);
			ret = 1;
			goto out;
		}
	}

	// V3, V5 or both
	const int v3 = cmd_exists(cmd, "protocol-v3", 0);
	const int v5 = cmd_exists(cmd, "protocol-v5", 0);

	if (v3 || v5) {
		data->use_v3 = v3 != 0;
		data->use_v5 = v5 != 0;
	}
	else {
		data->use_v3 = 1;
		data->use_v5 = 1;
	}

	// Subscribe topics
	for (unsigned long i = 0; i <= RRR_MQTT_SUB_TOPICS_MAX; i++) {
		if (i == RRR_MQTT_SUB_TOPICS_MAX) {
			RRR_MSG_0("Too many topics given (max is %i)\n", RRR_MQTT_SUB_TOPICS_MAX);
			ret = 1;
			goto out_cleanup_broker;
		}
		if (cmd_exists(cmd, "topic", i)) {
			const char *topic = cmd_get_value(cmd, "topic", i);
			if ((ret = rrr_mqtt_subscription_collection_push_unique_str (
					&data->topics,
					topic,
					0,
					0,
					0,
					data->qos
			)) != 0) {
				goto out;
			}
		}
		else {
			break;
		}
	}

	if ((ret = rrr_mqtt_client_new (
			&data->mqtt_client,
			mqtt_init_data,
			events,
			rrr_mqtt_session_collection_ram_new_client,
			NULL,
			__rrr_sub_suback_unsuback_handler,
			&data,
			__rrr_sub_packet_parsed_handler,
			&data,
			__rrr_sub_receive_publish,
			&data
	)) != 0) {
		goto out_cleanup_topic;
	}

	goto out;
	out_cleanup_topic:
		rrr_mqtt_subscription_collection_clear(&data->topics);
	out_cleanup_broker:
		RRR_FREE_IF_NOT_NULL(data->broker);
	out:
		return ret;
}

static int main_running = 1;

int rrr_signal_handler(int s, void *arg) {
	return rrr_signal_default_handler(&main_running, s, arg);
}

static int __rrr_sub_periodic(RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_sub_data *data = arg;

	int alive = 0;
	int send_allowed = 0;
	int close_wait = 0;

	int ret_tmp;

	if (data->transport_handle > 0 && (ret_tmp = rrr_mqtt_client_connection_check_alive (
			&alive,
			&send_allowed,
			&close_wait,
			data->mqtt_client,
			data->transport_handle
	)) != 0) {
		printf("Alive: %i\n", ret_tmp);
		return RRR_EVENT_ERR;
	}

	if (data->disconnect_time > 0) {
		if (!alive && !close_wait) {
			RRR_DBG_1("| Disconnect complete\n");
			return RRR_EVENT_EXIT;
		}
		else if (rrr_time_get_64() > data->disconnect_time + RRR_MQTT_DISCONNECT_TIMEOUT_S * 1000 * 1000) {
			RRR_DBG_1("| Disconnect timeout\n");
			return RRR_EVENT_EXIT;
		}
	}
	else if (!alive && main_running) {
		RRR_DBG_1("| Connecting to broker...\n");

		data->subscriptions_send_time = 0;
		data->disconnect_time = 0;

		const uint8_t protocol_version = data->ban_v5 && data->use_v3
			? 4
			: data->use_v5
				? 5
				: 4
		;

		// Ban v5 every other connection attempt
		data->ban_v5 = !data->ban_v5;

		if ((ret_tmp = rrr_mqtt_client_connect (
				&data->transport_handle,
				&data->session,
				data->mqtt_client,
				data->broker,
				(uint16_t) data->port,
				protocol_version,
				30,   // Keep-alive
				1,    // Clean start,
				NULL, // Username
				NULL, // Password
				&data->connect_properties,
				NULL, // Will topic
				NULL, // Will message
				0,    // Will QoS
				0     // Will retain
		)) != 0) {
			if (ret_tmp == RRR_MQTT_SOFT_ERROR) {
				RRR_MSG_0("Connection to %s:%i failed, trying again\n",
					data->broker, data->port);
			}
			else {
				RRR_MSG_0("Connection to %s:%i failed, critical error\n",
					data->broker, data->port);
				return RRR_EVENT_ERR;
			}
		}
	}
	else if (send_allowed) {
		if (!main_running) {
			RRR_DBG_1("| Disconnecting...\n");
			data->disconnect_time = rrr_time_get_64();

			if ((ret_tmp = rrr_mqtt_client_disconnect (
					data->mqtt_client,
					data->transport_handle,
					0 // Reason
			)) != 0 && ret_tmp != RRR_MQTT_INCOMPLETE) {
				return RRR_EVENT_ERR;
			}
		}
		else if (!data->subscriptions_send_time) {
			RRR_DBG_1("| Sending subscriptions...\n");
			data->subscriptions_send_time = rrr_time_get_64();

			if ((ret_tmp = rrr_mqtt_client_subscribe (
					data->mqtt_client,
					&data->session,
					&data->topics
			)) != 0) {
				return RRR_EVENT_ERR;
			}
		}
	}
	else if (!main_running) {
		RRR_DBG_1("| Exiting\n");
		return RRR_EVENT_EXIT;
	}

	return RRR_EVENT_OK;
}

int main (int argc, const char **argv, const char **env) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		fprintf(stderr, "Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	int ret = EXIT_SUCCESS;

	struct rrr_signal_handler *signal_handler = NULL;
	struct rrr_net_transport_config net_transport_config = RRR_NET_TRANSPORT_CONFIG_PLAIN_INITIALIZER;

	if (rrr_allocator_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_destroy_net_transport_config;
	}

	if (rrr_log_init() != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	rrr_strerror_init();

	rrr_signal_default_signal_actions_register();
	signal_handler = rrr_signal_handler_push(rrr_signal_handler, NULL);
	rrr_signal_handler_set_active (RRR_SIGNALS_ACTIVE);

	struct cmd_data cmd;
	struct rrr_sub_data data = {0};
	struct rrr_event_queue *events = NULL;
	struct rrr_mqtt_common_init_data mqtt_init_data = {
		NULL, /* Client name */
		RRR_MQTT_COMMON_RETRY_INTERVAL_S * 1000 * 1000,
		RRR_MQTT_COMMON_CLOSE_WAIT_TIME_S * 1000 * 1000,
		RRR_MQTT_COMMON_MAX_CONNECTIONS
	};

	cmd_init(&cmd, cmd_rules, argc, argv);

	if (rrr_main_parse_cmd_arguments_and_env(&cmd, env, CMD_CONFIG_DEFAULTS) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_allocator;
	}

	if (rrr_main_print_banner_help_and_version(&cmd, 1) != 0) {
		goto out_cleanup_cmd;
	}

	if (rrr_event_queue_new(&events) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_cmd;
	}

	if (__rrr_sub_init (
			&data,
			&cmd,
			events,
			&mqtt_init_data
	) != 0) {
		ret = EXIT_FAILURE;
		goto out_destroy_event;
	}

	if (rrr_mqtt_client_start(data.mqtt_client, &net_transport_config) != 0) {
		ret = EXIT_FAILURE;
		goto out_cleanup_data;
	}

	if (rrr_event_dispatch (
			events,
			250 * 1000, // 250 ms
			__rrr_sub_periodic,
			&data
	) != 0) {
		ret = EXIT_FAILURE;
	}

	rrr_signal_handler_set_active(RRR_SIGNALS_NOT_ACTIVE);
	rrr_signal_handler_remove(signal_handler);
	rrr_config_set_debuglevel_on_exit();

	out_cleanup_data:
		__rrr_sub_data_cleanup(&data);
	out_destroy_event:
		rrr_event_queue_destroy(events);
	out_cleanup_cmd:
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
	out_cleanup_allocator:
		rrr_allocator_cleanup();
	out_destroy_net_transport_config:
		rrr_net_transport_config_cleanup(&net_transport_config);
		return ret;
}
