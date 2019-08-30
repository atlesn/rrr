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
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/ip.h"
#include "../lib/utf8.h"
#include "../lib/linked_list.h"
#include "../global.h"

#define RRR_MQTT_DEFAULT_SERVER_PORT 1883
#define RRR_MQTT_DEFAULT_QOS 1
#define RRR_MQTT_DEFAULT_VERSION 4 // 3.1.1

struct mqtt_client_topic {
	RRR_LINKED_LIST_NODE(struct mqtt_client_topic);
	char topic[1];
};

struct mqtt_client_topic_list {
	RRR_LINKED_LIST_HEAD(struct mqtt_client_topic);
};

struct mqtt_client_data {
	struct instance_thread_data *thread_data;
	struct fifo_buffer output_buffer;
	struct rrr_mqtt_client_data *mqtt_client_data;
	rrr_setting_uint server_port;
	struct mqtt_client_topic_list topic_list;
	char *server;
	char *publish_topic;
	char *version_str;
	char *client_identifier;
	uint8_t qos;
	uint8_t version;
	struct rrr_mqtt_conn *connection;
};

static int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
//	struct mqtt_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	VL_DEBUG_MSG_2 ("mqtt: Result from buffer: %s measurement %" PRIu64 " size %lu, discarding data\n", reading->data, reading->data_numeric, size);

	free(data);

	// fifo_buffer_write(&private_data->output_buffer, data, size);

	return 0;
}

static void data_cleanup(void *arg) {
	struct mqtt_client_data *data = arg;
	fifo_buffer_invalidate(&data->output_buffer);
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->publish_topic);
	RRR_FREE_IF_NOT_NULL(data->version_str);
	RRR_FREE_IF_NOT_NULL(data->client_identifier);
	RRR_LINKED_LIST_DESTROY(&data->topic_list,struct mqtt_client_topic,free(node));
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

	struct mqtt_client_topic *topic = malloc(sizeof(*topic) + strlen(topic_str) + 1);
	if (topic == NULL) {
		VL_MSG_ERR("Could not allocate memory in parse_sub_topic\n");
		return 1;
	}

	strcpy(topic->topic, topic_str);

	RRR_LINKED_LIST_APPEND(&data->topic_list,topic);

	return 0;
}

// TODO : Provide more configuration arguments
static int parse_config (struct mqtt_client_data *data, struct rrr_instance_config *config) {
	int ret = 0;

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
		data->version = 3;
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
			NULL
		) != 0) {
		VL_MSG_ERR("Could not create new mqtt client\n");
		goto out_message;
	}

	pthread_cleanup_push(rrr_mqtt_client_destroy_void, data->mqtt_client_data);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE);

	if (poll_collection_count(&poll) > 0) {
		if (data->publish_topic == NULL || *(data->publish_topic) == '\0') {
			VL_MSG_ERR("mqtt client instance %s has senders specified but no publish topic (mqtt_publish_topic) is set in configuration\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_client;
		}
	}
	else {
		if (data->publish_topic != NULL) {
			VL_MSG_ERR("mqtt client instance %s has publish topic set but there are not senders specified in configuration\n",
					INSTANCE_D_NAME(thread_data));
			goto out_destroy_client;
		}
	}

	VL_DEBUG_MSG_1 ("mqtt client started thread %p\n", thread_data);

	if (rrr_mqtt_client_connect (
			&data->connection,
			data->mqtt_client_data,
			data->server,
			data->server_port,
			data->version,
			RRR_MQTT_CLIENT_KEEP_ALIVE,
			0 // <-- Clean start
	) != 0) {
		VL_MSG_ERR("Could not connect to mqtt server '%s' port %llu in instance %s\n",
				data->server, data->server_port, INSTANCE_D_NAME(thread_data));
		goto out_destroy_client;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		// TODO : Figure out what to do with data from local senders

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		if (rrr_mqtt_client_synchronized_tick(data->mqtt_client_data) != 0) {
			VL_MSG_ERR("Error from MQTT client while running tasks\n");
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

