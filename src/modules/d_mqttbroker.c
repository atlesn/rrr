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

#include "../lib/mqtt_broker.h"
#include "../lib/mqtt_common.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/settings.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/ip.h"
#include "../global.h"

#define RRR_MQTT_SERVER_PORT 1883
#define RRR_MQTT_BROKER_MAX_CONNECTIONS 100

struct mqtt_data {
	struct fifo_buffer local_buffer;
	struct rrr_mqtt_broker_data *mqtt_broker_data;
	rrr_setting_uint server_port;
};

static int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct mqtt_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	VL_DEBUG_MSG_2 ("mqtt: Result from buffer: %s measurement %" PRIu64 " size %lu, discarding data\n", reading->data, reading->data_numeric, size);

	free(data);

	// fifo_buffer_write(&private_data->local_buffer, data, size);

	return 0;
}

static void data_cleanup(void *arg) {
	struct mqtt_data *data = arg;
	fifo_buffer_invalidate(&data->local_buffer);
	rrr_mqtt_broker_destroy(data->mqtt_broker_data);
}

static int data_init(struct mqtt_data *data) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;

	ret |= fifo_buffer_init(&data->local_buffer);

	if (ret != 0) {
		VL_MSG_ERR("Could not initialize fifo buffer in mqttbroker data_init\n");
		goto out;
	}

	if ((ret = rrr_mqtt_broker_new(&data->mqtt_broker_data)) != 0) {
		VL_MSG_ERR("Could not create new mqtt broker\n");
		goto out;
	}

	out:
	if (ret != 0) {
		data_cleanup(data);
	}

	return ret;
}

// TODO : Provide more configuration arguments
static int parse_config (struct mqtt_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint mqtt_port = 0;

	if ((ret = rrr_instance_config_read_unsigned_integer(&mqtt_port, config, "mqtt_server_port")) == 0) {
		// OK
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		VL_MSG_ERR("Error while parsing mqtt_server_port setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		mqtt_port = RRR_MQTT_SERVER_PORT;
		ret = 0;
	}

	data->server_port = mqtt_port;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void *thread_entry_mqtt (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct mqtt_data* data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	int init_ret = 0;
	if ((init_ret = data_init(data)) != 0) {
		VL_MSG_ERR("Could not initalize data in mqtt instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("mqtt thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parse failed for mqtt instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE);

	VL_DEBUG_MSG_1 ("mqtt started thread %p\n", thread_data);

	if (rrr_mqtt_broker_listen_ipv4_and_ipv6(data->mqtt_broker_data, data->server_port, RRR_MQTT_BROKER_MAX_CONNECTIONS) != 0) {
		VL_MSG_ERR("Could not start network in mqtt broker instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		// TODO : Figure out what to do with data from local senders

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		usleep (5000); // 50 ms
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread mqtt %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct mqtt_data data;
	int ret = 0;
	if ((ret = data_init(&data)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_mqtt,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "mqtt";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_DEADEND;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = VL_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy mqtt module\n");
}

