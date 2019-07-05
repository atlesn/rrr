/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>
#include <inttypes.h>
#include <src/lib/types.h>
#include <unistd.h>

#include "../lib/settings.h"
#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/ip.h"
#include "../lib/vl_time.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../global.h"

#define RRR_UDPREADER_DEFAULT_PORT 2222

struct udpreader_data {
	struct fifo_buffer buffer;
	struct fifo_buffer inject_buffer;
	unsigned int listen_port;
	struct ip_data ip;
	struct rrr_type_definition_collection definitions;
	struct rrr_data_collection *tmp_type_data;
};

void type_data_cleanup(void *arg) {
	if (arg != NULL) {
		rrr_types_destroy_data(arg);
	}
}

void data_init(struct udpreader_data *data) {
	memset(data, '\0', sizeof(*data));

	fifo_buffer_init(&data->buffer);
	fifo_buffer_init(&data->inject_buffer);
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct udpreader_data *data = (struct udpreader_data *) arg;
	fifo_buffer_invalidate(&data->buffer);
	fifo_buffer_invalidate(&data->inject_buffer);
	if (data->tmp_type_data != NULL) {
		rrr_types_destroy_data(data->tmp_type_data);
	}
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
}

static int poll_delete (
		struct instance_thread_data *data,
		int (*callback)(struct fifo_callback_args *poll_data, char *data, unsigned long int size),
		struct fifo_callback_args *caller_data
) {
	struct udpreader_data *udpreader_data = data->private_data;
	return fifo_read_clear_forward(&udpreader_data->buffer, NULL, callback, caller_data);
}

static int poll (
		struct instance_thread_data *data,
		int (*callback)(struct fifo_callback_args *poll_data, char *data, unsigned long int size),
		struct fifo_callback_args *poll_data
) {
	struct udpreader_data *udpreader_data = data->private_data;
	return fifo_search(&udpreader_data->buffer, callback, poll_data);
}

int config_parse_port (struct udpreader_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint tmp_uint;
	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "udpr_port");

	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			VL_MSG_ERR("Could not parse udpr_port for instance %s\n", config->name);
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Could not find required udpr_port setting for instance %s\n", config->name);
		}
		else {
			VL_MSG_ERR("Error while parsing udpr port setting for instance %s\n", config->name);
		}
		ret = 1;
		goto out;
	}

	data->listen_port = tmp_uint;

	out:
	return ret;
}

int parse_config (struct udpreader_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	// Parse listen port
	if ((ret = config_parse_port (data, config)) != 0) {
		goto out;
	}

	// Parse expected input data
	if (rrr_types_parse_definition (&data->definitions, config, "udpr_input_types") != 0) {
		VL_MSG_ERR("Could not parse command line argument udpr_input_types in udpreader\n");
		return 1;
	}

	if (data->definitions.count == 0) {
		VL_MSG_ERR("No data types defined in udpr_input_types\n");
		return 1;
	}

	out:
	return ret;
}

void free_message(void *msg) {
	if (msg != NULL) {
		free(msg);
	}
}

int read_data_callback (struct ip_buffer_entry *entry, void *arg) {
	struct udpreader_data *data = arg;

	// ATTENTION! - Received ip message does not contain a vl_message struct
	if (rrr_types_parse_data(data->tmp_type_data, entry->data.data, entry->data_length) != 0) {
		VL_MSG_ERR("udpreader received an invalid packet\n");
		free (entry);
		return 0;
	}
	else {
		VL_DEBUG_MSG_2("udpreader received a valid packet in callback\n");
	}
	free (entry);

	struct vl_message *message = NULL;
	pthread_cleanup_push(free_message,message);

	uint64_t timestamp = time_get_64();
	message = rrr_types_create_message(data->tmp_type_data, timestamp);

	if (message != NULL) {
		fifo_buffer_write(&data->buffer, (char*)message, sizeof(*message));

		VL_DEBUG_MSG_3("udpreader created a message with timestamp %llu size %lu\n", (long long unsigned int) message->timestamp_from, (long unsigned int) sizeof(*message));

		message = NULL;
	}

	pthread_cleanup_pop(0);

	return 0;
}

int inject_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct udpreader_data *udpreader_data = poll_data->private_data;
	return read_data_callback((struct ip_buffer_entry *) data, udpreader_data);
}

int read_data(struct udpreader_data *data) {
	int ret = 0;

	ret |= ip_receive_packets (
		data->ip.fd,
		read_data_callback,
		data,
		NULL
	);

	struct fifo_callback_args callback_data = {NULL, data, 0};
	ret |= fifo_read_clear_forward(&data->inject_buffer, NULL, inject_callback, &callback_data);

	ret = (ret != 0 ? 1 : 0);

	return ret;
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	struct udpreader_data *data = thread_data->private_data;
	VL_DEBUG_MSG_2("udpreader: writing data from inject function\n");

	if (data->inject_buffer.invalid) {
		return 1;
	}

	fifo_buffer_write(&data->inject_buffer, (char *) message, sizeof(*message));

	return 0;
}


static void *thread_entry_udpreader(struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct udpreader_data *data = thread_data->private_data = thread_data->private_memory;

	thread_data->thread = start_data->thread;

	data_init(data);

	VL_DEBUG_MSG_1 ("UDPreader thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);
	pthread_cleanup_push(type_data_cleanup, data->tmp_type_data);

	int config_error = 0;
	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parsing failed for udpreader instance %s\n", thread_data->init_data.module->instance_name);
		config_error = 1;
	}
	else {
		data->tmp_type_data = rrr_types_allocate_data(&data->definitions);
	}

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (config_error) {
		goto out_message;
	}

	pthread_cleanup_push(ip_network_cleanup, &data->ip);

	data->ip.port = data->listen_port;
	if (ip_network_start(&data->ip) != 0) {
		VL_MSG_ERR("Could not initialize network in udpreader\n");
		pthread_exit(0);
	}
	VL_DEBUG_MSG_2("udpreader: listening on port %d\n", data->listen_port);

	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		//		struct vl_message *reading = message_new_reading(time, time);

		VL_DEBUG_MSG_2("udpreader: reading from network\n");

		if (read_data(data) != 0) {
			break;
		}

/*		fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading)); */

		usleep (50000); // 10 ms
	}

	pthread_cleanup_pop(1);

	out_message:

	VL_DEBUG_MSG_1 ("udpreader %s received encourage stop\n", thread_data->init_data.instance_config->name);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct udpreader_data data;
	data_init(&data);
	int ret = parse_config(&data, config);
	data_cleanup(&data);
	return ret;
}

static struct module_operations module_operations = {
	thread_entry_udpreader,
	poll,
	NULL,
	poll_delete,
	NULL,
	test_config,
	inject
};

static const char *module_name = "udpreader";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
		data->module_name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(void) {
}


