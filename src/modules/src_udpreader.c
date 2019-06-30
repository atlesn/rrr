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
#include "../global.h"

#define VL_UDPREADER_MAX_DATA_FIELDS CMD_ARGUMENT_MAX
#define RRR_UDPREADER_DEFAULT_PORT 2222

struct udpreader_data {
	struct fifo_buffer buffer;
	unsigned int listen_port;
	struct ip_data ip;
	struct rrr_type_definition_collection definitions;
	struct rrr_data_collection *type_data;
};

void type_data_cleanup(void *arg) {
	if (arg != NULL) {
		rrr_types_destroy_data(arg);
	}
}

struct udpreader_data *data_init(struct module_thread_data *module_thread_data) {
	// Use special memory region provided in module_thread_data which we don't have to free
	struct udpreader_data *data = (struct udpreader_data *) module_thread_data->private_memory;
	memset(data, '\0', sizeof(*data));

	fifo_buffer_init(&data->buffer);

	return data;
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct udpreader_data *data = (struct udpreader_data *) arg;
	fifo_buffer_invalidate(&data->buffer);
	if (data->type_data != NULL) {
		rrr_types_destroy_data(data->type_data);
	}
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
}

static int poll_delete (
		struct module_thread_data *data,
		int (*callback)(struct fifo_callback_args *poll_data, char *data, unsigned long int size),
		struct fifo_callback_args *caller_data
) {
	struct udpreader_data *udpreader_data = data->private_data;
	return fifo_read_clear_forward(&udpreader_data->buffer, NULL, callback, caller_data);
}

static int poll (
		struct module_thread_data *data,
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

int config_parser (struct udpreader_data *data, struct rrr_instance_config *config) {
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

static int parse_config(struct udpreader_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint udpr_port;
	if ((ret = rrr_instance_config_read_port_number (&udpr_port, config, "udpr_port")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			udpr_port = RRR_UDPREADER_DEFAULT_PORT;
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing udpreader udpr_port for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->listen_port = udpr_port;

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
	if (rrr_types_parse_data(entry->data.data, entry->data_length, data->type_data) != 0) {
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
	message = rrr_types_create_message_le(data->type_data, timestamp);

	if (message != NULL) {
		fifo_buffer_write(&data->buffer, (char*)message, sizeof(*message));

		VL_DEBUG_MSG_3("udpreader created a message with timestamp %llu\n", (long long unsigned int) message->timestamp_from);

		message = NULL;
	}

	pthread_cleanup_pop(0);

	return 0;
}

int read_data(struct udpreader_data *data) {
	return ip_receive_packets (
		data->ip.fd,
		NULL,
		read_data_callback,
		data,
		NULL
	);
}

static void *thread_entry_udpreader(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	struct udpreader_data *data = data_init(thread_data);

	VL_DEBUG_MSG_1 ("UDPreader thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);
	thread_data->private_data = data;

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	pthread_cleanup_push(type_data_cleanup, data->type_data);
	data->type_data = rrr_types_allocate_data(&data->definitions);

	pthread_cleanup_push(ip_network_cleanup, &data->ip);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parsing failed for udpreader instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	data->ip.port = data->listen_port;
	if (ip_network_start(&data->ip) != 0) {
		VL_MSG_ERR("Could not initialize network in udpreader\n");
		pthread_exit(0);
	}
	VL_DEBUG_MSG_2("udpreader: listening on port %d\n", data->listen_port);

	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		uint64_t time = time_get_64();

//		struct vl_message *reading = message_new_reading(time, time);

		VL_DEBUG_MSG_2("udpreader: reading from network\n");

		if (read_data(data) != 0) {
			break;
		}

/*		fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading)); */

		usleep (50000); // 10 ms
	}

	out_message:

	VL_DEBUG_MSG_1 ("udpreader %s received encourage stop\n", thread_data->init_data.instance_config->name);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
	thread_entry_udpreader,
	poll,
	NULL,
	poll_delete,
	NULL
};

static const char *module_name = "udpreader";


__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
		data->module_name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload() {
}


