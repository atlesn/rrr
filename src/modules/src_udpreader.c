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
#include <src/lib/array.h>
#include <unistd.h>

#include "../lib/settings.h"
#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/ip.h"
#include "../lib/array.h"
#include "../lib/rrr_socket.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/utf8.h"
#include "../lib/read.h"
#include "../global.h"

#define RRR_UDPREADER_DEFAULT_PORT 2222

struct udpreader_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_fifo_buffer buffer;
	struct rrr_fifo_buffer inject_buffer;
	unsigned int listen_port;
	struct rrr_ip_data ip;
	struct rrr_array definitions;
	struct rrr_read_session_collection read_sessions;
	int do_sync_byte_by_byte;
	char *default_topic;
	ssize_t default_topic_length;
};

void data_cleanup(void *arg) {
	struct udpreader_data *data = (struct udpreader_data *) arg;
	rrr_fifo_buffer_invalidate(&data->buffer);
	rrr_fifo_buffer_invalidate(&data->inject_buffer);
	rrr_array_clear(&data->definitions);
	rrr_read_session_collection_clear(&data->read_sessions);
	RRR_FREE_IF_NOT_NULL(data->default_topic);
}

int data_init(struct udpreader_data *data, struct rrr_instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	int ret = 0;

	ret |= rrr_fifo_buffer_init(&data->buffer);
	ret |= rrr_fifo_buffer_init(&data->inject_buffer);

	if (ret != 0) {
		data_cleanup(data);
	}

	return ret;
}

static int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct udpreader_data *udpreader_data = data->private_data;
	return rrr_fifo_read_clear_forward(&udpreader_data->buffer, NULL, callback, poll_data, wait_milliseconds);
}

static int poll (RRR_MODULE_POLL_SIGNATURE) {
	struct udpreader_data *udpreader_data = data->private_data;
	return rrr_fifo_search(&udpreader_data->buffer, callback, poll_data, wait_milliseconds);
}

int config_parse_port (struct udpreader_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint tmp_uint;
	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "udpr_port");

	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_ERR("Could not parse udpr_port for instance %s\n", config->name);
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Could not find required udpr_port setting for instance %s\n", config->name);
		}
		else {
			RRR_MSG_ERR("Error while parsing udpr port setting for instance %s\n", config->name);
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
	if (rrr_instance_config_parse_array_definition_from_config_silent_fail(&data->definitions, config, "udpr_input_types") != 0) {
 		RRR_MSG_ERR("Could not parse command line argument udpr_input_types in udpreader\n");
		return 1;
	}

	if (data->definitions.node_count == 0) {
		RRR_MSG_ERR("No data types defined in udpr_input_types\n");
		return 1;
	}

	// Message default topic
	if ((ret = rrr_settings_get_string_noconvert_silent(&data->default_topic, config->settings, "udpr_default_topic")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing configuration parameter socket_default_path in udpreader instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		if (rrr_utf8_validate(data->default_topic, strlen(data->default_topic)) != 0) {
			RRR_MSG_ERR("udpr_default_topic for instance %s was not valid UTF-8\n", config->name);
			ret = 1;
			goto out;
		}
		data->default_topic_length = strlen(data->default_topic);
	}

	// Sync byte by byte if parsing fails
	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udpr_sync_byte_by_byte")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udpr_sync_byte_by_byte for udpreader instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	data->do_sync_byte_by_byte = yesno;

	out:
	return ret;
}

int read_data_receive_message_callback (struct rrr_message *message, void *arg) {
	struct udpreader_data *data = arg;

	rrr_fifo_buffer_write(&data->buffer, (char*)message, MSG_TOTAL_SIZE(message));
	RRR_DBG_3("udpreader created a message with timestamp %llu size %lu\n",
			(long long unsigned int) message->timestamp_from, (long unsigned int) sizeof(*message));

	return 0;
}

int read_raw_data_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct udpreader_data *data = arg;
	int ret = 0;

	if ((ret = rrr_array_new_message_from_buffer_with_callback (
			entry->message,
			entry->data_length,
			data->default_topic,
			data->default_topic_length,
			&data->definitions,
			read_data_receive_message_callback,
			data
	)) != 0) {
		RRR_MSG_ERR("Could not create message in udpreader instance %s read_data_callback\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	rrr_ip_buffer_entry_destroy_void(entry);
	return ret;
}

int inject_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	RRR_DBG_4("udpreader inject callback size %lu\n", size);
	struct udpreader_data *udpreader_data = poll_data->private_data;
	return read_raw_data_callback((struct rrr_ip_buffer_entry *) data, udpreader_data);
}

int read_data(struct udpreader_data *data) {
	int ret = 0;

	if ((ret = rrr_ip_receive_array (
		&data->read_sessions,
		data->ip.fd,
		&data->definitions,
		data->do_sync_byte_by_byte,
		read_raw_data_callback,
		data,
		NULL
	)) != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			RRR_MSG_ERR("Received invalid data in ip_receive_packets in udpreader instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			// Don't allow invalid data to stop processing
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Error from ip_receive_packets in udpreader instance %s return was %i\n",
					INSTANCE_D_NAME(data->thread_data), ret);
			ret = 1;
			goto out;
		}
	}

	struct rrr_fifo_callback_args callback_data = {NULL, data, 0};
	if ((ret = rrr_fifo_read_clear_forward(&data->inject_buffer, NULL, inject_callback, &callback_data, 50)) != 0) {
		RRR_MSG_ERR("Error from inject buffer in udpreader instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	return ret;
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	struct udpreader_data *data = thread_data->private_data;
	RRR_DBG_2("udpreader: writing data from inject function\n");

	if (data->inject_buffer.invalid) {
		return 1;
	}

	rrr_fifo_buffer_write(&data->inject_buffer, (char *) message, sizeof(*message));

	return 0;
}


static void *thread_entry_udpreader (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct udpreader_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in udpreader instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("UDPreader thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Configuration parsing failed for udpreader instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	pthread_cleanup_push(rrr_ip_network_cleanup, &data->ip);

	data->ip.port = data->listen_port;
	if (rrr_ip_network_start_udp_ipv4(&data->ip) != 0) {
		RRR_MSG_ERR("Could not initialize network in udpreader\n");
		goto out_message;
	}
	RRR_DBG_2("udpreader: listening on port %d\n", data->listen_port);

	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_update_watchdog_time(thread_data->thread);

		if (read_data(data) != 0) {
			break;
		}
	}

	pthread_cleanup_pop(1);

	out_message:

	RRR_DBG_1 ("udpreader %s received encourage stop\n", thread_data->init_data.instance_config->name);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct udpreader_data data;
	int ret = 0;
	if ((ret = data_init(&data, NULL)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_udpreader,
	NULL,
	poll,
	NULL,
	poll_delete,
	NULL,
	test_config,
	inject,
	NULL
};

static const char *module_name = "udpreader";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
		data->start_priority = RRR_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
}


