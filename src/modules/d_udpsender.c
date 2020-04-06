/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include "../lib/poll.h"
#include "../lib/array.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../global.h"

struct udpsender_data {
	struct rrr_fifo_buffer input_buffer;
	struct rrr_instance_thread_data *thread_data;
	struct rrr_ip_data ip;
	char *target_host;
	unsigned int source_port;
	unsigned int target_port;
	int do_send_rrr_message;
	int force_target;
};

void data_cleanup(void *arg) {
	struct udpsender_data *data = (struct udpsender_data *) arg;
	RRR_FREE_IF_NOT_NULL(data->target_host);
	rrr_fifo_buffer_invalidate(&data->input_buffer);
}

int data_init(struct udpsender_data *data, struct rrr_instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	int ret = 0;

	ret |= rrr_fifo_buffer_init_custom_free(&data->input_buffer, rrr_ip_buffer_entry_destroy_void);

	return ret;
}

int config_parse_port (struct udpsender_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint tmp_uint;

	// Source port
	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "udps_source_port");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_ERR("Could not parse udps_source_port for instance %s\n", config->name);
		}
		else {
			RRR_MSG_ERR("Error while parsing udps_source_port setting for instance %s\n", config->name);
		}
		ret = 1;
		goto out;
	}
	data->source_port = tmp_uint;

	// Target host port
	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "udps_target_port");
	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_ERR("Could not parse udps_target_port for instance %s\n", config->name);
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Could not find required udps_target_port setting for instance %s\n", config->name);
		}
		else {
			RRR_MSG_ERR("Error while parsing udps_target_port setting for instance %s\n", config->name);
		}
		ret = 1;
		goto out;
	}
	data->target_port = tmp_uint;

	out:
	return ret;
}

int parse_config (struct udpsender_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	// Parse listen port
	if ((ret = config_parse_port (data, config)) != 0) {
		goto out;
	}

	// Message default topic
	if ((ret = rrr_settings_get_string_noconvert_silent(&data->target_host, config->settings, "udps_target_host")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing configuration parameter udps_target_host in udpsender instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	// Send complete RRR message
	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udps_send_rrr_message")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udps_send_rrr_message for udpsender instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	data->do_send_rrr_message = yesno;

	// Force target
	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udps_force_target")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udps_force_target for udpsender instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	data->force_target = yesno;

	out:
	return ret;
}

static int poll_callback_final (struct udpsender_data *data, struct rrr_ip_buffer_entry *entry) {
	rrr_fifo_buffer_write(&data->input_buffer, (char *) entry, sizeof(*entry));
	return 0;
}

static int poll_callback (struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct udpsender_data *private_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;
	struct rrr_ip_buffer_entry *entry = NULL;

	RRR_DBG_3 ("udpsender instance %s: Result from buffer: timestamp %" PRIu64 " measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->timestamp_from, message->data_numeric, size);

	if (rrr_ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(message), NULL, 0, message) != 0) {
		RRR_MSG_ERR("Could not create ip buffer entry in udpsender poll_callback\n");
		free(data);
		return 1;
	}

	return poll_callback_final(private_data, entry);
}

static int poll_callback_ip (struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct udpsender_data *private_data = thread_data->private_data;
	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	RRR_DBG_3 ("udpsender instance %s: Result from buffer ip: size %lu\n",
			INSTANCE_D_NAME(thread_data), size);

	return poll_callback_final(private_data, entry);
}

static int input_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct udpsender_data *udpsender_data = poll_data->private_data;
	int ret = RRR_FIFO_OK;

	void *send_data = data;
	ssize_t send_size = size;

	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	if (data->force_target == 1 || entry->addr_len == 0) {
		ret = rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
			&data->ip,
			data->target_port,
			data->target_host,
			send_data,
			send_size
		);
	}
	else {
		ret = rrr_ip_send_raw (
			&data->ip.fd,
			addr,
			len,
			send_data,
			send_size
		);
	}

	if (ret != 0) {
		RRR_MSG_ERR("Could not send data in udpsender instance %s", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	free(entry);
	return ret;
}

static void *thread_entry_udpsender (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct udpsender_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;
	struct poll_collection poll_ip;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in udpsender instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("UDPsender thread data is %p\n", thread_data);

	poll_collection_init(&poll_ip);
	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Configuration parsing failed for udpsender instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_NO_SENDERS_OK);
	poll_add_from_thread_senders_ignore_error(&poll_ip, thread_data, RRR_POLL_POLL_DELETE_IP|RRR_POLL_NO_SENDERS_OK);

	poll_remove_senders_also_in(&poll, &poll_ip);

	if (poll_collection_count(&poll) + poll_collection_count(&poll_ip) == 0) {
		RRR_MSG_ERR("No senders specified for dead-end module udpsender instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	data->ip.port = data->source_port;
	if (data->ip.port == 0) {
		if (rrr_ip_network_start_udp_ipv4_nobind(&data->ip) != 0) {
			RRR_MSG_ERR("Could not initialize network in udpsender\n");
			goto out_message;
		}
		RRR_DBG_1("udpsender instance %s started, not bound to any particular port\n", INSTANCE_D_NAME(thread_data));
	}
	else {
		if (rrr_ip_network_start_udp_ipv4(&data->ip) != 0) {
			RRR_MSG_ERR("Could not initialize network in udpsender\n");
			goto out_message;
		}
		RRR_DBG_1("udpsender instance %s started, bound to port %d\n", INSTANCE_D_NAME(thread_data), data->listen_port);
	}

	pthread_cleanup_push(rrr_ip_network_cleanup, &data->ip);

	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 25) != 0) {
			break;
		}
		if (poll_do_poll_delete_ip_simple (&poll_ip, thread_data, poll_callback_ip, 25) != 0) {
			break;
		}

		struct rrr_fifo_callback_args callback_args = {
			thread_data, udpsender_data, 0
		};

		if (rrr_fifo_read_clear_forward(&udpsender_data->input_buffer, NULL, input_callback, &callback_args, 0) != 0) {
			RRR_MSG_ERR("Error while iterating input buffer in udpsender instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_cleanup_network;
		}
	}

	out_cleanup_network:
	pthread_cleanup_pop(1);

	out_message:

	RRR_DBG_1 ("udpsender %s stopping\n", thread_data->init_data.instance_config->name);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct udpsender_data data;
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
	thread_entry_udpsender,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	test_config,
	NULL,
	NULL
};

static const char *module_name = "udpsender";

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


