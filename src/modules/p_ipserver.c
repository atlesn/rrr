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

#ifdef VL_WITH_OPENSSL
#include "../lib/module_crypt.h"
#endif

// Should not be smaller than module max
#define VL_IPSERVER_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPSERVER_SERVER_PORT 5555
#define VL_IPSERVER_RATE_LIMIT 20 // Time between sending packets, milliseconds

struct ipserver_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	struct fifo_buffer output_buffer;
	struct ip_data ip;
#ifdef VL_WITH_OPENSSL
	char *crypt_file;
	struct module_crypt_data crypt_data;
#endif
	struct ip_stats_twoway stats;
	rrr_setting_uint server_port;
};

// Poll request from other modules
int ipserver_poll_delete_ip (RRR_MODULE_POLL_SIGNATURE) {
	struct ipserver_data *ipserver_data = data->private_data;

	return fifo_read_clear_forward(&ipserver_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct ipserver_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	VL_DEBUG_MSG_2 ("ipserver: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&private_data->send_buffer, data, size);

	return 0;
}

void spawn_error(struct ipserver_data *data, const char *buf) {
	struct vl_message *message = message_new_info(time_get_64(), buf);
	struct ip_buffer_entry *entry = malloc(sizeof(*entry));
	memset(entry, '\0', sizeof(*entry));

	VL_ASSERT(sizeof(*(&entry->data.message))==sizeof(*message),equal_size_of_message);

	memcpy(&entry->data.message, message, sizeof(*message));
	free(message);

	fifo_buffer_write(&data->receive_buffer, (char*)entry, sizeof(*entry));

	VL_MSG_ERR ("%s", message->data);
}

int process_entries_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ipserver_data *private_data = poll_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	VL_DEBUG_MSG_4("ipserver process entries callback got packet from buffer of size %lu\n", size);

	fifo_buffer_write(&private_data->output_buffer, (char*) entry, sizeof(*entry));

	return 0;
}

int process_entries(struct ipserver_data *data) {
	struct fifo_callback_args poll_data = {NULL, data, 0};
	return fifo_read_clear_forward(&data->receive_buffer, NULL, process_entries_callback, &poll_data, 50);
}

int send_replies_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ipserver_data *private_data = poll_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	struct addrinfo res;
	res.ai_addr = &entry->addr;
	res.ai_addrlen = entry->addr_len;

	struct ip_send_packet_info info;
	info.fd = private_data->ip.fd;
	info.packet_counter = 0;
	info.res = &res;

	struct vl_message *message_err = NULL;

	VL_DEBUG_MSG_3 ("ipserver: send reply timestamp %" PRIu64 "\n", entry->data.message.timestamp_from);

	if (ip_send_message (
			&entry->data.message,
#ifdef VL_WITH_OPENSSL
			&private_data->crypt_data,
#endif
			&info,
			VL_DEBUGLEVEL_2 ? &private_data->stats.send : NULL
	) != 0) {
		message_err = message_new_info(time_get_64(), "ipserver: Error while sending packet to client\n");
		fifo_buffer_write(&private_data->send_buffer, data, size);
		goto spawn_error;
	}

	free(data);

	return 0;

	spawn_error:
	fifo_buffer_write(&private_data->receive_buffer, (char*) message_err, sizeof(*message_err));
	VL_MSG_ERR ("%s", message_err->data);

	return 1;
}

int send_replies(struct ipserver_data *data) {
	struct fifo_callback_args poll_data = {NULL, data, 0};
	return fifo_read_clear_forward(&data->send_buffer, NULL, send_replies_callback, &poll_data, 50);
}

struct receive_packets_data {
	struct ipserver_data *data;
	int counter;
};


int receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct receive_packets_data *callback_data = arg;
	struct ipserver_data *data = callback_data->data;

	callback_data->counter++;

	VL_DEBUG_MSG_3 ("Ipserver received OK message with data '%s'\n", entry->data.message.data);

	fifo_buffer_write(&data->output_buffer, (char*) entry, sizeof(*entry));

	// Generate ACK reply
	VL_DEBUG_MSG_2 ("ipserver: Generate ACK message for entry with timestamp %" PRIu64 "\n", entry->data.message.timestamp_from);
	struct ip_buffer_entry *ack = malloc(sizeof(*ack));
	memcpy(ack, entry, sizeof(*ack));
	ack->data.message.type = MSG_TYPE_ACK;
	fifo_buffer_write(&data->send_buffer, (char*) ack, sizeof(*ack));

	return (callback_data->counter == 5 ? VL_IP_RECEIVE_STOP : VL_IP_RECEIVE_OK);
}

int receive_packets(struct ipserver_data *data) {
	struct receive_packets_data callback_data;
	callback_data.data = data;
	callback_data.counter = 0;
	return ip_receive_messages (
		data->ip.fd,
#ifdef VL_WITH_OPENSSL
		&data->crypt_data,
#endif
		receive_packets_callback,
		&callback_data,
		VL_DEBUGLEVEL_2 ? &data->stats.receive : NULL
	);
}

void data_cleanup(void *arg) {
	struct ipserver_data *data = arg;
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->receive_buffer);
	fifo_buffer_invalidate(&data->output_buffer);
#ifdef VL_WITH_OPENSSL
	RRR_FREE_IF_NOT_NULL(data->crypt_file);
#endif
}

int data_init(struct ipserver_data *data) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;
	ret |= fifo_buffer_init(&data->send_buffer) << 0;
	ret |= fifo_buffer_init(&data->receive_buffer) << 1;
	ret |= fifo_buffer_init(&data->output_buffer) << 2;
	if (ret == 0) {
		ret = ip_stats_init_twoway(&data->stats, VL_IP_STATS_DEFAULT_PERIOD, "ipserver") << 3;
	}
	else {
		data_cleanup(data);
	}
	return ret;
}

// TODO : Provide more configuration arguments
static int parse_config (struct ipserver_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint ipserver_port = 0;

#ifdef VL_WITH_OPENSSL
	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->crypt_file, config, "ipserver_keyfile")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing ipserver_keyfile settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
#endif

	if ((ret = rrr_instance_config_read_unsigned_integer(&ipserver_port, config, "ipserver_server_port")) == 0) {
		// OK
	}
	else if (ret != RRR_SETTING_NOT_FOUND) {
		VL_MSG_ERR("Error while parsing ipserver_server_port setting of instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else {
		ipserver_port = VL_IPSERVER_SERVER_PORT;
		ret = 0;
	}

	data->server_port = ipserver_port;
	data->ip.port = ipserver_port;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void *thread_entry_ipserver (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct ipserver_data* data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	int init_ret = 0;
	if ((init_ret = data_init(data)) != 0) {
		VL_MSG_ERR("Could not initalize data in ipserver instance %s flags %i\n",
			INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("ipserver thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(ip_network_cleanup, &data->ip);
	pthread_cleanup_push(data_cleanup, data);
#ifdef VL_WITH_OPENSSL
	pthread_cleanup_push(module_crypt_data_cleanup, &data->crypt_data);
#endif
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parse failed for ipserver instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE_IP) != 0) {
		VL_MSG_ERR("Ipserver requires poll_delete_ip from senders\n");
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("ipserver started thread %p\n", thread_data);

#ifdef VL_WITH_OPENSSL
	if (	data->crypt_file != NULL &&
			module_crypt_data_init(&data->crypt_data, data->crypt_file) != 0
	) {
		VL_MSG_ERR("ipserver: Cannot continue without crypt library\n");
		goto out_message;
	}
#endif

	network_restart:
	ip_network_cleanup(&data->ip);
	ip_network_start(&data->ip);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		if (poll_do_poll_delete_ip_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		if (receive_packets(data) != 0) {
			usleep (5000); // 50 ms
			goto network_restart;
		}

		process_entries(data);
		send_replies(data);
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread ipserver %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
#ifdef VL_WITH_OPENSSL
	pthread_cleanup_pop(1);
#endif
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

int test_config (struct rrr_instance_config *config) {
	struct ipserver_data data;
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
		thread_entry_ipserver,
		NULL,
		NULL,
		NULL,
		NULL,
		ipserver_poll_delete_ip,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "ipserver";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = VL_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy ipserver module\n");
}

