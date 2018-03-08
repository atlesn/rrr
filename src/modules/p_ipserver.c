/*

Voltage Logger

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#include "../modules.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../global.h"
#include "../lib/module_crypt.h"
#include "common/ip.h"

// Should not be smaller than module max
#define VL_IPSERVER_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPSERVER_SERVER_PORT 5555
#define VL_IPSERVER_RATE_LIMIT 20 // Time between sending packets, milliseconds

struct ipserver_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	struct fifo_buffer output_buffer;
	struct ip_data ip;
	const char *crypt_file;
	struct module_crypt_data crypt_data;
};

// Poll request from other modules
int ipserver_poll_delete_ip (
	struct module_thread_data *thread_data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *caller_data
) {
	struct ipserver_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->output_buffer, NULL, callback, caller_data);
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
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
	memcpy(&entry->message, message, sizeof(*message));
	free(message);

	fifo_buffer_write(&data->receive_buffer, (char*)entry, sizeof(*entry));

	VL_MSG_ERR ("%s", message->data);
}

int process_entries_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ipserver_data *private_data = poll_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	fifo_buffer_write(&private_data->output_buffer, (char*) entry, sizeof(*entry));

	return 0;
}

int process_entries(struct ipserver_data *data) {
	struct fifo_callback_args poll_data = {NULL, data};
	return fifo_read_clear_forward(&data->receive_buffer, NULL, process_entries_callback, &poll_data);
}

int send_replies_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ipserver_data *private_data = poll_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	char buf[MSG_STRING_MAX_LENGTH];
	memset(buf, '\0', MSG_STRING_MAX_LENGTH);
	buf[0] = '\0'; // Network messages must start and end with zero

	struct addrinfo res;
	res.ai_addr = &entry->addr;
	res.ai_addrlen = entry->addr_len;

	struct ip_send_packet_info info;
	info.fd = private_data->ip.fd;
	info.packet_counter = 0;
	info.res = &res;

	struct vl_message *message_err;

	if (message_prepare_for_network (&entry->message, buf, MSG_STRING_MAX_LENGTH) != 0) {
		return 1;
	}

	VL_DEBUG_MSG_2 ("ipserver: send reply timestamp %" PRIu64 "\n", entry->message.timestamp_from);

	if (ip_send_packet(
			&entry->message,
			&private_data->crypt_data,
			&info
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
	struct fifo_callback_args poll_data = {NULL, data};
	return fifo_read_clear_forward(&data->send_buffer, NULL, send_replies_callback, &poll_data);
}

struct receive_packets_data {
	struct ipserver_data *data;
	int counter;
};


int receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct receive_packets_data *callback_data = arg;
	struct ipserver_data *data = callback_data->data;

	callback_data->counter++;

	VL_DEBUG_MSG_2 ("Ipserver received OK message with data '%s'\n", entry->message.data);

	fifo_buffer_write(&data->output_buffer, (char*) entry, sizeof(*entry));

	// Generate ACK reply
	VL_DEBUG_MSG_2 ("ipserver: Generate ACK message for entry with timestamp %" PRIu64 "\n", entry->message.timestamp_from);
	struct ip_buffer_entry *ack = malloc(sizeof(*ack));
	memcpy(ack, entry, sizeof(*ack));
	ack->message.type = MSG_TYPE_ACK;
	fifo_buffer_write(&data->send_buffer, (char*) ack, sizeof(*ack));

	return (callback_data->counter == 5 ? VL_IP_RECEIVE_STOP : VL_IP_RECEIVE_OK);
}

int receive_packets(struct ipserver_data *data) {
	struct receive_packets_data callback_data;
	callback_data.data = data;
	callback_data.counter = 0;
	return ip_receive_packets (
		data->ip.fd,
		&data->crypt_data,
		receive_packets_callback,
		&callback_data
	);
}

void init_data(struct ipserver_data *data) {
	if (sizeof(*data) > VL_MODULE_PRIVATE_MEMORY_SIZE) {
		VL_MSG_ERR ("ipserver: Module thread private memory area too small\n");
		exit(EXIT_FAILURE);
	}
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->send_buffer);
	fifo_buffer_init(&data->receive_buffer);
	fifo_buffer_init(&data->output_buffer);
}

void data_cleanup(void *arg) {
	struct ipserver_data *data = arg;
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->receive_buffer);
	fifo_buffer_invalidate(&data->output_buffer);
}

// TODO : Provide more configuration arguments
static int parse_cmd (struct ipserver_data *data, struct cmd_data *cmd) {
//	const char *ip_server = cmd_get_value(cmd, "ipclient_server", 0);
//	const char *ip_port = cmd_get_value(cmd, "ipclient_server_port", 0);
	const char *crypt_file = cmd_get_value(cmd, "ipserver_keyfile", 0);

//	data->ip_server = VL_IPCLIENT_SERVER_NAME;
//	data->ip_port = VL_IPCLIENT_SERVER_PORT;
	data->crypt_file = NULL;

/*	if (ip_server != NULL) {
		data->ip_server = ip_server;
	}
	if (ip_port != NULL) {
		data->ip_port = ip_port;
	}*/
	if (crypt_file != NULL) {
		data->crypt_file = crypt_file;
	}

	return 0;
}

static void *thread_entry_ipserver(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct ipserver_data* data = thread_data->private_data = thread_data->private_memory;

	VL_DEBUG_MSG_1 ("ipserver thread data is %p\n", thread_data);

	init_data(data);
	parse_cmd(data, start_data->cmd);

	pthread_cleanup_push(ip_network_cleanup, &data->ip);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);
	pthread_cleanup_push(module_crypt_data_cleanup, &data->crypt_data);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_IPSERVER_MAX_SENDERS) {
		VL_MSG_ERR ("Too many senders for ipserver module, max is %i\n", VL_IPSERVER_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_IPSERVER_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *caller_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);

	for (int i = 0; i < senders_count; i++) {
		VL_DEBUG_MSG_1 ("ipserver: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete_ip;

		if (poll[i] == NULL) {
			VL_MSG_ERR ("ipserver cannot use this sender, lacking poll_delete_ip function.\n");
			goto out_message;
		}
	}

	VL_DEBUG_MSG_1 ("ipserver started thread %p\n", thread_data);
	if (senders_count == 0) {
		VL_MSG_ERR ("Error: Sender was not set for ipserver processor module\n");
		goto out_message;
	}

	if (	data->crypt_file != NULL &&
			module_crypt_data_init(&data->crypt_data, data->crypt_file) != 0
	) {
		VL_MSG_ERR("ipserver: Cannot continue without crypt library\n");
		goto out_message;
	}

	network_restart:
	ip_network_cleanup(&data->ip);
	ip_network_start(&data->ip);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, data};
			int res = poll[i](thread_data->senders[i], poll_callback, &poll_data);
			if (!(res >= 0)) {
				VL_MSG_ERR ("ipserver module received error from poll function\n");
				err = 1;
				break;
			}
		}

		if (receive_packets(data) != 0) {
			usleep (5000); // 50 ms
			goto network_restart;
		}

		process_entries(data);
		send_replies(data);

		if (err != 0) {
			break;
		}
		usleep (5000); // 50 ms
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread ipserver %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_ipserver,
		NULL,
		NULL,
		NULL,
		ipserver_poll_delete_ip
};

static const char *module_name = "ipserver";

__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
	data->private_data = NULL;
	data->name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(struct module_dynamic_data *data) {
	VL_DEBUG_MSG_1 ("Destroy ipserver module\n");
}

