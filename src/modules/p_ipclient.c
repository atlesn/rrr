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
#include "../lib/cmdlineparser/cmdline.h"
#include "common/ip.h"

// Should not be smaller than module max
#define VL_IPCLIENT_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPCLIENT_SERVER_NAME "localhost"
#define VL_IPCLIENT_SERVER_PORT "5555"
#define VL_IPCLIENT_SEND_RATE 20 // Time between sending packets, milliseconds
#define VL_IPCLIENT_BURST_LIMIT 10 // Number of packets to send before we switch to reading

struct ipclient_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	const char *ip_server;
	const char *ip_port;
	struct ip_data ip;
};

// Poll request from other modules
int ipclient_poll_delete (
	struct module_thread_data *thread_data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *caller_data
) {
	struct ipclient_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->receive_buffer, NULL, callback, caller_data);
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct ipclient_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	printf ("ipclient: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&private_data->send_buffer, data, size);

	return 0;
}

struct send_packet_info {
	struct ipclient_data *data;
	int fd;
	struct addrinfo *res;
	int packet_counter;
};

int send_packet_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct send_packet_info *info = poll_data->private_data;
	struct module_thread_data *thread_data = poll_data->source;
	struct ipclient_data *ipclient_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	char buf[MSG_STRING_MAX_LENGTH];
	memset(buf, '\0', MSG_STRING_MAX_LENGTH);
	buf[0] = '\0'; // Network messages must start and end with zero

	if (message_prepare_for_network (message, buf, MSG_STRING_MAX_LENGTH) != 0) {
		return FIFO_SEARCH_KEEP;
	}

	printf("ipclient sent packet timestamp from %" PRIu64 "\n", message->timestamp_from);

	if (sendto(info->fd, buf, MSG_STRING_MAX_LENGTH, 0, info->res->ai_addr, info->res->ai_addrlen) == -1) {
		fprintf(stderr, "ipclient: Error while sending packet to server\n");
		return FIFO_SEARCH_ERR;
	}

	info->packet_counter++;

	if (info->packet_counter == VL_IPCLIENT_BURST_LIMIT) {
		printf ("ipclient burst limit reached, switching to reading\n");
		return FIFO_SEARCH_STOP;
	}

	update_watchdog_time(thread_data->thread);
	usleep (VL_IPCLIENT_SEND_RATE * 1000);

	// DO NOT FREE MESSAGE
	return FIFO_SEARCH_KEEP;
}

int receive_packets_search_callback (struct fifo_callback_args *callback_data, char *data, unsigned long int size) {
	struct ipclient_data *ipclient_data = callback_data->source;
	struct vl_message *message_to_match = callback_data->private_data;
	struct vl_message *checked_entry = (struct vl_message *) data;

	printf ("ipclient: match class %" PRIu32 " vs %" PRIu32 "\n", message_to_match->class, checked_entry->class);
	printf ("ipclient: match timestamp from %" PRIu64 " vs %" PRIu64 "\n", message_to_match->timestamp_from, checked_entry->timestamp_from);
	printf ("ipclient: match timestamp to %" PRIu64 " vs %" PRIu64 "\n", message_to_match->timestamp_to, checked_entry->timestamp_to);
	printf ("ipclient: match length %" PRIu32 " vs %" PRIu32 "\n", message_to_match->length, checked_entry->length);

	if (	message_to_match->class == checked_entry->class &&
			message_to_match->timestamp_from == checked_entry->timestamp_from &&
			message_to_match->timestamp_to == checked_entry->timestamp_to &&
			message_to_match->length == checked_entry->length
	) {
		printf ("ipclient received ACK for message %s\n", checked_entry->data);
		free(checked_entry);
		return FIFO_SEARCH_GIVE | FIFO_SEARCH_STOP;
	}

	return FIFO_SEARCH_KEEP;
}

void receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct ipclient_data *data = arg;
	struct vl_message *message = &entry->message;

	printf ("ipclient: Received packet from server: %s\n", entry->message.data);

	// First, check if package is an ACK from the server in case we should delete
	// the original message from our send queue. If not, we let some other module
	// pick the packet up.
	if (MSG_IS_ACK(message)) {
		printf ("ipclient: Packet is ACK\n");
		struct fifo_callback_args callback_args;
		callback_args.source = data;
		callback_args.private_data = message;
		fifo_search(&data->send_buffer, receive_packets_search_callback, &callback_args);
		free(entry);
	}
	else {
		struct vl_message *message = malloc(sizeof(*message));
		memcpy (message, &entry->message, sizeof(*message));
		free (entry);
		fifo_buffer_write(&data->receive_buffer, (char*) message, sizeof(*message));
	}
}

int receive_packets(struct ipclient_data *data) {
	struct fifo_callback_args poll_data = {NULL, data};
	return ip_receive_packets(data->ip.fd, receive_packets_callback, data);
}

int send_packets(struct module_thread_data *thread_data) {
	struct ipclient_data *data = thread_data->private_data;
	const char* hostname = data->ip_server;
	const char* portname = data->ip_port;

	printf ("ipclient: Send to %s:%s\n", hostname, portname);

	struct addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;

	char errbuf[256];
	struct vl_message *message;

	struct addrinfo* res = NULL;
	int err = getaddrinfo(hostname,portname,&hints,&res);
	if (err != 0) {
		fprintf(stderr, "ipclient: Could not get address info of server %s port %s: %s", hostname, portname, gai_strerror(err));
		goto out_error_nofree;
	}

	struct send_packet_info info;
	info.fd = data->ip.fd;
	info.res = res;
	info.packet_counter = 0;

	struct fifo_callback_args poll_data = {thread_data, &info};
	err = fifo_search(&data->send_buffer, send_packet_callback, &poll_data);

	printf ("ipclient sent %i packets\n", info.packet_counter);

	freeaddrinfo(res);

	return err;

	out_error_nofree:
	return 1;
}

void init_data(struct ipclient_data *data) {
	if (sizeof(*data) > VL_MODULE_PRIVATE_MEMORY_SIZE) {
		fprintf (stderr, "ipclient: Module thread private memory area too small\n");
		exit(EXIT_FAILURE);
	}
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->send_buffer);
	fifo_buffer_init(&data->receive_buffer);
}

void data_cleanup(void *arg) {
	struct ipclient_data *data = arg;
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->receive_buffer);
}

static int parse_cmd (struct ipclient_data *data, struct cmd_data *cmd) {
	const char *ip_server = cmd_get_value(cmd, "ipclient_server", 0);
	const char *ip_port = cmd_get_value(cmd, "ipclient_server_port", 0);

	data->ip_server = VL_IPCLIENT_SERVER_NAME;
	data->ip_port = VL_IPCLIENT_SERVER_PORT;

	if (ip_server != NULL) {
		data->ip_server = ip_server;
	}
	if (ip_port != NULL) {
		data->ip_port = ip_port;
	}

	return 0;
}

static void *thread_entry_ipclient(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct ipclient_data* data = thread_data->private_data = thread_data->private_memory;

	printf ("ipclient thread data is %p\n", thread_data);

	init_data(data);
	pthread_cleanup_push(data_cleanup, data);

	parse_cmd(data, start_data->cmd);

	pthread_cleanup_push(ip_network_cleanup, &data->ip);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_IPCLIENT_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for ipclient module, max is %i\n", VL_IPCLIENT_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_IPCLIENT_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *caller_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);

	for (int i = 0; i < senders_count; i++) {
		printf ("ipclient: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;

		if (poll[i] == NULL) {
			fprintf (stderr, "ipclient cannot use this sender, lacking poll delete function.\n");
			goto out_message;
		}
	}

	printf ("ipclient started thread %p\n", thread_data);
	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for ipclient processor module\n");
		goto out_message;
	}

	network_restart:
	ip_network_cleanup(&data->ip);
	ip_network_start(&data->ip);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		printf ("ipclient polling data\n");
		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res = poll[i](thread_data->senders[i], poll_callback, &poll_data);
			if (!(res >= 0)) {
				fprintf (stderr, "ipclient module received error from poll function\n");
				err = 1;
				break;
			}
		}

		update_watchdog_time(thread_data->thread);
		if (send_packets(thread_data) != 0) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		update_watchdog_time(thread_data->thread);
		if (receive_packets(data) != 0) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		if (err != 0) {
			break;
		}
		usleep (100000); // 100 ms
	}

	out_message:
	printf ("Thread ipclient %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_ipclient,
		NULL,
		NULL,
		ipclient_poll_delete
};

static const char *module_name = "ipclient";

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
	printf ("Destroy ipclient module\n");
}

