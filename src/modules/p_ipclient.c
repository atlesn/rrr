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

struct ipclient_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	const char *ip_server;
	const char *ip_port;
};

// Poll request from other modules
int ipclient_poll_delete (
	struct module_thread_data *thread_data,
	void (*callback)(void *caller_data, char *data, unsigned long int size),
	struct module_thread_data *caller_data
) {
	struct ipclient_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->receive_buffer, NULL, callback, caller_data);
}

void poll_callback(void *caller_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = caller_data;
	struct ipclient_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	printf ("ipclient: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&private_data->send_buffer, data, size);
}

struct send_packet_info {
	struct ipclient_data *data;
	int fd;
	struct addrinfo *res;
};

void send_packet_callback(void *caller_data, char *data, unsigned long int size) {
	struct send_packet_info *info = caller_data;
	struct vl_message *message = (struct vl_message *) data;

	char buf[MSG_STRING_MAX_LENGTH];
	memset(buf, '\0', MSG_STRING_MAX_LENGTH);
	buf[0] = '\0'; // Network messages must start and end with zero

	struct vl_message *message_err;

	if (message_prepare_for_network (message, buf, MSG_STRING_MAX_LENGTH) != 0) {
		return;
	}

	if (sendto(info->fd, buf, MSG_STRING_MAX_LENGTH, 0, info->res->ai_addr, info->res->ai_addrlen) == -1) {
		message_err = message_new_info(time_get_64(), "ipclient: Error while sending packet to server\n");
		goto spawn_error;
	}

	// DO NOT FREE MESSAGE

	return;

	spawn_error:
	fifo_buffer_write(&info->data->receive_buffer, (char*) message_err, sizeof(*message_err));
	fprintf (stderr, "%s", message_err->data);

	return;
}

void receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct ipclient_data *data = arg;

	printf ("ipclient: Received packet from server: %s\n", entry->message.data);
	fifo_buffer_write(&data->receive_buffer, (char*) &entry->message, sizeof(entry->message));
}

void receive_packets(struct ipclient_data *data, struct send_packet_info *info) {
	ip_receive_packets(info->fd, receive_packets_callback, data);
}

void send_receive_packets(struct ipclient_data *data) {
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
		sprintf(errbuf, "ipclient: Could not get address info of server %s port %s: %s", hostname, portname, gai_strerror(err));
		goto out_spawn_error;
	}

	int fd = socket(res->ai_family,res->ai_socktype,res->ai_protocol);
	if (fd == -1) {
		sprintf (errbuf, "ipclient: Could not create socket: %s", strerror(errno));
		goto out_spawn_error_freeaddrinfo;
	}

	struct send_packet_info *info = malloc(sizeof(*info));
	info->data = data;
	info->fd = fd;
	info->res = res;

	fifo_read_forward(&data->send_buffer, NULL, send_packet_callback, info);

	// Check for replies
	receive_packets(data, info);

	close(fd);
	free(info);
	freeaddrinfo(res);
	return;

	out_spawn_error_freeaddrinfo:
	freeaddrinfo(res);

	out_spawn_error:
	message = message_new_info(time_get_64(), errbuf);
	fifo_buffer_write(&data->receive_buffer, (char*)message, sizeof(*message));
	fprintf (stderr, "%s", (char*)message);
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

	parse_cmd(data, start_data->cmd);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_IPCLIENT_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for ipclient module, max is %i\n", VL_IPCLIENT_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_IPCLIENT_MAX_SENDERS])(struct module_thread_data *data, void (*callback)(void *caller_data, char *data, unsigned long int size), struct module_thread_data *caller_data);


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


	for (int i = 0; i < senders_count; i++) {
		while (thread_get_state(thread_data->senders[i]->thread) != VL_THREAD_STATE_RUNNING && thread_check_encourage_stop(thread_data->thread) != 1) {
			update_watchdog_time(thread_data->thread);
			printf ("ipclient: Waiting for source thread to become ready\n");
			usleep (5000);
		}
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		printf ("ipclient polling data\n");
		for (int i = 0; i < senders_count; i++) {
			int res = poll[i](thread_data->senders[i], poll_callback, thread_data);
			if (!(res >= 0)) {
				printf ("ipclient module received error from poll function\n");
				err = 1;
				break;
			}
		}

		printf ("ipclient sending data\n");
		send_receive_packets(data);

		if (err != 0) {
			break;
		}
		usleep (1249000); // 1249 ms
	}

	out_message:
	printf ("Thread ipclient %p exiting\n", thread_data->thread);

	out:
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

