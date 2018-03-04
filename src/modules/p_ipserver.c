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
#include "common/ip.h"

// Should not be smaller than module max
#define VL_IPSERVER_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPSERVER_SERVER_PORT 5555
#define VL_IPSERVER_RATE_LIMIT 20 // Time between sending packets, milliseconds

struct ipserver_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	struct ip_data ip;
};

// Poll request from other modules
int ipserver_poll_delete (
	struct module_thread_data *thread_data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *caller_data
) {
	struct ipserver_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->receive_buffer, NULL, callback, caller_data);
}

void poll_callback(void *caller_data, char *data, unsigned long int size) {
	struct fifo_callback_args *poll_data = caller_data;
	struct module_thread_data *thread_data = poll_data->source;
	struct ipserver_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	printf ("ipserver: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&private_data->send_buffer, data, size);
}

void spawn_error(struct ipserver_data *data, const char *buf) {
	struct vl_message *message = message_new_info(time_get_64(), buf);
	struct ip_buffer_entry *entry = malloc(sizeof(*entry));
	memset(entry, '\0', sizeof(*entry));
	memcpy(&entry->message, message, sizeof(*message));
	free(message);

	fifo_buffer_write(&data->receive_buffer, (char*)entry, sizeof(*entry));

	fprintf (stderr, "%s", message->data);
}

int process_entries_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ipserver_data *private_data = poll_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	// TODO : Do MySQL-stuff here

	// Generate acknowledgement message, tag it as finished and stored safely
	// We can re-use the message, just flip the type. The entry already
	// contains the IP-address of the sender.
	entry->message.type = MSG_TYPE_TAG;

	printf ("ipserver: Generate TAG message for entry with timestamp %" PRIu64 "\n", entry->message.timestamp_from);

	fifo_buffer_write(&private_data->send_buffer, (char*) entry, sizeof(*entry));

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

	struct vl_message *message_err;

	if (message_prepare_for_network (&entry->message, buf, MSG_STRING_MAX_LENGTH) != 0) {
		return 1;
	}

	printf ("ipserver: send reply timestamp %" PRIu64 "\n", entry->message.timestamp_from);
	if (sendto(private_data->ip.fd, buf, MSG_STRING_MAX_LENGTH, 0, &entry->addr, entry->addr_len) == -1) {
		message_err = message_new_info(time_get_64(), "ipserver: Error while sending packet to server\n");
		fifo_buffer_write(&private_data->send_buffer, data, size);
		goto spawn_error;
	}

	free(data);

	return 0;

	spawn_error:
	fifo_buffer_write(&private_data->receive_buffer, (char*) message_err, sizeof(*message_err));
	fprintf (stderr, "%s", message_err->data);

	return 1;
}

int send_replies(struct ipserver_data *data) {
	struct fifo_callback_args poll_data = {NULL, data};
	return fifo_read_clear_forward(&data->send_buffer, NULL, send_replies_callback, &poll_data);
}

void receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct ipserver_data *data = arg;

	printf ("Ipserver received OK message with data '%s'\n", entry->message.data);

	fifo_buffer_write(&data->receive_buffer, (char*) entry, sizeof(*entry));

	// Generate ACK reply
	printf ("ipserver: Generate ACK message for entry with timestamp %" PRIu64 "\n", entry->message.timestamp_from);
	struct ip_buffer_entry *ack = malloc(sizeof(*ack));
	memcpy(ack, entry, sizeof(*ack));
	ack->message.type = MSG_TYPE_ACK;
	fifo_buffer_write(&data->send_buffer, (char*) ack, sizeof(*ack));
}

int receive_packets(struct ipserver_data *data) {
	return ip_receive_packets(data->ip.fd, receive_packets_callback, data);
}

void init_data(struct ipserver_data *data) {
	if (sizeof(*data) > VL_MODULE_PRIVATE_MEMORY_SIZE) {
		fprintf (stderr, "ipserver: Module thread private memory area too small\n");
		exit(EXIT_FAILURE);
	}
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->send_buffer);
	fifo_buffer_init(&data->receive_buffer);
}

void data_cleanup(void *arg) {
	struct ipserver_data *data = arg;
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->receive_buffer);
}

static void *thread_entry_ipserver(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct ipserver_data* data = thread_data->private_data = thread_data->private_memory;

	printf ("ipserver thread data is %p\n", thread_data);

	init_data(data);

	pthread_cleanup_push(ip_network_cleanup, &data->ip);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_IPSERVER_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for ipserver module, max is %i\n", VL_IPSERVER_MAX_SENDERS);
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
		printf ("ipserver: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;

		if (poll[i] == NULL) {
			fprintf (stderr, "ipserver cannot use this sender, lacking poll delete function.\n");
			goto out_message;
		}
	}

	printf ("ipserver started thread %p\n", thread_data);
	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for ipserver processor module\n");
		goto out_message;
	}

	network_restart:
	ip_network_cleanup(&data->ip);
	ip_network_start(&data->ip);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

/*		printf ("ipserver polling data\n");
		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res = poll[i](thread_data->senders[i], poll_callback, thread_data);
			if (!(res >= 0)) {
				printf ("ipserver module received error from poll function\n");
				err = 1;
				break;
			}
		}*/

		if (receive_packets(data) != 0) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		process_entries(data);
		send_replies(data);

		if (err != 0) {
			break;
		}
		usleep (10000); // 100 ms
	}

	out_message:
	printf ("Thread ipserver %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_ipserver,
		NULL,
		NULL,
		ipserver_poll_delete
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
	printf ("Destroy ipserver module\n");
}

