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

// Should not be smaller than module max
#define VL_IPSERVER_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPSERVER_SERVER_PORT 5555

struct ipserver_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	int fd;
};

struct ipserver_buffer_entry {
	struct vl_message message; // Must be first, we do dangerous casts :)
	struct sockaddr_storage addr;
	socklen_t addr_len;
};

// Poll request from other modules
int ipserver_poll_delete (
	struct module_thread_data *thread_data,
	void (*callback)(void *caller_data, char *data, unsigned long int size),
	struct module_thread_data *caller_data
) {
	struct ipserver_data *data = thread_data->private_data;

	return fifo_read_clear_forward(&data->receive_buffer, NULL, callback, caller_data);
}

void poll_callback(void *caller_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = caller_data;
	struct ipserver_data *private_data = thread_data->private_data;
	struct vl_message *reading = (struct vl_message *) data;
	printf ("ipserver: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	fifo_buffer_write(&private_data->send_buffer, data, size);
}

void spawn_error(struct ipserver_data *data, const char *buf) {
	struct vl_message *message = message_new_info(time_get_64(), buf);
	struct ipserver_buffer_entry *entry = realloc(message, sizeof(*entry));
	memset (&entry->addr, '\0', sizeof(entry->addr));
	memset (&entry->addr_len, '\0', sizeof(entry->addr_len));

	fifo_buffer_write(&data->receive_buffer, (char*)entry, sizeof(*entry));

	fprintf (stderr, "%s", message->data);
}

void process_entries_callback(void *caller_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = caller_data;
	struct ipserver_data *private_data = thread_data->private_data;
	struct ipserver_buffer_entry *entry = (struct ipserver_buffer_entry *) data;

	// TODO : Do MySQL-stuff here

	// Generate acknowledgement message, tag it as finished and stored safely
	// We can re-use the message, just flip the type. The entry already
	// contains the IP-address of the sender.
	entry->message.type = MSG_TYPE_TAG;

	fifo_buffer_write(&private_data->send_buffer, (char*) entry, sizeof(*entry));
}

int process_entries(struct ipserver_data *data) {
	return fifo_read_clear_forward(&data->receive_buffer, NULL, process_entries_callback, data);
}

int receive_packets(struct ipserver_data *data) {
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	char errbuf[256];

	struct pollfd fds;
	fds.fd = data->fd;
	fds.events = POLLIN;

	char buffer[MSG_STRING_MAX_LENGTH];

	while (1) {
		int res = poll(&fds, 1, 500);
		if (res == -1) {
			sprintf (errbuf, "ipserver: Error from poll when reading data from network: %s\n", strerror(errno));
			spawn_error(data, errbuf);
			return 1;
		}
		else if (!(fds.revents & POLLIN)) {
			printf ("ipserver: no data\n");
			break;
		}

		printf ("ipserver: reading data\n");

		memset(buffer, '\0', MSG_STRING_MAX_LENGTH);
		ssize_t count = recvfrom(data->fd, buffer, MSG_STRING_MAX_LENGTH, 0, (struct sockaddr*) &src_addr, &src_addr_len);

		if (count == -1) {
			sprintf (errbuf, "ipserver: Error from recvfrom when reading data from network: %s\n", strerror(errno));
			spawn_error(data, errbuf);
			return 1;
		}

		if (count < 10) {
			sprintf (errbuf, "ipserver: Received short packet from network\n");
			spawn_error(data, errbuf);
			continue;
		}

		char *start = buffer;
		if (*start != '\0') {
			sprintf (errbuf, "ipserver: Datagram received from network did not start with zero\n");
			spawn_error(data, errbuf);
			continue;
		}

		start++;
		count--;

		struct ipserver_buffer_entry *entry = malloc(sizeof(*entry));
		memset(entry, '\0', sizeof(*entry));

		if (parse_message(start, count, &entry->message) != 0) {
			sprintf (errbuf, "ipserver: Received invalid message\n");
			free (entry);
			spawn_error(data, errbuf);
			continue;
		}

		if (message_checksum_check(&entry->message) != 0) {
			sprintf (errbuf, "ipserver: Message checksum was invalid for '%s'\n", start);
			free (entry);
			spawn_error(data, errbuf);
			continue;
		}
		else {
			printf ("Ipserver received OK message with data '%s'\n", entry->message.data);
			entry->addr = src_addr;
			entry->addr_len = src_addr_len;
			fifo_buffer_write(&data->receive_buffer, (char*) entry, sizeof(*entry));
		}
	}

	return 0;
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

void ipserver_network_cleanup (void *arg) {
	struct ipserver_data *data = arg;
	if (data->fd != 0) {
		close(data->fd);
	}
}

void ipserver_network_start (struct ipserver_data *data) {
	char errbuf[256];

	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1) {
		sprintf (errbuf, "ipserver: Could not create socket: %s", strerror(errno));
		goto out_spawn_error;
	}

	struct sockaddr_in si;
	memset(&si, '\0', sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = htons(VL_IPSERVER_SERVER_PORT);
    si.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind (fd, (struct sockaddr *) &si, sizeof(si)) == -1) {
		sprintf (errbuf, "ipserver: Could not bind to port %d: %s", VL_IPSERVER_SERVER_PORT, strerror(errno));
		goto out_spawn_error_close_socket;
	}

	data->fd = fd;

	return;

	out_spawn_error_close_socket:
	close(fd);

	struct vl_message *message;

	out_spawn_error:
	message = message_new_info(time_get_64(), errbuf);
	fifo_buffer_write(&data->receive_buffer, (char*)message, sizeof(*message));
	fprintf (stderr, "%s", (char*)message);
}

static void *thread_entry_ipserver(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct ipserver_data* data = thread_data->private_data = thread_data->private_memory;

	printf ("ipserver thread data is %p\n", thread_data);

	init_data(data);

	pthread_cleanup_push(ipserver_network_cleanup, data);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_IPSERVER_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for ipserver module, max is %i\n", VL_IPSERVER_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_IPSERVER_MAX_SENDERS])(struct module_thread_data *data, void (*callback)(void *caller_data, char *data, unsigned long int size), struct module_thread_data *caller_data);

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


	for (int i = 0; i < senders_count; i++) {
		while (thread_get_state(thread_data->senders[i]->thread) != VL_THREAD_STATE_RUNNING && thread_check_encourage_stop(thread_data->thread) != 1) {
			update_watchdog_time(thread_data->thread);
			printf ("ipserver: Waiting for source thread to become ready\n");
			usleep (5000);
		}
	}

	network_restart:
	ipserver_network_cleanup(data);
	ipserver_network_start(data);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

/*		printf ("ipserver polling data\n");
		for (int i = 0; i < senders_count; i++) {
			int res = poll[i](thread_data->senders[i], poll_callback, thread_data);
			if (!(res >= 0)) {
				printf ("ipserver module received error from poll function\n");
				err = 1;
				break;
			}
		}*/

		printf ("ipserver receiving data\n");
		if (receive_packets(data) != 0) {
			usleep (1249000); // 1249 ms
			goto network_restart;
		}

		printf ("ipserver processing data\n");
		process_entries(data);

		if (err != 0) {
			break;
		}
		usleep (1249000); // 1249 ms
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

