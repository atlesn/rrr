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

#define _GNU_SOURCE // for pthread_tryjoin_np

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
#include <poll.h>

#include "../modules.h"
#include "../lib/module_crypt.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/cmdlineparser/cmdline.h"
#include "../global.h"
#include "common/ip.h"

// Should not be smaller than module max
#define VL_IPCLIENT_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPCLIENT_SERVER_NAME "localhost"
#define VL_IPCLIENT_SERVER_PORT "5555"
#define VL_IPCLIENT_SEND_RATE 50 // Time between sending packets, milliseconds
#define VL_IPCLIENT_BURST_LIMIT 20 // Number of packets to send before we switch to reading
#define VL_IPCLIENT_SEND_INTERVAL 10000 // Milliseconds before resending a packet

struct ipclient_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer receive_buffer;
	const char *ip_server;
	const char *ip_port;
	const char *crypt_file;
	struct ip_data ip;
	pthread_t receive_thread;
	pthread_mutex_t network_lock;
	int receive_thread_died;
	int receive_thread_started;
	struct module_crypt_data crypt_data;
	struct ip_stats_twoway stats;
};

void init_data(struct ipclient_data *data) {
	if (sizeof(*data) > VL_MODULE_PRIVATE_MEMORY_SIZE) {
		VL_MSG_ERR ("ipclient: Module thread private memory area too small\n");
		exit(EXIT_FAILURE);
	}
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->send_buffer);
	fifo_buffer_init(&data->receive_buffer);
	pthread_mutex_init(&data->network_lock, NULL);
	ip_stats_init_twoway(&data->stats, VL_IP_STATS_DEFAULT_PERIOD, "ipclient");
}

void data_cleanup(void *arg) {
	struct ipclient_data *data = arg;
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->receive_buffer);
}

static int parse_cmd (struct ipclient_data *data, struct cmd_data *cmd) {
	const char *ip_server = cmd_get_value(cmd, "ipclient_server", 0);
	const char *ip_port = cmd_get_value(cmd, "ipclient_server_port", 0);
	const char *crypt_file = cmd_get_value(cmd, "ipclient_keyfile", 0);

	data->ip_server = VL_IPCLIENT_SERVER_NAME;
	data->ip_port = VL_IPCLIENT_SERVER_PORT;
	data->crypt_file = NULL;

	if (ip_server != NULL) {
		data->ip_server = ip_server;
	}
	if (ip_port != NULL) {
		data->ip_port = ip_port;
	}
	if (crypt_file != NULL) {
		data->crypt_file = crypt_file;
	}

	return 0;
}

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

	VL_DEBUG_MSG_2 ("ipclient: Result from buffer: %s measurement %" PRIu64 " size %lu\n", reading->data, reading->data_numeric, size);

	struct ip_buffer_entry *entry = malloc(sizeof(*entry));
	memset(entry, '\0', sizeof(*entry));
	memcpy(&entry->message, reading, sizeof(entry->message));
	free(data);

	fifo_buffer_write(&private_data->send_buffer, (char*)entry, sizeof(*entry));

	return 0;
}

int send_packet_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ip_send_packet_info *info = poll_data->private_data;
	struct module_thread_data *thread_data = poll_data->source;
	struct ipclient_data *ipclient_data = thread_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;
	struct vl_message *message = &entry->message;

	uint64_t time_now = time_get_64();

	// Check if we sent this packet recently
	if (entry->time + VL_IPCLIENT_SEND_INTERVAL * 1000 > time_now) {
		VL_DEBUG_MSG_3 ("ipclient: Not sending packet with timestamp %" PRIu64", it was sent recently\n", message->timestamp_from);
		return FIFO_SEARCH_KEEP;
	}

	entry->time = time_now;

	if (ip_send_packet(
			message,
			&ipclient_data->crypt_data,
			info,
			VL_DEBUGLEVEL_2 ? &ipclient_data->stats.send : NULL
	) != 0) {
		return FIFO_SEARCH_ERR;
	}

	info->packet_counter++;

	if (info->packet_counter == VL_IPCLIENT_BURST_LIMIT) {
		VL_DEBUG_MSG_2 ("ipclient burst limit reached\n");
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
	struct ip_buffer_entry *checked_entry = (struct ip_buffer_entry *) data;
	struct vl_message *message = &checked_entry->message;

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG ("ipclient: match class %" PRIu32 " vs %" PRIu32 "\n", message_to_match->class, message->class);
		VL_DEBUG_MSG ("ipclient: match timestamp from %" PRIu64 " vs %" PRIu64 "\n", message_to_match->timestamp_from, message->timestamp_from);
		VL_DEBUG_MSG ("ipclient: match timestamp to %" PRIu64 " vs %" PRIu64 "\n", message_to_match->timestamp_to, message->timestamp_to);
		VL_DEBUG_MSG ("ipclient: match length %" PRIu32 " vs %" PRIu32 "\n", message_to_match->length, message->length);
	}

	if (	message_to_match->class == message->class &&
			message_to_match->timestamp_from == message->timestamp_from &&
			message_to_match->timestamp_to == message->timestamp_to &&
			message_to_match->length == message->length
	) {
		VL_DEBUG_MSG_2 ("ipclient received ACK for message with timestamp %" PRIu64 "\n", message->timestamp_from);
		free(checked_entry);
		return FIFO_SEARCH_GIVE | FIFO_SEARCH_STOP;
	}

	return FIFO_SEARCH_KEEP;
}

int receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct ipclient_data *data = arg;
	struct vl_message *message = &entry->message;

	VL_DEBUG_MSG_3 ("ipclient: Received packet from server type %" PRIu32 " with timestamp %" PRIu64 "\n",
			entry->message.type, entry->message.timestamp_to);

	// First, check if package is an ACK from the server in case we should delete
	// the original message from our send queue. If not, we let some other module
	// pick the packet up.
	if (MSG_IS_ACK(message)) {
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

	return VL_IP_RECEIVE_OK;
}

int receive_packets(struct ipclient_data *data) {
	struct fifo_callback_args poll_data = {NULL, data};
	return ip_receive_packets(
			data->ip.fd,
			&data->crypt_data,
			receive_packets_callback,
			data,
			VL_DEBUGLEVEL_2 ? &data->stats.receive : NULL
	);
}

int send_packets(struct module_thread_data *thread_data) {
	struct ipclient_data *data = thread_data->private_data;
	const char* hostname = data->ip_server;
	const char* portname = data->ip_port;

	VL_DEBUG_MSG_2 ("ipclient: Send to %s:%s\n", hostname, portname);

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
		VL_MSG_ERR ("ipclient: Could not get address info of server %s port %s: %s\n", hostname, portname, gai_strerror(err));
		goto out_error_nofree;
	}

	struct ip_send_packet_info info;
	info.fd = data->ip.fd;
	info.res = res;
	info.packet_counter = 0;

	struct fifo_callback_args poll_data = {thread_data, &info};
	err = fifo_search(&data->send_buffer, send_packet_callback, &poll_data);

	VL_DEBUG_MSG_2 ("ipclient sent %i packets\n", info.packet_counter);

	freeaddrinfo(res);

	return err;

	out_error_nofree:
	return 1;
}

void ipclient_receive_thread_cleanup_unlock_network(void *arg) {
	struct module_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;
	pthread_mutex_unlock(&data->network_lock);
}

void ipclient_receive_thread_cleanup_set_died(void *arg) {
	struct module_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;
	data->receive_thread_died = 1;
}

static void *thread_ipclient_receive(void *arg) {
	struct module_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;

	pthread_cleanup_push(ipclient_receive_thread_cleanup_set_died, arg);

	while (1) {
		pthread_mutex_lock(&data->network_lock);
		pthread_cleanup_push(ipclient_receive_thread_cleanup_unlock_network, arg);
		update_watchdog_time(thread_data->thread);

		// TODO : Handle bad errors->exit and nice errors->continue
		if (receive_packets(data) != 0) {
			VL_MSG_ERR ("Error while receiving packets in ipclient receive thread\n");
		}

		pthread_cleanup_pop(1);
		usleep(10000); // 10ms
	}

	pthread_cleanup_pop(1);
	pthread_exit(0);
}

void stop_receive_thread(void *arg) {
	struct module_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;
	if (data->receive_thread_started == 1 && data->receive_thread_died != 1) {
		void *ret;
		pthread_cancel(data->receive_thread);
		int maxrounds = 4;
		while (data->receive_thread_died != 1) {
			VL_DEBUG_MSG_1 ("Waiting for ipclient receive thread to die\n");
			usleep(1000000);
			if (--maxrounds == 0) {
				VL_MSG_ERR ("Could not join with ipclient receive thread\n");
				break;
			}
		}
		int res = pthread_tryjoin_np(data->receive_thread, &ret);
		if (res != 0) {
			VL_MSG_ERR ("Could not joing with ipclient receive thread: %s\n", strerror(res));
		}
		VL_DEBUG_MSG_1 ("ipclient joined with receive thread successfully\n");
	}
}

int start_receive_thread(struct module_thread_data *thread_data) {
	struct ipclient_data* data = thread_data->private_data;

	if (data->receive_thread_started == 1 && data->receive_thread_died != 1) {
		VL_MSG_ERR ("Bug: Tried to start receive thread in ipclient while already started\n");
		return 1;
	}

	data->receive_thread_started = 0;
	data->receive_thread_died = 0;
	int err = pthread_create(&data->receive_thread, NULL, thread_ipclient_receive, thread_data);
	if (err != 0) {
		VL_MSG_ERR ("Error while starting ipclient receive thread: %s\n", strerror(err));
		return 1;
	}

	data->receive_thread_started = 1;
	return 0;
}

static void *thread_entry_ipclient(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct ipclient_data* data = thread_data->private_data = thread_data->private_memory;

	VL_DEBUG_MSG_1 ("ipclient thread data is %p\n", thread_data);

	init_data(data);
	pthread_cleanup_push(data_cleanup, data);

	parse_cmd(data, start_data->cmd);

	pthread_cleanup_push(ip_network_cleanup, &data->ip);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);
	pthread_cleanup_push(stop_receive_thread, thread_data);
	pthread_cleanup_push(module_crypt_data_cleanup, &data->crypt_data);

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	if (senders_count > VL_IPCLIENT_MAX_SENDERS) {
		VL_MSG_ERR ("Too many senders for ipclient module, max is %i\n", VL_IPCLIENT_MAX_SENDERS);
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
		VL_DEBUG_MSG_1 ("ipclient: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;

		if (poll[i] == NULL) {
			VL_MSG_ERR ("ipclient cannot use this sender, lacking poll delete function.\n");
			goto out_message;
		}
	}

	VL_DEBUG_MSG_1 ("ipclient started thread %p\n", thread_data);
	if (senders_count == 0) {
		VL_MSG_ERR ("Error: Sender was not set for ipclient processor module\n");
		goto out_message;
	}

	if (	data->crypt_file != NULL &&
			module_crypt_data_init(&data->crypt_data, data->crypt_file) != 0
	) {
		VL_MSG_ERR("ipclient: Cannot continue without crypt library\n");
		goto out_message;
	}

	network_restart:
	VL_DEBUG_MSG_2 ("ipclient restarting network\n");
	stop_receive_thread(thread_data);
	ip_network_cleanup(&data->ip);
	if (ip_network_start(&data->ip) != 0) {
		update_watchdog_time(thread_data->thread);
		usleep (1000000);
		goto network_restart;
	}
	if (start_receive_thread(thread_data) != 0) {
		VL_MSG_ERR ("Could not start ipclient receive thread\n");
		pthread_exit(0);
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		VL_DEBUG_MSG_5 ("ipclient polling data\n");
		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res = poll[i](thread_data->senders[i], poll_callback, &poll_data);
			if (!(res >= 0)) {
				VL_MSG_ERR ("ipclient module received error from poll function\n");
				err = 1;
				break;
			}
		}

		update_watchdog_time(thread_data->thread);
		if (send_packets(thread_data) != 0 || data->receive_thread_died == 1) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		if (err != 0) {
			break;
		}
		usleep (100000); // 100 ms
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread ipclient %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_ipclient,
		NULL,
		NULL,
		ipclient_poll_delete,
		NULL
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
	VL_DEBUG_MSG_1 ("Destroy ipclient module\n");
}

