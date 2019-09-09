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
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef VL_WITH_OPENSSL
#include "../lib/module_crypt.h"
#endif

#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/poll_helper.h"
#include "../lib/ip.h"
#include "../lib/rrr_socket.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_IPCLIENT_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPCLIENT_SERVER_NAME "localhost"
#define VL_IPCLIENT_SERVER_PORT "5555"
#define VL_IPCLIENT_LOCAL_PORT 5555
#define VL_IPCLIENT_SEND_RATE 50 // Time between sending packets, milliseconds
#define VL_IPCLIENT_BURST_LIMIT 20 // Number of packets to send before we switch to reading
#define VL_IPCLIENT_SEND_INTERVAL 10000 // Milliseconds before resending a packet

struct ipclient_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer local_output_buffer;

	char *ip_server;
	char *ip_port;
#ifdef VL_WITH_OPENSSL
	char *crypt_file;
	struct module_crypt_data crypt_data;
#endif

	struct ip_data ip;
	pthread_t receive_thread;
	pthread_mutex_t network_lock;
	int receive_thread_died;
	int receive_thread_started;
	struct ip_stats_twoway stats;
	int no_ack;

	struct rrr_socket_read_session_collection read_sessions;
};

void data_cleanup(void *arg) {
	struct ipclient_data *data = arg;
#ifdef VL_WITH_OPENSSL
	RRR_FREE_IF_NOT_NULL(data->crypt_file);
#endif
	RRR_FREE_IF_NOT_NULL(data->ip_port);
	RRR_FREE_IF_NOT_NULL(data->ip_server);
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->local_output_buffer);
	rrr_socket_read_session_collection_destroy(&data->read_sessions);
}

int data_init(struct ipclient_data *data) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;
	ret |= fifo_buffer_init_custom_free(&data->send_buffer, ip_buffer_entry_destroy_void);
	ret |= fifo_buffer_init(&data->local_output_buffer);
	ret |= pthread_mutex_init(&data->network_lock, NULL);
	if (ret != 0) {
		data_cleanup(data);
		goto err;
	}
	ret = ip_stats_init_twoway(&data->stats, VL_IP_STATS_DEFAULT_PERIOD, "ipclient");
	err:
	return (ret != 0);
}

int parse_config (struct ipclient_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_server, config, "ipclient_server")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing ipclient_server settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->ip_server = malloc(strlen(VL_IPCLIENT_SERVER_NAME) + 1);
		if (data->ip_server == NULL) {
			VL_MSG_ERR("Could not allocate memory in ipclient parse_config\n");
			goto out;
		}
		strcpy(data->ip_server, VL_IPCLIENT_SERVER_NAME);
		ret = 0;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_port, config, "ipclient_server_port")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing ipclient_server_port settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->ip_port = malloc(strlen(VL_IPCLIENT_SERVER_PORT) + 1);
		if (data->ip_port == NULL) {
			VL_MSG_ERR("Could not allocate memory in ipclient parse_config\n");
			goto out;
		}
		strcpy(data->ip_port, VL_IPCLIENT_SERVER_PORT);
		ret = 0;
	}

#ifdef VL_WITH_OPENSSL
	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->crypt_file, config, "ipclient_keyfile")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing ipclient_keyfile settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->crypt_file = NULL;
		ret = 0;
	}
#endif

	if ((ret = rrr_instance_config_check_yesno(&data->no_ack, config, "ipclient_no_ack")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Syntax error in avg_preserve_points for instance %s, specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		data->no_ack = 0;
		ret = 0;
	}

	rrr_setting_uint src_port;
	if ((ret = rrr_instance_config_read_port_number(&src_port, config, "ipclient_src_port")) == 0) {
		data->ip.port = src_port;
	}
	else if (ret == RRR_SETTING_NOT_FOUND) {
		data->ip.port = VL_IPCLIENT_LOCAL_PORT;
		ret = 0;
	}
	else {
		VL_MSG_ERR("ipclient: Could not understand ipclient_src_port argument, must be numeric\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}
// Poll request from other modules
int ipclient_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct ipclient_data *ipclient_data = data->private_data;

	return fifo_read_clear_forward(&ipclient_data->local_output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

int poll_callback (struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *private_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;
	struct ip_buffer_entry *entry = NULL;

	int ret = 0;

	VL_DEBUG_MSG_3 ("ipclient: Result from buffer: timestamp %" PRIu64 " measurement %" PRIu64 " size %lu\n", message->timestamp_from, message->data_numeric, size);

	if (ip_buffer_entry_new(&entry, sizeof(*message) - 1 + message->length, NULL, 0, message) != 0) {
		VL_MSG_ERR("Could not create ip buffer entry in ipclient poll_callback\n");
		ret = 1;
		free(data);
	}
	else {
		fifo_buffer_write(&private_data->send_buffer, (char*)entry, sizeof(*entry));
	}

	return ret;
}

int send_packet_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct ip_send_packet_info *info = poll_data->private_data;
	struct instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *ipclient_data = thread_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;
	const struct vl_message *message = entry->message;

	uint64_t time_now = time_get_64();

	VL_DEBUG_MSG_3 ("ipclient send packet timestamp %" PRIu64 " size %lu\n", message->timestamp_from, size);

	// Check if we sent this packet recently
	if (entry->send_time + VL_IPCLIENT_SEND_INTERVAL * 1000 > time_now) {
		VL_DEBUG_MSG_3 ("ipclient: Not sending packet with timestamp %" PRIu64", it was sent recently\n", message->timestamp_from);
		return FIFO_SEARCH_KEEP;
	}

	entry->send_time = time_now;

	if (ip_send_message (
			message,
#ifdef VL_WITH_OPENSSL
			&ipclient_data->crypt_data,
#endif
			info,
			VL_DEBUGLEVEL_2 ? &ipclient_data->stats.send : NULL
	) != 0) {
		return FIFO_CALLBACK_ERR;
	}

	info->packet_counter++;

	if (info->packet_counter == VL_IPCLIENT_BURST_LIMIT) {
		VL_DEBUG_MSG_2 ("ipclient burst limit reached\n");
		return FIFO_SEARCH_STOP;
	}

	update_watchdog_time(thread_data->thread);
	usleep (VL_IPCLIENT_SEND_RATE * 1000);

	if (ipclient_data->no_ack == 1) {
		return FIFO_SEARCH_GIVE | FIFO_SEARCH_FREE;
	}
	else {
		return FIFO_SEARCH_KEEP;
	}
}

int receive_packets_search_callback (struct fifo_callback_args *callback_data, char *data, unsigned long int size) {
	struct vl_message *message_to_match = callback_data->private_data;
	struct ip_buffer_entry *checked_entry = (struct ip_buffer_entry *) data;
	const struct vl_message *message = checked_entry->message;

	VL_DEBUG_MSG_4("ipclient reive_packets_search_callback got packet from buffer of size %lu\n", size);

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG ("ipclient: match class %" PRIu32 " vs %" PRIu32 "\n", message_to_match->class, message->class);
		VL_DEBUG_MSG ("ipclient: match timestamp from %" PRIu64 " vs %" PRIu64 "\n", message_to_match->timestamp_from, message->timestamp_from);
		VL_DEBUG_MSG ("ipclient: match timestamp to %" PRIu64 " vs %" PRIu64 "\n", message_to_match->timestamp_to, message->timestamp_to);
		VL_DEBUG_MSG ("ipclient: match length %" PRIu32 " vs %" PRIu32 "\n", message_to_match->length, message->length);
	}

	if (	message_to_match->class == message->class &&
			message_to_match->timestamp_from == message->timestamp_from &&
			message_to_match->timestamp_to == message->timestamp_to
	) {
		VL_DEBUG_MSG_2 ("ipclient received ACK for message with timestamp %" PRIu64 "\n", message->timestamp_from);
		return FIFO_SEARCH_GIVE | FIFO_SEARCH_FREE | FIFO_SEARCH_STOP;
	}

	return FIFO_SEARCH_KEEP;
}

int receive_packets_callback(struct ip_buffer_entry *entry, void *arg) {
	struct ipclient_data *data = arg;
	struct vl_message *message = entry->message;

	VL_DEBUG_MSG_3 ("ipclient: Received packet from server type %" PRIu32 " with timestamp %" PRIu64 "\n",
			message->type, message->timestamp_to);

	// First, check if package is an ACK from the server in case we should delete
	// the original message from our send queue. If not, we let some other module
	// pick the packet up.
	if (MSG_IS_ACK(message)) {
		if (data->no_ack == 1) {
			VL_DEBUG_MSG_3 ("ipclient: Message was ACK but it is disabled, ignoring\n");
		}
		else {
			struct fifo_callback_args callback_args;
			callback_args.source = data;
			callback_args.private_data = message;
			fifo_search(&data->send_buffer, receive_packets_search_callback, &callback_args, 50);
		}
	}
	else {
		VL_DEBUG_MSG_3 ("ipclient: Write message with timestamp %" PRIu64 " to receive buffer\n",
				message->timestamp_from);
		fifo_buffer_write(&data->local_output_buffer, (char*) message, sizeof(*message));
		entry->message = NULL;
	}

	ip_buffer_entry_destroy_void(entry);

	return VL_IP_RECEIVE_OK;
}

int receive_packets(struct ipclient_data *data) {
//	struct fifo_callback_args poll_data = {NULL, data, 0};
	return ip_receive_messages (
			&data->read_sessions,
			data->ip.fd,
#ifdef VL_WITH_OPENSSL
			&data->crypt_data,
#endif
			receive_packets_callback,
			data,
			VL_DEBUGLEVEL_2 ? &data->stats.receive : NULL
	);
}

int send_packets(struct instance_thread_data *thread_data) {
	struct ipclient_data *data = thread_data->private_data;
	const char* hostname = data->ip_server;
	const char* portname = data->ip_port;

	struct addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;

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

	struct fifo_callback_args poll_data = {thread_data, &info, 0};
	err = fifo_search(&data->send_buffer, send_packet_callback, &poll_data, 50);

	if (info.packet_counter > 0) {
		VL_DEBUG_MSG_2 ("ipclient sent %i packets\n", info.packet_counter);
	}

	freeaddrinfo(res);

	return err;

	out_error_nofree:
	return 1;
}

void ipclient_receive_thread_cleanup_unlock_network(void *arg) {
	struct instance_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;
	pthread_mutex_unlock(&data->network_lock);
}

void ipclient_receive_thread_cleanup_set_died(void *arg) {
	struct instance_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;
	data->receive_thread_died = 1;
}

static void *thread_ipclient_receive(void *arg) {
	struct instance_thread_data *thread_data = arg;
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
	struct instance_thread_data *thread_data = arg;
	struct ipclient_data* data = thread_data->private_data;
	if (data->receive_thread_started == 1 && data->receive_thread_died != 1) {
		pthread_detach(data->receive_thread);
		pthread_cancel(data->receive_thread);
		int maxrounds = 4;
		while (data->receive_thread_died != 1) {
			VL_DEBUG_MSG_1 ("Waiting for ipclient receive thread to die\n");
			usleep(10000);
			if (--maxrounds == 0) {
				VL_MSG_ERR ("Could not join with ipclient receive thread\n");
				break;
			}
		}
		VL_DEBUG_MSG_1 ("ipclient joined with receive thread successfully\n");
	}
}

int start_receive_thread(struct instance_thread_data *thread_data) {
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

static void *thread_entry_ipclient (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct ipclient_data* data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data) != 0) {
		VL_MSG_ERR("Could not initialize data in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("ipclient thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(ip_network_cleanup, &data->ip);
	pthread_cleanup_push(stop_receive_thread, thread_data);
#ifdef VL_WITH_OPENSSL
	pthread_cleanup_push(module_crypt_data_cleanup, &data->crypt_data);
#endif
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parse failed for ipclient instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("Ipclient requires poll_delete from senders\n");
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("ipclient started thread %p\n", thread_data);

#ifdef VL_WITH_OPENSSL
	if (	data->crypt_file != NULL &&
			module_crypt_data_init(&data->crypt_data, data->crypt_file) != 0
	) {
		VL_MSG_ERR("ipclient: Cannot continue without crypt library\n");
		goto out_message;
	}
#endif

	network_restart:
	VL_DEBUG_MSG_2 ("ipclient restarting network\n");
	stop_receive_thread(thread_data);
	ip_network_cleanup(&data->ip);
	if (ip_network_start_udp_ipv4(&data->ip) != 0) {
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
		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		update_watchdog_time(thread_data->thread);
		if (send_packets(thread_data) != 0 || data->receive_thread_died == 1) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		if (err != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread ipclient %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
#ifdef VL_WITH_OPENSSL
	pthread_cleanup_pop(1);
#endif
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	pthread_exit(0);

}

static int test_config (struct rrr_instance_config *config) {
	struct ipclient_data data;
	int ret;

	if ((ret = data_init(&data)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);

	err:
	data_cleanup(&data);
	return ret;
}

static struct module_operations module_operations = {
		NULL,
		thread_entry_ipclient,
		NULL,
		NULL,
		NULL,
		ipclient_poll_delete,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "ipclient";

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
	VL_DEBUG_MSG_1 ("Destroy ipclient module\n");
}

