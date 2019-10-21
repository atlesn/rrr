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
/*
#ifdef VL_WITH_OPENSSL
#include "../lib/module_crypt.h"
#endif
*/
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/poll_helper.h"
#include "../lib/udpstream.h"
#include "../lib/rrr_socket.h"
#include "../lib/rrr_socket_common.h"
#include "../lib/gnu.h"
#include "../lib/linked_list.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_IPCLIENT_MAX_SENDERS VL_MODULE_MAX_SENDERS
#define VL_IPCLIENT_SERVER_NAME "localhost"
#define VL_IPCLIENT_SERVER_PORT "5555"
#define VL_IPCLIENT_LOCAL_PORT 5555
//#define VL_IPCLIENT_SEND_RATE 50 // Time between sending packets, milliseconds
//#define VL_IPCLIENT_BURST_LIMIT 50 // Number of packets to send before we switch to reading
//#define VL_IPCLIENT_SEND_INTERVAL 1000 // Milliseconds before resending a packet
#define VL_IPCLIENT_SEND_BUFFER_MAX 100000 // Max unsent messages to store from senders
#define VL_IPCLIENT_SEND_BUFFER_MIN 20000 // Max unsent messages to store from senders
#define VL_IPCLIENT_CONNECT_TIMEOUT_MS 5000
#define VL_IPCLIENT_CONCURRENT_CONNECTIONS 10

struct ipclient_destination {
	RRR_LL_NODE(struct ipclient_destination);
	struct sockaddr *addr;
	socklen_t addrlen;
	uint32_t connect_handle;
	uint64_t connect_time;
};

struct ipclient_destination_collection {
	RRR_LL_HEAD(struct ipclient_destination);
};

struct connect_handle {
	uint32_t connect_handle;
	uint64_t start_time;
	int is_established;
};

struct ipclient_data {
	struct fifo_buffer send_buffer;
	struct fifo_buffer local_output_buffer;

	struct instance_thread_data *thread_data;

	int listen;

	char *ip_default_remote;
	char *ip_default_remote_port;

	rrr_setting_uint src_port;
	/*
#ifdef VL_WITH_OPENSSL
	char *crypt_file;
	struct module_crypt_data crypt_data;
#endif
*/
	struct rrr_udpstream udpstream;
	uint32_t active_connect_handle;
	struct connect_handle connect_handles[VL_IPCLIENT_CONCURRENT_CONNECTIONS];

	struct ipclient_destination_collection destinations;
};

static int __ipclient_destination_destroy (struct ipclient_destination *dest) {
	RRR_FREE_IF_NOT_NULL(dest->addr);
	free(dest);
	return 0;
}

static int __ipclient_destination_new (
		struct ipclient_destination **target,
		const struct sockaddr *addr,
		socklen_t addrlen
) {
	int ret = 0;

	struct ipclient_destination *result = malloc(sizeof(*result));
	if (result == NULL) {
		VL_MSG_ERR("Could not allocate memory in __ipclient_destination_new A\n");
		ret = 1;
		goto out;
	}
	memset(result, '\0', sizeof(*result));

	result->addr = malloc(addrlen);
	if (result->addr == NULL) {
		VL_MSG_ERR("Could not allocate memory in __ipclient_destination_new B\n");
		ret = 1;
		goto out;
	}

	memcpy(result->addr, addr, addrlen);
	result->addrlen = addrlen;

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		__ipclient_destination_destroy(result);
	}
	return ret;
}

static struct ipclient_destination *__ipclient_destination_find_or_create (
		struct ipclient_destination_collection *collection,
		const struct sockaddr *addr,
		socklen_t addrlen
) {
	struct ipclient_destination *result = NULL;

	RRR_LL_ITERATE_BEGIN(collection, struct ipclient_destination);
		if (node->addrlen == addrlen && memcmp(node->addr, addr, addrlen) == 0) {
			result = node;
			goto out;
		}
	RRR_LL_ITERATE_END(collection);

	if (__ipclient_destination_new(&result, addr, addrlen) != 0) {
		goto out;
	}

	RRR_LL_PUSH(collection, result);

	out:
	return result;
}

void data_cleanup(void *arg) {
	struct ipclient_data *data = arg;
	/*
#ifdef VL_WITH_OPENSSL
	RRR_FREE_IF_NOT_NULL(data->crypt_file);
#endif
*/
	RRR_LL_DESTROY(&data->destinations, struct ipclient_destination, __ipclient_destination_destroy(node));
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote_port);
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote);
	fifo_buffer_invalidate(&data->send_buffer);
	fifo_buffer_invalidate(&data->local_output_buffer);
	rrr_udpstream_clear(&data->udpstream);
}

int data_init(struct ipclient_data *data, struct instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;
	ret |= fifo_buffer_init_custom_free(&data->send_buffer, ip_buffer_entry_destroy_void);
	ret |= fifo_buffer_init(&data->local_output_buffer);
	if (ret != 0) {
		data_cleanup(data);
		goto err;
	}
	data->thread_data = thread_data;
	rrr_udpstream_init(&data->udpstream, 0);
	err:
	return (ret != 0);
}

static void clean_destinations(struct ipclient_data *data) {
	uint64_t time_now = time_get_64();
	RRR_LL_ITERATE_BEGIN(&data->destinations, struct ipclient_destination);
		if (node->connect_time == 0) {
			node->connect_time = time_now;
		}
		if (node->connect_handle > 0) {
			int status = rrr_udpstream_connection_check(&data->udpstream, node->connect_handle);
			if (status == 0) {
				RRR_LL_ITERATE_NEXT();
			}
			else if (status == RRR_UDPSTREAM_NOT_READY) {
				if (time_now - node->connect_time > VL_IPCLIENT_CONNECT_TIMEOUT_MS * 1000) {
					RRR_LL_ITERATE_SET_DESTROY();
				}
			}
			else {
				RRR_LL_ITERATE_SET_DESTROY();
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->destinations, __ipclient_destination_destroy(node));
}

int parse_config (struct ipclient_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_default_remote, config, "ipclient_default_remote")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing ipclient_default_remote settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->ip_default_remote = NULL; //malloc(strlen(VL_IPCLIENT_SERVER_NAME) + 1);
		ret = 0;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_default_remote_port, config, "ipclient_default_remote_port")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing ipclient_default_remote_port settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_asprintf(&data->ip_default_remote_port, "%i", VL_IPCLIENT_LOCAL_PORT) <= 0) {
			VL_MSG_ERR("Could not allocate string for port number in ipclient instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
/*
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
*/
	if ((ret = rrr_instance_config_check_yesno(&data->listen, config, "ipclient_listen")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Syntax error in ipclient_listen for instance %s, specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		data->listen = 0;
		ret = 0;
	}

	rrr_setting_uint src_port;
	if ((ret = rrr_instance_config_read_port_number(&src_port, config, "ipclient_src_port")) == 0) {
		data->src_port = src_port;
	}
	else if (ret == RRR_SETTING_NOT_FOUND) {
		data->src_port = VL_IPCLIENT_LOCAL_PORT;
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

	if (ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(message), NULL, 0, message) != 0) {
		VL_MSG_ERR("Could not create ip buffer entry in ipclient poll_callback\n");
		ret = 1;
		free(data);
	}
	else {
		fifo_buffer_write(&private_data->send_buffer, (char*)entry, sizeof(*entry));
	}

	return ret;
}

static int connect_with_udpstream(struct ipclient_data *data) {
	int ret = 0;

	if (data->ip_default_remote == NULL) {
		goto out;
	}

	uint64_t time_now = time_get_64();
	int connect_max = 2;

	for (int i = 0; i < VL_IPCLIENT_CONCURRENT_CONNECTIONS; i++) {
		struct connect_handle *connect_handle = &data->connect_handles[i];

		// Check for connect timeout and check if alive
		if (connect_handle->connect_handle != 0) {
			if ((ret = rrr_udpstream_connection_check(&data->udpstream, connect_handle->connect_handle)) != 0) {
				if (ret == RRR_UDPSTREAM_NOT_READY) {
					if (time_now - connect_handle->start_time > VL_IPCLIENT_CONNECT_TIMEOUT_MS * 1000) {
						VL_MSG_ERR("CONNECT timed out for ipclient instance %s connect handle %u\n",
								INSTANCE_D_NAME(data->thread_data), connect_handle->connect_handle);
						connect_handle->connect_handle = 0;
					}
				}
				else if (ret == RRR_UDPSTREAM_RESET) {
					VL_DEBUG_MSG_2("CONNECT reset for ipclient %s connect handle %u\n",
							INSTANCE_D_NAME(data->thread_data), connect_handle->connect_handle);
					connect_handle->connect_handle = 0;
				}
				else {
					VL_MSG_ERR("CONNECT error %i while checking connection for ipclient instance %s connect handle %u\n",
							ret, INSTANCE_D_NAME(data->thread_data), connect_handle->connect_handle);
					connect_handle->connect_handle = 0;
				}
				ret = 0;
			}
			else {
				connect_handle->is_established = 1;
			}

			if (connect_handle->is_established == 0 && time_now - connect_handle->start_time > VL_IPCLIENT_CONNECT_TIMEOUT_MS * 1000) {
				connect_handle->connect_handle = 0;
			}
		}

		// Check for sending new CONNECT
		if (connect_handle->connect_handle == 0 && connect_max-- > 0) {
			connect_handle->is_established = 0;
			connect_handle->start_time = time_now;
			if (rrr_udpstream_connect(&connect_handle->connect_handle, &data->udpstream, data->ip_default_remote, data->ip_default_remote_port) != 0) {
				VL_MSG_ERR("UDP-stream could not connect in ipclient instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				ret = 1;
				goto out;
			}
		}

		// Check for setting active connect handle
		if (data->active_connect_handle == 0 && connect_handle->is_established != 0) {
			data->active_connect_handle = connect_handle->connect_handle;
		}
	}

	out:
	return ret;
}

static void invalidate_connect_handle (struct ipclient_data *data, uint16_t connect_handle) {
	for (int i = 0; i < VL_IPCLIENT_CONCURRENT_CONNECTIONS; i++) {
		struct connect_handle *cur = &data->connect_handles[i];

		if (cur->connect_handle == connect_handle) {
			cur->connect_handle = 0;
		}
	}

	if (data->active_connect_handle == connect_handle) {
		data->active_connect_handle = 0;
	}
}

struct receive_packets_callback_data {
	struct ipclient_data *data;
	int count;
	struct rrr_udpstream_receive_data *receive_data;
};

int receive_messages_callback(struct vl_message *message, void *arg) {
	struct receive_packets_callback_data *receive_packets_callback_data = arg;
	struct ipclient_data *data = receive_packets_callback_data->data;

	VL_DEBUG_MSG_3 ("ipclient: Write message with timestamp %" PRIu64 " to receive buffer\n",
			message->timestamp_from);

	fifo_buffer_write(&data->local_output_buffer, (char*) message, sizeof(*message));

	receive_packets_callback_data->count++;

	return VL_IP_RECEIVE_OK;
}

int receive_packets_callback(struct rrr_udpstream_receive_data *receive_data, void *arg) {
	struct receive_packets_callback_data *receive_packets_callback_data = arg;

	receive_packets_callback_data->receive_data = receive_data;

	struct rrr_socket_common_receive_message_callback_data callback_data = {
			receive_messages_callback, receive_packets_callback_data
	};

	if (rrr_socket_common_receive_message_raw_callback (
			receive_data->data,
			receive_data->data_size,
			&callback_data
	) != 0) {
		VL_MSG_ERR("Error while processign message in receive_packets_callback of ipclient instance %s\n",
				INSTANCE_D_NAME(receive_packets_callback_data->data->thread_data));
	}

	receive_packets_callback_data->receive_data = NULL;

	return 0;
}

int receive_packets(int *receive_count, struct ipclient_data *data) {
	int ret = 0;

	*receive_count = 0;

	if ((ret = rrr_udpstream_do_read_tasks(&data->udpstream)) != 0) {
		if (ret != RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Error from UDP-stream while reading data in receive_packets of ipclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	struct receive_packets_callback_data callback_data = {
			data, 0, NULL
	};

	if ((ret = rrr_udpstream_do_process_receive_buffers (
			&data->udpstream,
			rrr_socket_common_get_session_target_length_from_message_and_checksum_raw,
			NULL,
			receive_packets_callback,
			&callback_data
	)) != 0) {
		VL_MSG_ERR("Error from UDP-stream while processing buffers in receive_packets of ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	*receive_count = callback_data.count;

	out:
	return ret;
}

struct send_packet_callback_data {
	int packet_counter;
};

int send_packet_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct send_packet_callback_data *info = poll_data->private_data;
	struct instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *ipclient_data = thread_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;
	const struct vl_message *message = entry->message;

	struct vl_message *message_network = NULL;

	int ret = 0;

	VL_DEBUG_MSG_3 ("ipclient queing packet for sending timestamp %" PRIu64 " size %lu\n", message->timestamp_from, size);

	update_watchdog_time(thread_data->thread);

	struct ipclient_destination *destination = NULL;
	uint32_t connect_handle = 0;

	if (entry->addr_len != 0) {
		struct ipclient_destination *destination = __ipclient_destination_find_or_create (
				&ipclient_data->destinations,
				&entry->addr,
				entry->addr_len
		);

		if (destination != NULL) {
			if (destination->connect_handle == 0) {
				if (rrr_udpstream_connect_raw (
						&destination->connect_handle,
						&ipclient_data->udpstream,
						destination->addr,
						destination->addrlen
				) != 0) {
					VL_MSG_ERR("Could not send connect packet with address information from message in ipclient instance %s, packet must be dropped\n",
							INSTANCE_D_NAME(thread_data));
					ret = FIFO_SEARCH_GIVE | FIFO_SEARCH_FREE;
					goto out;
				}

				// Do housekeeping here (a quiet place) to avoid doing it repeatedly
				clean_destinations(ipclient_data);

				// Don't try to send the message immediately, will most likely block
				ret = FIFO_SEARCH_KEEP;
				goto out;
			}
			connect_handle = destination->connect_handle;
		}
	}
	else if (ipclient_data->ip_default_remote != NULL) {
		connect_handle = ipclient_data->active_connect_handle;
		if (connect_handle == 0) {
			// Connection not ready
			ret = FIFO_SEARCH_KEEP;
			goto out;
		}
	}
	else {
		VL_MSG_ERR("ipclient instance %s dropping message from sender without address information\n",
				INSTANCE_D_NAME(thread_data));
		ret = FIFO_SEARCH_GIVE | FIFO_SEARCH_FREE;
		goto out;
	}

	message_network = message_duplicate(message);
	ssize_t message_network_size = MSG_TOTAL_SIZE(message_network);

	message_prepare_for_network((struct vl_message *) message_network);
	rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message_network);

	if ((ret = rrr_udpstream_queue_outbound_data (
			&ipclient_data->udpstream,
			connect_handle,
			message_network,
			message_network_size
	)) != 0) {
		if (ret == RRR_UDPSTREAM_BUFFER_FULL || ret == RRR_UDPSTREAM_NOT_READY) {
			ret = FIFO_SEARCH_KEEP | FIFO_SEARCH_STOP;
			goto out;
		}
		else if (ret == RRR_UDPSTREAM_IDS_EXHAUSTED || ret == RRR_UDPSTREAM_UNKNOWN_CONNECT_ID) {
			// Stop using this stream, a new one must be created
			if (destination != NULL) {
				destination->connect_handle = 0;
			}
			else {
				invalidate_connect_handle(ipclient_data, connect_handle);
			}
			ret = FIFO_SEARCH_KEEP;
			goto out;
		}
		else {
			VL_MSG_ERR("Error while queuing message for sending in ipclient instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = FIFO_SEARCH_KEEP | FIFO_CALLBACK_ERR;
			goto out;
		}
	}

	info->packet_counter++;

	ret = FIFO_SEARCH_GIVE | FIFO_SEARCH_FREE;

	out:
	RRR_FREE_IF_NOT_NULL(message_network);
	return ret;
}

int send_packets(int *send_count, struct ipclient_data *data) {
	int ret = 0;

	*send_count = 0;

	if (fifo_buffer_get_entry_count(&data->send_buffer) > 0) {
		struct send_packet_callback_data callback_data = {
				0
		};
		struct fifo_callback_args poll_data = {
				data->thread_data, &callback_data, 0
		};
		ret = fifo_search(&data->send_buffer, send_packet_callback, &poll_data, 0);

		if (callback_data.packet_counter > 0) {
			VL_DEBUG_MSG_3 ("ipclient instance %s queued %i packets for transmission\n",
					INSTANCE_D_NAME(data->thread_data), callback_data.packet_counter);
		}
	}

	if ((ret = rrr_udpstream_do_send_tasks(send_count, &data->udpstream)) != 0) {
		VL_MSG_ERR("UDP-stream send tasks failed in send_packets of ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
	}

	return ret;
}

static int receive_data(int *receive_count, struct ipclient_data *data) {
	int ret = 0;

//	update_watchdog_time(data->thread_data->thread);

	// TODO : Handle bad errors->exit and nice errors->continue
	if (receive_packets(receive_count, data) != 0) {
		VL_MSG_ERR ("Error while receiving packets in ipclient receive_data thread\n");
		ret = 1;
		goto out;
	}

	if (*receive_count > 0) {
		VL_DEBUG_MSG_2("ipclient instance %s: received %i messages\n",
				INSTANCE_D_NAME(data->thread_data), *receive_count);
	}

	out:
	return ret;
}

static void *thread_entry_ipclient (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data, thread_data) != 0) {
		VL_MSG_ERR("Could not initialize data in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("ipclient thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parse failed for ipclient instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_NO_SENDERS_OK) != 0) {
		VL_MSG_ERR("Ipclient requires poll_delete from senders\n");
		goto out_message;
	}

	int no_polling = poll_collection_count(&poll) > 0 ? 0 : 1;

	VL_DEBUG_MSG_1 ("ipclient started thread %p\n", thread_data);
/*
#ifdef VL_WITH_OPENSSL
	if (	data->crypt_file != NULL &&
			module_crypt_data_init(&data->crypt_data, data->crypt_file) != 0
	) {
		VL_MSG_ERR("ipclient: Cannot continue without crypt library\n");
		goto out_message;
	}
#endif
*/

	network_restart:
	VL_DEBUG_MSG_2 ("ipclient restarting network\n");

	// Only close here and not when shutting down the thread (might cause
	// deadlock in rrr_socket). rrr_socket cleanup will close the socket if we exit.
	rrr_udpstream_close(&data->udpstream);
	rrr_udpstream_set_flags(&data->udpstream, data->listen != 0 ? RRR_UDPSTREAM_FLAGS_ACCEPT_CONNECTIONS : 0);
	if (rrr_udpstream_bind(&data->udpstream, data->src_port) != 0) {
		VL_MSG_ERR("UDP-stream could not bind in ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out_message;
	}

	int consecutive_zero_recv_and_send = 0;
	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		if (connect_with_udpstream(data) != 0) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		int send_buffer_size_before = fifo_buffer_get_entry_count(&data->send_buffer);
		if (no_polling == 0 && send_buffer_size_before < VL_IPCLIENT_SEND_BUFFER_MIN) {
			int send_buffer_size_before = 0;
			int send_buffer_size_after = 0;
			do {
				send_buffer_size_before = fifo_buffer_get_entry_count(&data->send_buffer);

				if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
					break;
				}

				send_buffer_size_after = fifo_buffer_get_entry_count(&data->send_buffer);
			} while (send_buffer_size_after - send_buffer_size_before >= FIFO_MAX_READS && send_buffer_size_after < VL_IPCLIENT_SEND_BUFFER_MAX);
//			VL_DEBUG_MSG_2("ipclient instance %s receive buffer size %i\n",
//					INSTANCE_D_NAME(thread_data), send_buffer_size_after);
		}

//		VL_DEBUG_MSG_2("ipclient instance %s receive\n",
//				INSTANCE_D_NAME(thread_data));
		int receive_count = 0;
		if (receive_data(&receive_count, data) != 0) {
			usleep (10000); // 10 ms
			goto network_restart;
		}

		int send_count = 0;
		update_watchdog_time(thread_data->thread);
		if (send_packets(&send_count, data) != 0) {
			usleep (10000); // 10 ms
			goto network_restart;
		}

		if (receive_count == 0 && send_count == 0) {
			if (consecutive_zero_recv_and_send > 1000) {
				VL_DEBUG_MSG_2("ipclient instance %s long sleep send buffer size %i\n",
						INSTANCE_D_NAME(thread_data), fifo_buffer_get_entry_count(&data->send_buffer));
				usleep (100000); // 100 ms
			}
			else {
				sched_yield();
				usleep(1000);
				consecutive_zero_recv_and_send++;
//				printf("ipclient instance %s yield\n", INSTANCE_D_NAME(thread_data));
			}
		}
		else {
			consecutive_zero_recv_and_send = 0;
			VL_DEBUG_MSG_3("ipclient instance %s receive count %i send count %i\n",
					INSTANCE_D_NAME(thread_data), receive_count, send_count);
		}

		if (err != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread ipclient %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	pthread_exit(0);

}

static int test_config (struct rrr_instance_config *config) {
	struct ipclient_data data;
	int ret;

	if ((ret = data_init(&data, NULL)) != 0) {
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
	data->type = VL_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = VL_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy ipclient module\n");
}

