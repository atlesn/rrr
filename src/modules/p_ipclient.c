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
#define VL_IPCLIENT_RESEND_INTERVAL_MS (RRR_UDPSTREAM_RESEND_INTERVAL_FRAME_MS * 4) // Milliseconds before resending a packet
#define VL_IPCLIENT_RELEASE_QUEUE_MAX 500 // Max unreleased messages awaiting release ACK
#define VL_IPCLIENT_RELEASE_QUEUE_URGE_TIMEOUT_MS 100 // Time before urging for release ACK

#define VL_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX 500 // Max unsent messages to store from other mmodules

#define VL_IPCLIENT_SEND_BUFFER_ASSURED_MAX 500 // Max unsent messages to store
#define VL_IPCLIENT_SEND_BUFFER_ASSURED_MIN 400 // Min unsent messages to store

#define VL_IPCLIENT_SEND_BUFFER_UNASSURED_MAX 20000 // Max unsent messages to store from senders
#define VL_IPCLIENT_SEND_BUFFER_UNASSURED MIN 10000 // Min unsent messages to store from senders

#define VL_IPCLIENT_CONNECT_TIMEOUT_MS 5000
#define VL_IPCLIENT_CONCURRENT_CONNECTIONS 3



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

struct ipclient_queue_entry {
	RRR_LL_NODE(struct ipclient_queue_entry);
	struct ip_buffer_entry *entry;
	uint16_t stream_id;
	uint64_t boundary_id_combined;
	uint64_t send_time;
	int no_more_sending;
};

struct ipclient_queue {
	RRR_LL_HEAD(struct ipclient_queue_entry);
};

struct ipclient_data {
	struct fifo_buffer local_output_buffer;
	struct fifo_buffer send_queue_intermediate;

	struct ipclient_queue release_queue;
	struct ipclient_queue send_queue;

	struct instance_thread_data *thread_data;

	int listen;
	int no_assured_single_delivery;

	uint64_t total_poll_count;
	uint64_t total_queued_count;

	// All messages get an ID used to assure exactly one delivery
	uint32_t send_boundary_low_pos;
	uint32_t send_boundary_high;

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

static int __ipclient_queue_entry_destroy (
		struct ipclient_queue_entry *entry
) {
	if (entry->entry != NULL) {
		ip_buffer_entry_destroy(entry->entry);
	}
	free(entry);
	return 0;
}

void data_cleanup(void *arg) {
	struct ipclient_data *data = arg;
	/*
#ifdef VL_WITH_OPENSSL
	RRR_FREE_IF_NOT_NULL(data->crypt_file);
#endif
*/
	RRR_LL_DESTROY(&data->release_queue, struct ipclient_queue_entry, __ipclient_queue_entry_destroy(node));
	RRR_LL_DESTROY(&data->send_queue, struct ipclient_queue_entry, __ipclient_queue_entry_destroy(node));
	RRR_LL_DESTROY(&data->destinations, struct ipclient_destination, __ipclient_destination_destroy(node));
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote_port);
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote);
	fifo_buffer_invalidate(&data->local_output_buffer);
	fifo_buffer_invalidate(&data->send_queue_intermediate);
	rrr_udpstream_clear(&data->udpstream);
}

int data_init(struct ipclient_data *data, struct instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;
	ret |= fifo_buffer_init_custom_free(&data->local_output_buffer, ip_buffer_entry_destroy_void);
	ret |= fifo_buffer_init_custom_free(&data->send_queue_intermediate, ip_buffer_entry_destroy_void);
	if (ret != 0) {
		data_cleanup(data);
		goto err;
	}
	data->thread_data = thread_data;
	rrr_udpstream_init(&data->udpstream, 0);
	err:
	return (ret != 0);
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

static void __ipclient_queue_remove_entry (
		struct ipclient_queue *queue,
		uint64_t boundary_id_combined
) {
	int iterations = 0;

	if (RRR_LL_COUNT(queue) == 0) {
		return;
	}

	if (boundary_id_combined < RRR_LL_FIRST(queue)->boundary_id_combined ||
		boundary_id_combined > RRR_LL_LAST(queue)->boundary_id_combined
	) {
		return;
	}

	int64_t diff_to_last = RRR_LL_LAST(queue)->boundary_id_combined - boundary_id_combined;
	int64_t diff_to_first = boundary_id_combined - RRR_LL_FIRST(queue)->boundary_id_combined;

	RRR_LL_ITERATE_BEGIN_EITHER(queue, struct ipclient_queue_entry, (diff_to_last < diff_to_first));
		iterations++;
//		printf ("cmp %" PRIu64 " vs %" PRIu64 "\n", boundary_id_combined, node->boundary_id_combined);
		if (node->boundary_id_combined == boundary_id_combined) {
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, __ipclient_queue_entry_destroy(node));

//	printf ("iterations to remove: %i\n", iterations);
}

static struct ip_buffer_entry *__ipclient_queue_remove_entry_and_get_data (
		struct ipclient_queue *queue,
		uint64_t boundary_id_combined
) {
	struct ip_buffer_entry *ret = NULL;

	RRR_LL_ITERATE_BEGIN(queue, struct ipclient_queue_entry);
//		VL_DEBUG_MSG("cmp boundary %" PRIu64 " vs %" PRIu64 "\n", boundary_id_combined, node->boundary_id_combined);
		if (node->boundary_id_combined == boundary_id_combined) {
			ret = node->entry;
			node->entry = NULL;
			RRR_LL_ITERATE_SET_DESTROY();
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(queue, __ipclient_queue_entry_destroy(node));

	return ret;
}

static struct ipclient_queue_entry *__ipclient_queue_find_entry (
		struct ipclient_queue *queue,
		uint64_t boundary_id_combined
) {
	if (RRR_LL_FIRST(queue) != NULL && boundary_id_combined < RRR_LL_FIRST(queue)->boundary_id_combined) {
		return NULL;
	}
	if (RRR_LL_LAST(queue) != NULL && boundary_id_combined > RRR_LL_LAST(queue)->boundary_id_combined) {
		return NULL;
	}

	RRR_LL_ITERATE_BEGIN(queue, struct ipclient_queue_entry);
		if (node->boundary_id_combined > boundary_id_combined) {
			return NULL;
		}
		if (node->boundary_id_combined == boundary_id_combined) {
			return node;
		}
	RRR_LL_ITERATE_END(queue);

	return NULL;
}


static void __ipclient_queue_set_entry_no_more_sending (
		struct ipclient_queue *queue,
		uint64_t boundary_id_combined
) {
	struct ipclient_queue_entry *entry = __ipclient_queue_find_entry(queue, boundary_id_combined);

	if (entry != NULL) {
		entry->no_more_sending = 1;
	}
}

static void __ipclient_queue_insert_ordered (
		struct ipclient_queue *queue,
		struct ipclient_queue_entry *entry
) {
	if (RRR_LL_LAST(queue) == NULL || RRR_LL_LAST(queue)->boundary_id_combined < entry->boundary_id_combined) {
//		VL_DEBUG_MSG("queue append entry with ip buf entry %p boundary %" PRIu64 "\n",
//				entry->entry, entry->boundary_id);
		RRR_LL_APPEND(queue, entry);
		return;
	}

	RRR_LL_ITERATE_BEGIN(queue, struct ipclient_queue_entry);
		if (entry->boundary_id_combined < node->boundary_id_combined) {
			RRR_LL_ITERATE_INSERT(queue, entry);
//			VL_DEBUG_MSG("queue insert entry with ip buf entry %p boundary %" PRIu64 " before %" PRIu64 "\n",
//					entry->entry, entry->boundary_id, node->boundary_id);
			entry = NULL;
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END();

	if (entry != NULL) {
		RRR_LL_ITERATE_BEGIN(queue, struct ipclient_queue_entry);
			VL_MSG_ERR("dump queue boundaries: %u - %" PRIu64 "\n", node->stream_id, node->boundary_id_combined);
		RRR_LL_ITERATE_END();
		VL_BUG("Entry with boundary %" PRIu64 " was not inserted in __ipclient_queue_insert_ordered\n", entry->boundary_id_combined);
	}
}

static int __ipclient_queue_insert_entry_or_destroy (
		struct ipclient_queue *queue,
		struct ip_buffer_entry *entry,
		uint16_t stream_id,
		uint64_t boundary_id
) {
	int ret = 0;
	struct ipclient_queue_entry *new_entry = NULL;

	if (__ipclient_queue_find_entry(queue, boundary_id) != NULL) {
		goto out;
	}

	if ((new_entry = malloc(sizeof(*new_entry))) == NULL) {
		VL_MSG_ERR("Could not allocate memory in __ipclient_queue_insert_entry_or_free\n");
		ret = 1;
		goto out;
	}
	memset(new_entry, '\0', sizeof(*new_entry));

	new_entry->stream_id = stream_id;
	new_entry->boundary_id_combined = boundary_id;
	new_entry->entry = entry;
	entry = NULL;

	__ipclient_queue_insert_ordered(queue, new_entry);
	new_entry = NULL;

	out:
	if (entry != NULL) {
		ip_buffer_entry_destroy(entry);
	}
	if (new_entry != NULL) {
		__ipclient_queue_entry_destroy(new_entry);
	}

	return ret;
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

	if ((ret = rrr_instance_config_check_yesno(&data->no_assured_single_delivery, config, "ipclient_no_assured_single_delivery")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Syntax error in ipclient_no_assured_single_delivery for instance %s, specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		data->no_assured_single_delivery = 0;
		ret = 0;
	}

	rrr_setting_uint boundary_id = 0;
	if ((ret = rrr_instance_config_read_unsigned_integer(&boundary_id, config, "ipclient_boundary_id")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			data->send_boundary_high = 0;
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing ipclient_boundary_id setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	else {
		if (data->no_assured_single_delivery != 0) {
			VL_MSG_ERR("Cannot have ipclient_boundary_id set while assured single delivery is turned off for instance %s\n",
					config->name);
		}
		if (boundary_id > 0xffffffff) {
			VL_MSG_ERR("Setting ipclient_boundary_id was out of range, must be <= 0xffffffff for instance %s\n",
					config->name);
			ret = 1;
			goto out;
		}
		data->send_boundary_high = boundary_id;
	}

	if (data->no_assured_single_delivery == 0 && data->send_boundary_high == 0) {
		data->send_boundary_high = (uint32_t) rand();
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

struct strip_ip_buffer_callback_args {
	struct ipclient_data *data;
	int (*final_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE);
	struct fifo_callback_args *final_poll_data;
};

int ipclient_poll_delete_strip_ip_buffer (FIFO_CALLBACK_ARGS) {
	int ret = 0;

	(void)(size);

	struct strip_ip_buffer_callback_args *callback_data_strip = callback_data->private_data;

	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;
	struct vl_message *message = entry->message;

	ret = callback_data_strip->final_callback(callback_data_strip->final_poll_data, (char*) message, sizeof(*message));
	entry->message = NULL;

	ip_buffer_entry_destroy(entry);

	return ret;
}


int ipclient_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct ipclient_data *ipclient_data = data->private_data;

	struct strip_ip_buffer_callback_args strip_callback_data = {
		ipclient_data,
		callback,
		poll_data
	};

	struct fifo_callback_args fifo_callback_args = {
		ipclient_data->thread_data, &strip_callback_data, 0
	};

	return fifo_read_clear_forward (
			&ipclient_data->local_output_buffer,
			NULL,
			ipclient_poll_delete_strip_ip_buffer,
			&fifo_callback_args,
			wait_milliseconds
	);
}

int ipclient_poll_delete_ip (RRR_MODULE_POLL_SIGNATURE) {
	struct ipclient_data *ipclient_data = data->private_data;

	return fifo_read_clear_forward(&ipclient_data->local_output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

static int poll_callback_final (struct ipclient_data *data, struct ip_buffer_entry *entry) {
	fifo_buffer_write(&data->send_queue_intermediate, (char *) entry, sizeof(*entry));
	return 0;
}

static int poll_callback (struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *private_data = thread_data->private_data;
	struct vl_message *message = (struct vl_message *) data;
	struct ip_buffer_entry *entry = NULL;

	VL_DEBUG_MSG_3 ("ipclient instance %s: Result from buffer: timestamp %" PRIu64 " measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->timestamp_from, message->data_numeric, size);

	if (ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(message), NULL, 0, message) != 0) {
		VL_MSG_ERR("Could not create ip buffer entry in ipclient poll_callback\n");
		free(data);
		return 1;
	}

	return poll_callback_final(private_data, entry);
}

static int poll_callback_ip (struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *private_data = thread_data->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	VL_DEBUG_MSG_3 ("ipclient instance %s: Result from buffer ip: size %lu\n",
			INSTANCE_D_NAME(thread_data), size);

	return poll_callback_final(private_data, entry);
}

void release_queue_cleanup_and_deliver (struct ipclient_data *data) {
	int lost_entries = 0;
	uint16_t prev_ok_stream_id = 0;
	RRR_LL_ITERATE_BEGIN(&data->release_queue, struct ipclient_queue_entry);
		if (node->stream_id == prev_ok_stream_id) {
			RRR_LL_ITERATE_NEXT();
		}
		if (rrr_udpstream_stream_exists(&data->udpstream, node->stream_id)) {
			prev_ok_stream_id = node->stream_id;
			RRR_LL_ITERATE_NEXT();
		}
		RRR_LL_ITERATE_SET_DESTROY();
		lost_entries++;
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->release_queue, __ipclient_queue_entry_destroy(node));

	if (lost_entries > 0) {
		VL_MSG_ERR("ipclient instance %s lost %i messages which was missing release ACK in release queue\n",
			INSTANCE_D_NAME(data->thread_data), lost_entries);
	}
}

int release_queue_send_urges (int *send_count_result, struct ipclient_data *data) {
	int ret = 0;

	*send_count_result = 0;

	// If our release queue is full, spam out A LOT of ACK messages to
	// force remote to generate release ACKs aiding us in reducing the
	// buffer size instead of it sending more data. This also has the effect
	// of reduced window size on the remote.
/*	int dupes = 1;
	if (RRR_LL_COUNT(&data->release_queue) > VL_IPCLIENT_RELEASE_QUEUE_MAX) {
		dupes = 2;
	}*/

	int send_count = 0;

	if (RRR_LL_COUNT(&data->release_queue) > 0) {
		uint64_t time_now = time_get_64();
		RRR_LL_ITERATE_BEGIN(&data->release_queue, struct ipclient_queue_entry);
			int do_send = 0;
			if (node->send_time == 0) {
				do_send = 1;
			}
			else if (time_now - node->send_time > VL_IPCLIENT_RELEASE_QUEUE_URGE_TIMEOUT_MS * 1000) {
				do_send = 1;
			}
			if (do_send != 0) {
				VL_DEBUG_MSG_3("ipclient instance %s: send release ACK urge for boundary %" PRIu64 "\n",
						INSTANCE_D_NAME(data->thread_data), node->boundary_id_combined);

				node->send_time = time_now;
				if (rrr_udpstream_release_ack_urge (
						&data->udpstream,
						node->stream_id,
						node->boundary_id_combined,
						&node->entry->addr,
						node->entry->addr_len,
						-150
				) != 0) {
					VL_MSG_ERR("Could not send release ACK urge in ipclient receive_messages\n");
					ret = 1;
					goto out;
				}
				send_count++;
			}

			if (send_count > 5) {
				RRR_LL_ITERATE_LAST();
			}
		RRR_LL_ITERATE_END(&data->release_queue);
		if (send_count > 0) {
			VL_DEBUG_MSG_2("ipclient instance %s: sent %i release ACK urges\n",
					INSTANCE_D_NAME(data->thread_data), send_count);
		}
	}

	*send_count_result = send_count;

	out:
	return ret;
}

static int connect_with_udpstream (struct ipclient_data *data) {
	int ret = 0;

	if (data->ip_default_remote == NULL) {
		goto out;
	}

	uint64_t time_now = time_get_64();
	int connect_max = 2;
	int active_was_found = 0;

	for (int i = 0; i < VL_IPCLIENT_CONCURRENT_CONNECTIONS; i++) {
		struct connect_handle *connect_handle = &data->connect_handles[i];

		// Check for connect timeout and check if alive
		if (connect_handle->connect_handle != 0) {
			if (data->active_connect_handle == connect_handle->connect_handle) {
				active_was_found = 1;
			}

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

			if (rrr_udpstream_connect (
					&connect_handle->connect_handle,
					data->send_boundary_high,
					&data->udpstream,
					data->ip_default_remote,
					data->ip_default_remote_port
			) != 0) {
				VL_MSG_ERR("UDP-stream could not connect in ipclient instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				ret = 1;
				goto out;
			}
		}

		// Check for setting active connect handle
		if (data->active_connect_handle == 0 && connect_handle->is_established != 0 && connect_handle->connect_handle != 0) {
			data->active_connect_handle = connect_handle->connect_handle;
			active_was_found = 1;
		}
	}

	if (active_was_found == 0) {
		data->active_connect_handle = 0;
	}

	out:
	return ret;
}

static void invalidate_connect_handle (struct ipclient_data *data, uint32_t connect_handle) {
	VL_DEBUG_MSG_2("ipclient instance %s invalidate connect handle %u active is %u\n",
			INSTANCE_D_NAME(data->thread_data), connect_handle, data->active_connect_handle);

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

static int delivery_listener (uint16_t stream_id, uint64_t boundary_id, uint8_t frame_type, void *arg) {
	struct ipclient_data *data = arg;

	(void)(stream_id);

	if (frame_type == RRR_UDPSTREAM_FRAME_TYPE_DELIVERY_ACK) {
		VL_DEBUG_MSG_3("ipclient instance %s DELIVERY ACK for boundary %" PRIu64 "\n",
				INSTANCE_D_NAME(data->thread_data), boundary_id);
		__ipclient_queue_set_entry_no_more_sending(&data->send_queue, boundary_id);
	}
	else if (frame_type == RRR_UDPSTREAM_FRAME_TYPE_RELEASE_ACK) {
		VL_DEBUG_MSG_3("ipclient instance %s received release ACK for boundary %" PRIu64 "\n",
				INSTANCE_D_NAME(data->thread_data), boundary_id);

		struct ip_buffer_entry *entry = __ipclient_queue_remove_entry_and_get_data(&data->release_queue, boundary_id);
		if (entry == NULL) {
			VL_DEBUG_MSG_2("Note: Received RELEASE ACK for unknown boundary %" PRIu64 " in ipclient instance %s\n",
					boundary_id, INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		fifo_buffer_write(&data->local_output_buffer, (char*) entry, sizeof(*entry));
	}
	else if (frame_type == RRR_UDPSTREAM_FRAME_TYPE_COMPLETE_ACK) {
		VL_DEBUG_MSG_3("ipclient instance %s COMPLETE ACK for boundary %" PRIu64 "\n",
				INSTANCE_D_NAME(data->thread_data), boundary_id);
		__ipclient_queue_remove_entry(&data->send_queue, boundary_id);
	}

	out:
	return 0;
}

struct receive_messages_callback_data {
	struct ipclient_data *data;
	int count;
	struct rrr_udpstream_callback_data *receive_data;
};

static int receive_messages_callback_final(struct vl_message *message, void *arg) {
	struct receive_messages_callback_data *callback_data = arg;
	struct ipclient_data *data = callback_data->data;

	int ret = VL_IP_RECEIVE_OK;

	if (callback_data->receive_data->boundary_id != 0) {
		VL_DEBUG_MSG_3 ("ipclient: Write message with timestamp %" PRIu64 " boundary id %" PRIu64 " to release queue\n",
				message->timestamp_from, callback_data->receive_data->boundary_id);

		struct ip_buffer_entry *entry = NULL;
		if (ip_buffer_entry_new (
				&entry,
				MSG_TOTAL_SIZE(message),
				callback_data->receive_data->addr,
				callback_data->receive_data->addr_len,
				message
		) != 0) {
			VL_MSG_ERR("Could not create ip buffer entry in ipclient receive_messages_callback_final\n");
			ret = VL_IP_RECEIVE_ERR;
			goto out;
		}
		message = NULL;

		if (__ipclient_queue_insert_entry_or_destroy (
				&data->release_queue,
				entry,
				callback_data->receive_data->stream_id,
				callback_data->receive_data->boundary_id
		) != 0) {
			VL_MSG_ERR("Could not add ip buffer entry to release queue in receive_messages_callback_final\n");
			ret = VL_IP_RECEIVE_ERR;
			goto out;
		}
	}
	else {
		struct ip_buffer_entry *entry = NULL;

		if (ip_buffer_entry_new_with_empty_message (
				&entry,
				MSG_TOTAL_SIZE(message),
				callback_data->receive_data->addr,
				callback_data->receive_data->addr_len
		) != 0) {
			VL_MSG_ERR("Could not allocate IP buffer entry in ipclient receive_messages_callback_final\n");
			ret = VL_IP_RECEIVE_ERR;
			goto out;
		}

		memcpy(entry->message, message, MSG_TOTAL_SIZE(message));

		VL_DEBUG_MSG_3 ("ipclient: Write message with timestamp %" PRIu64 " to local output buffer\n",
				message->timestamp_from);

		fifo_buffer_write(&data->local_output_buffer, (char*) entry, sizeof(*entry));

		message = NULL;
	}

	callback_data->count++;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

static int receive_messages_callback(struct rrr_udpstream_callback_data *receive_data, void *arg) {
	struct receive_messages_callback_data *callback_data = arg;

	int ret = 0;

	callback_data->receive_data = receive_data;

	struct rrr_socket_common_receive_message_callback_data socket_callback_data = {
			receive_messages_callback_final, callback_data
	};

	// This function will always free the data, also upon errors
	if ((ret = rrr_socket_common_receive_message_raw_callback (
			receive_data->data,
			receive_data->data_size,
			&socket_callback_data
	)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Invalid message received in ipclient instance %s boundary id %" PRIu64 "\n",
					INSTANCE_D_NAME(callback_data->data->thread_data), receive_data->boundary_id);
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while processing message in receive_packets_callback of ipclient instance %s return was %i\n",
					INSTANCE_D_NAME(callback_data->data->thread_data), ret);
			ret = 1;
			goto out;
		}
	}

	out:
	callback_data->receive_data = NULL;
	return ret;
}

static int receive_messages(int *receive_count, struct ipclient_data *data) {
	int ret = 0;

	*receive_count = 0;

	if ((ret = rrr_udpstream_do_read_tasks(&data->udpstream, delivery_listener, data)) != 0) {
		if (ret != RRR_SOCKET_SOFT_ERROR) {
			VL_MSG_ERR("Error from UDP-stream while reading data in receive_packets of ipclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	struct receive_messages_callback_data callback_data = {
			data, 0, NULL
	};

	if (RRR_LL_COUNT(&data->release_queue) < VL_IPCLIENT_RELEASE_QUEUE_MAX) {
		if ((ret = rrr_udpstream_do_process_receive_buffers (
				&data->udpstream,
				rrr_socket_common_get_session_target_length_from_message_and_checksum_raw,
				NULL,
				receive_messages_callback,
				&callback_data
		)) != 0) {
			VL_MSG_ERR("Error from UDP-stream while processing buffers in receive_packets of ipclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
	}
	else {
		VL_MSG_ERR("icplient instance %s release queue is full, possible hang-up with following data loss imminent\n",
				INSTANCE_D_NAME(data->thread_data));
	}

	*receive_count = callback_data.count;

	if (*receive_count > 0) {
		VL_DEBUG_MSG_3("ipclient instance %s: received %i messages\n",
				INSTANCE_D_NAME(data->thread_data), *receive_count);
	}

	out:
	return ret;
}

struct send_packet_callback_data {
	int packet_counter;
};

#define IPCLIENT_QUEUE_RESULT_OK			0
#define IPCLIENT_QUEUE_RESULT_ERR			(1<<0)
#define IPCLIENT_QUEUE_RESULT_DATA_ERR		(1<<1)
#define IPCLIENT_QUEUE_RESULT_STOP			(1<<2)
#define IPCLIENT_QUEUE_RESULT_NOT_QUEUED	(1<<3)

struct queue_message_callback_data {
	struct ipclient_data *data;
	struct ip_buffer_entry *entry;
	uint64_t boundary_id;
	int fifo_action;
};

static int queue_message_callback (const struct rrr_udpstream_send_data *send_data, void *arg) {
	struct queue_message_callback_data *callback_data = arg;

	if (callback_data->entry != send_data->data) {
		VL_BUG("data pointer mismatch in queue_message_callback\n");
	}

	if (send_data->boundary_id != 0) {
		callback_data->fifo_action = FIFO_SEARCH_GIVE;

		if (__ipclient_queue_insert_entry_or_destroy (
				&callback_data->data->send_queue,
				callback_data->entry,
				send_data->stream_id,
				send_data->boundary_id
		) != 0) {
			VL_MSG_ERR("Could not add ip buffer entry to queue in ipclient poll_callback_final\n");
			return 1;
		}
	}

	return 0;
}

static int queue_message (
		int *packet_counter,
		struct queue_message_callback_data *callback_data,
		int no_callback
) {
	struct instance_thread_data *thread_data = callback_data->data->thread_data;
	const struct vl_message *message = callback_data->entry->message;
	const struct ip_buffer_entry *entry = callback_data->entry;
	struct ipclient_data *ipclient_data = callback_data->data;

	struct vl_message *message_network = NULL;

	int ret = 0;

	VL_DEBUG_MSG_3 ("ipclient queing packet for sending timestamp %" PRIu64 " boundary %" PRIu64 "\n",
			message->timestamp_from, callback_data->boundary_id);

	update_watchdog_time(thread_data->thread);

	struct ipclient_destination *destination = NULL;
	uint32_t connect_handle = 0;

	if (entry->addr_len != 0) {
		if (ipclient_data->active_connect_handle != 0 &&
			rrr_udpstream_connection_check_address_equal (
					&ipclient_data->udpstream,
					ipclient_data->active_connect_handle,
					&entry->addr,
					entry->addr_len
			)
		) {
			connect_handle = ipclient_data->active_connect_handle;
		}
		else {
			struct ipclient_destination *destination = __ipclient_destination_find_or_create (
					&ipclient_data->destinations,
					&entry->addr,
					entry->addr_len
			);

			if (destination != NULL) {
				if (destination->connect_handle == 0) {
					if (rrr_udpstream_connect_raw (
							&destination->connect_handle,
							ipclient_data->send_boundary_high,
							&ipclient_data->udpstream,
							destination->addr,
							destination->addrlen
					) != 0) {
						VL_MSG_ERR("Could not send connect packet with address information from message in ipclient instance %s, packet must be dropped\n",
								INSTANCE_D_NAME(thread_data));
						ret = IPCLIENT_QUEUE_RESULT_DATA_ERR;
						goto out;
					}

					// Do housekeeping here (a quiet place) to avoid doing it repeatedly
					clean_destinations(ipclient_data);

					// Don't try to send the message immediately, will most likely block
					ret = IPCLIENT_QUEUE_RESULT_NOT_QUEUED;
					goto out;
				}
				connect_handle = destination->connect_handle;
			}
		}
	}
	else if (ipclient_data->ip_default_remote != NULL) {
		connect_handle = ipclient_data->active_connect_handle;
		if (connect_handle == 0) {
			// Connection not ready
			ret = IPCLIENT_QUEUE_RESULT_NOT_QUEUED;
			goto out;
		}
	}
	else {
		VL_MSG_ERR("ipclient instance %s dropping message from sender without address information\n",
				INSTANCE_D_NAME(thread_data));
		ret = IPCLIENT_QUEUE_RESULT_DATA_ERR;
		goto out;
	};

	message_network = message_duplicate(message);
	ssize_t message_network_size = MSG_TOTAL_SIZE(message_network);

	message_prepare_for_network((struct vl_message *) message_network);
	rrr_socket_msg_checksum_and_to_network_endian ((struct rrr_socket_msg *) message_network);

	if ((ret = rrr_udpstream_queue_outbound_data (
			&ipclient_data->udpstream,
			connect_handle,
			message_network,
			message_network_size,
			callback_data->boundary_id,
			(no_callback ? NULL : queue_message_callback),
			(no_callback ? NULL : callback_data)
	)) != 0) {
		if (ret == RRR_UDPSTREAM_BUFFER_FULL || ret == RRR_UDPSTREAM_NOT_READY) {
			ret = IPCLIENT_QUEUE_RESULT_OK | IPCLIENT_QUEUE_RESULT_STOP | IPCLIENT_QUEUE_RESULT_NOT_QUEUED;
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
			ret = IPCLIENT_QUEUE_RESULT_OK | IPCLIENT_QUEUE_RESULT_STOP | IPCLIENT_QUEUE_RESULT_NOT_QUEUED;
			goto out;
		}
		else {
			VL_MSG_ERR("Error while queuing message for sending in ipclient instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = IPCLIENT_QUEUE_RESULT_OK | IPCLIENT_QUEUE_RESULT_ERR | IPCLIENT_QUEUE_RESULT_NOT_QUEUED;
			goto out;
		}
	}

	ipclient_data->total_queued_count++;

	(*packet_counter)++;

	out:
	RRR_FREE_IF_NOT_NULL(message_network);
	return ret;
}

int queue_messages_callback (struct fifo_callback_args *args, char *data, unsigned long int size) {
	struct ipclient_data *ipclient_data = args->private_data;
	struct ip_buffer_entry *entry = (struct ip_buffer_entry *) data;

	int ret = 0;

	(void)(size);

	VL_DEBUG_MSG_3("Send non-assured delivery message in ipclient instance %s\n",
			INSTANCE_D_NAME(ipclient_data->thread_data));

	int send_count = 0;

	struct queue_message_callback_data callback_data = {
			ipclient_data,
			entry,
			(ipclient_data->no_assured_single_delivery ? 0 : ++(ipclient_data->send_boundary_low_pos)),
			0
	};

	if ((ret = queue_message(&send_count, &callback_data, 0)) != IPCLIENT_QUEUE_RESULT_OK) {
		int final_ret = 0;
		if ((ret & IPCLIENT_QUEUE_RESULT_NOT_QUEUED) != 0) {
			// Don't do anything
		}
		if ((ret & IPCLIENT_QUEUE_RESULT_DATA_ERR) != 0) {
			// Just delete the data
		}
		if ((ret & IPCLIENT_QUEUE_RESULT_STOP) != 0) {
			final_ret |= FIFO_SEARCH_STOP;
		}
		ret &= ~(IPCLIENT_QUEUE_RESULT_DATA_ERR|IPCLIENT_QUEUE_RESULT_STOP|IPCLIENT_QUEUE_RESULT_NOT_QUEUED);
		if (ret != 0) {
			// Upon other errors than data errors, message is not destroyed
			ret = FIFO_GLOBAL_ERR;
			goto out;
		}
		ret = final_ret;
	}

	if (send_count > 0) {
		VL_DEBUG_MSG_3 ("ipclient instance %s udpstream sent %i unasssured packets\n",
				INSTANCE_D_NAME(ipclient_data->thread_data), send_count);
	}

	out:
	if (entry != NULL) {
		ip_buffer_entry_destroy(entry);
	}
	if (callback_data.fifo_action != 0) {
		ret |= callback_data.fifo_action;
	}
	else {
		ret |= FIFO_SEARCH_GIVE | FIFO_SEARCH_FREE;
	}
	return ret;
}

/*
 *
		if (data->no_assured_single_delivery != 0) {
	}
	else {
		data->total_poll_count++;
	}
 *
 */
int queue_messages(int *send_count, struct ipclient_data *data) {
	int ret = 0;

	*send_count = 0;

	struct fifo_callback_args fifo_callback_args = {
		data->thread_data, data, 0
	};

	if (fifo_search(&data->send_queue_intermediate, queue_messages_callback, &fifo_callback_args, 0)) {
		VL_MSG_ERR("Error from buffer in ipclient send_packets\n");
		ret = 1;
		goto out;
	}

	uint64_t time_now = time_get_64();

	int resend_count = 0;

	// Check for timed out messages and send again
	RRR_LL_ITERATE_BEGIN(&data->send_queue, struct ipclient_queue_entry);
		if (node->entry->addr_len == 0 && data->active_connect_handle == 0) {
			// Don't attempt to queue default deliveries, not connected
			RRR_LL_ITERATE_NEXT();
		}

		int do_send = 0;
		if (node->no_more_sending == 0) {
			if (node->send_time == 0) {
				node->send_time = time_now();
			}
			else if (time_now - node->send_time > VL_IPCLIENT_RESEND_INTERVAL_MS * 1000) {
				VL_DEBUG_MSG_3("Timeout for assured delivery message with boundary %" PRIu64 " in ipclient instance %s, re-send\n",
						node->boundary_id_combined, INSTANCE_D_NAME(data->thread_data));
				resend_count++;
				do_send = 1;
			}
		}

		struct queue_message_callback_data callback_data = {
				data,
				node->entry,
				node->boundary_id_combined,
				0
		};

		if (do_send != 0) {
			// The "1" means callback is disabled, if not it will be added to the queue again
			// causing semantic and memory problems
			if ((ret = queue_message(send_count, &callback_data, 1)) != IPCLIENT_QUEUE_RESULT_OK) {
				if ((ret & IPCLIENT_QUEUE_RESULT_NOT_QUEUED) != 0) {
					// Entry was not added, keep it
				}
				if ((ret & IPCLIENT_QUEUE_RESULT_DATA_ERR) != 0) {
					VL_DEBUG_MSG_2("Data error for assured delivery message with boundary %" PRIu64 " when queueing in ipclient instance %s\n",
							node->boundary_id_combined, INSTANCE_D_NAME(data->thread_data));
					RRR_LL_ITERATE_SET_DESTROY();
				}
				if ((ret & IPCLIENT_QUEUE_RESULT_STOP) != 0) {
					RRR_LL_ITERATE_LAST();
				}
				ret &= ~(IPCLIENT_QUEUE_RESULT_DATA_ERR|IPCLIENT_QUEUE_RESULT_STOP|IPCLIENT_QUEUE_RESULT_NOT_QUEUED);
				if (ret != 0) {
					ret = 1;
					goto out;
				}
			}
			else {
				node->send_time = time_now;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->send_queue, __ipclient_queue_entry_destroy(node));

	if ((*send_count) > 0) {
		VL_DEBUG_MSG_3 ("ipclient instance %s queued %i packets for transmission\n",
				INSTANCE_D_NAME(data->thread_data), (*send_count));
	}

	if (resend_count > 0) {
		VL_DEBUG_MSG_3 ("ipclient instance %s re-queued %i packets for transmission\n",
				INSTANCE_D_NAME(data->thread_data), resend_count);
	}

	out:
	return ret;
}



static void *thread_entry_ipclient (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;
	struct poll_collection poll_ip;

	if (data_init(data, thread_data) != 0) {
		VL_MSG_ERR("Could not initialize data in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("ipclient thread data is %p\n", thread_data);

	poll_collection_init(&poll_ip);
	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll_ip);
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

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_NO_SENDERS_OK);
	poll_add_from_thread_senders_ignore_error(&poll_ip, thread_data, RRR_POLL_POLL_DELETE_IP|RRR_POLL_NO_SENDERS_OK);

	poll_remove_senders_also_in(&poll, &poll_ip);

	int no_polling = poll_collection_count(&poll) + poll_collection_count(&poll_ip) > 0 ? 0 : 1;

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

	uint64_t time_now = time_get_64();
	uint64_t prev_stats_time = time_now;
	uint64_t prev_urge_time = time_now;
	int consecutive_zero_recv_and_send = 0;
	int ack_urge_total = 0;
	int receive_total = 0;
	int queued_total = 0;
	int send_total = 0;
	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		time_now = time_get_64();

		if (connect_with_udpstream(data) != 0) {
			usleep (1000000); // 1000 ms
			goto network_restart;
		}

		if (no_polling == 0 &&
				fifo_buffer_get_entry_count(&data->send_queue_unassured) < VL_IPCLIENT_SEND_BUFFER_UNASSURED_MAX &&
				RRR_LL_COUNT(&data->send_queue) < VL_IPCLIENT_SEND_BUFFER_ASSURED_MAX
		) {
			uint64_t poll_timeout = time_now + 100 * 1000; // 100ms
			if (data->send_boundary_low_pos >= RRR_UDPSTREAM_BOUNDARY_POS_LOW_MAX) {
				// Counter must be wrapped, and all outstanding messages must
				// be delivered before we poll for more.
				if (RRR_LL_COUNT(&data->send_queue) == 0) {
					// Reset ID counter when all outstanding messages are assured delivered
					data->send_boundary_low_pos = 0;
				}
			}
			else {
				do {
					if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 25) != 0) {
						break;
					}
					if (poll_do_poll_delete_ip_simple (&poll_ip, thread_data, poll_callback_ip, 25) != 0) {
						break;
					}
				} while (fifo_buffer_get_entry_count(&data->send_queue_unassured) < VL_IPCLIENT_SEND_BUFFER_UNASSURED_MAX &&
						RRR_LL_COUNT(&data->send_queue) < VL_IPCLIENT_SEND_BUFFER_ASSURED_MAX &&
						time_get_64() > poll_timeout
				);
	//			VL_DEBUG_MSG_2("ipclient instance %s receive buffer size %i\n",
	//					INSTANCE_D_NAME(thread_data), send_buffer_size_after);
			}
		}

//		VL_DEBUG_MSG_2("ipclient instance %s receive\n",
//				INSTANCE_D_NAME(thread_data));
		int receive_count = 0;
		if (receive_messages(&receive_count, data) != 0) {
			usleep (10000); // 10 ms
			goto network_restart;
		}
		receive_total += receive_count;

		int queue_count = 0;
		update_watchdog_time(thread_data->thread);
		if (queue_messages(&queue_count, data) != 0) {
			usleep (10000); // 10 ms
			goto network_restart;
		}
		queued_total += queue_count;

		int send_count = 0;
		if (rrr_udpstream_do_send_tasks(&send_count, &data->udpstream) != 0) {
			VL_MSG_ERR("UDP-stream send tasks failed in send_packets of ipclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			usleep (10000); // 10 ms
			goto network_restart;
		}
		send_total += send_count;

		if (receive_count == 0 && send_count == 0) {
			if (consecutive_zero_recv_and_send > 1000) {
				VL_DEBUG_MSG_2("ipclient instance %s long sleep send buffer assured %i unassured %i\n",
						INSTANCE_D_NAME(thread_data), RRR_LL_COUNT(&data->send_queue), fifo_buffer_get_entry_count(&data->send_queue_unassured));
				usleep (100000); // 100 ms
			}
			else {
				sched_yield();
				if (consecutive_zero_recv_and_send++ > 10) {
					usleep(10);
				}
//				printf("ipclient instance %s yield\n", INSTANCE_D_NAME(thread_data));
			}
		}
		else {
			consecutive_zero_recv_and_send = 0;
			VL_DEBUG_MSG_3("ipclient instance %s receive count %i send count %i queued count %i\n",
					INSTANCE_D_NAME(thread_data), receive_count, send_count, queue_count);
		}

		if (time_now - prev_stats_time > 1000000) {
			int output_buffer_count = fifo_buffer_get_entry_count(&data->local_output_buffer);
			if (VL_DEBUGLEVEL_1) {
				VL_DEBUG_MSG("-- ipclient instance %s OB %i RQ %i AQ %i UQ %i TP %" PRIu64 " TQ %" PRIu64 " r/s %i q/s %i s/s %i u/s %i\n",
						INSTANCE_D_NAME(thread_data),
						output_buffer_count,
						RRR_LL_COUNT(&data->release_queue),
						RRR_LL_COUNT(&data->send_queue),
						fifo_buffer_get_entry_count(&data->send_queue_unassured),
						data->total_poll_count,
						data->total_queued_count,
						receive_total,
						queued_total,
						send_total,
						ack_urge_total
				);
				rrr_udpstream_dump_stats(&data->udpstream);
				VL_DEBUG_MSG("--------------\n");
			}
			prev_stats_time = time_now;
			ack_urge_total = 0;
			receive_total = 0;
			queued_total = 0;
			send_total = 0;

			if (data->local_output_buffer.buffer_do_ratelimit != 1 && output_buffer_count > 250000) {
				VL_DEBUG_MSG_1("ipclient instance %s enabling rate limit on output buffer\n",
						INSTANCE_D_NAME(thread_data));
				data->local_output_buffer.buffer_do_ratelimit = 1;
			}
			else if (data->local_output_buffer.buffer_do_ratelimit != 0 && output_buffer_count == 0) {
				VL_DEBUG_MSG_1("ipclient instance %s disabling rate limit on output buffer\n",
						INSTANCE_D_NAME(thread_data));
				data->local_output_buffer.buffer_do_ratelimit = 0;
			}
		}

		release_queue_cleanup_and_deliver(data);

		if (time_now - prev_urge_time > (VL_IPCLIENT_RELEASE_QUEUE_URGE_TIMEOUT_MS * 1000) / 2) {
			int send_count = 0;
			if (release_queue_send_urges(&send_count, data) != 0) {
				break;
			}
			ack_urge_total += send_count;
			prev_urge_time = time_now;
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
		ipclient_poll_delete_ip,
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

