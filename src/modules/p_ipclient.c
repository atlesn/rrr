/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "../lib/log.h"

#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/threads.h"
#include "../lib/poll_helper.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/udpstream/udpstream_asd.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/message_broker.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/util/macro_utils.h"
#include "../lib/util/gnu.h"
#include "../lib/util/linked_list.h"
#include "../lib/util/rrr_time.h"

// Should not be smaller than module max
#define RRR_IPCLIENT_MAX_SENDERS RRR_MODULE_MAX_SENDERS
#define RRR_IPCLIENT_DEFAULT_PORT 5555

// Max unsent messages to store from other modules
#define RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX 500

#define RRR_IPCLIENT_CONNECT_TIMEOUT_MS 5000
#define RRR_IPCLIENT_CONCURRENT_CONNECTIONS 3

struct ipclient_data {
	struct rrr_msg_holder_collection send_queue_intermediate;

	struct rrr_instance_runtime_data *thread_data;

	uint32_t client_number;

	int do_disallow_remote_ip_swap;
	int do_ipv4_only;
	int do_listen;

	uint64_t total_poll_count;
	uint64_t total_queued_count;

	char *ip_default_remote;
	char *ip_default_remote_port;

	int (*queue_method)(struct rrr_msg_holder *entry, struct ipclient_data *data);

	rrr_setting_uint src_port;
	struct rrr_udpstream_asd *udpstream_asd;
};

void data_cleanup(void *arg) {
	struct ipclient_data *data = arg;

	if (data->udpstream_asd != NULL) {
		rrr_udpstream_asd_destroy(data->udpstream_asd);
		data->udpstream_asd = NULL;
	}

	RRR_FREE_IF_NOT_NULL(data->ip_default_remote_port);
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote);
	rrr_msg_holder_collection_clear(&data->send_queue_intermediate);
}

int data_init(struct ipclient_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

int delete_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data);
int queue_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data);

int parse_config (struct ipclient_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ipclient_client_number", client_number, 0);

	if (data->client_number == 0 || data->client_number > 0xffffffff) {
		RRR_MSG_0("Error while parsing setting ipclient_client_number of instance %s, must be in the range 1-4294967295 and unique for this client\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ipclient_default_remote", ip_default_remote);

	if (data->ip_default_remote == NULL || *(data->ip_default_remote) == '\0') {
		data->queue_method = delete_message_callback;
	}
	else {
		data->queue_method = queue_message_callback;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_default_remote_port, config, "ipclient_default_remote_port")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing ipclient_default_remote_port settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_asprintf(&data->ip_default_remote_port, "%i", RRR_IPCLIENT_DEFAULT_PORT) <= 0) {
			RRR_MSG_0("Could not allocate string for port number in ipclient instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	rrr_setting_uint src_port;
	if ((ret = rrr_instance_config_read_port_number(&src_port, config, "ipclient_src_port")) == 0) {
		data->src_port = src_port;
	}
	else if (ret == RRR_SETTING_NOT_FOUND) {
		data->src_port = RRR_IPCLIENT_DEFAULT_PORT;
		// OK
	}
	else {
		RRR_MSG_0("ipclient: Could not understand ipclient_src_port argument, must be numeric\n");
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ipclient_disallow_remote_ip_swap", do_disallow_remote_ip_swap, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ipclient_listen", do_listen, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ipclient_ipv4_only", do_ipv4_only, 0);

	// Reset any NOT_FOUND
	ret = 0;

	out:
	return ret;
}

static int poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct ipclient_data *private_data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_2 ("ipclient instance %s: Result from buffer timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&private_data->send_queue_intermediate, entry);

	rrr_msg_holder_unlock(entry);
	return 0;
}

struct receive_messages_callback_data {
	struct ipclient_data *data;
	int count;
};

static int receive_messages_callback_final(struct rrr_msg_holder *entry, void *arg) {
	struct receive_messages_callback_data *callback_data = arg;
	struct ipclient_data *data = callback_data->data;

	int ret = 0;

	rrr_thread_watchdog_time_update(INSTANCE_D_THREAD(data->thread_data));

	// The allocator function below ensures that the entries we receive here are not dirty,
	// all writing to it was performed while the locks were held
	if ((ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			entry,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Error while writing to output buffer in ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	callback_data->count++;

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int receive_messages (int *receive_count, struct ipclient_data *data) {
	int ret = 0;

	struct receive_messages_callback_data callback_data = { data, 0 };

	if ((ret = rrr_udpstream_asd_deliver_and_maintain_queues (
			data->udpstream_asd,
			receive_messages_callback_final,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error while receiving messages from ASD in receive_messages of ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	*receive_count = callback_data.count;
	return ret;
}

struct send_packet_callback_data {
	int packet_counter;
};

/*
#define IPCLIENT_QUEUE_RESULT_OK			0
#define IPCLIENT_QUEUE_RESULT_ERR			(1<<0)
#define IPCLIENT_QUEUE_RESULT_DATA_ERR		(1<<1)
#define IPCLIENT_QUEUE_RESULT_STOP			(1<<2)
#define IPCLIENT_QUEUE_RESULT_NOT_QUEUED	(1<<3)
*/

int delete_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data) {
	RRR_MSG_0("Warning: Received a message from sender in ipclient instance %s, but remote host is not set. Dropping message.\n",
			INSTANCE_D_NAME(ipclient_data->thread_data));

	(void)(entry);
	return 0;
}

int queue_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data) {
	int ret = 0;

	if ((ret = rrr_udpstream_asd_queue_and_incref_message(ipclient_data->udpstream_asd, entry)) != 0) {
		if (ret == RRR_UDPSTREAM_ASD_NOT_READY) {
			goto out;
		}
		else {
			RRR_MSG_0("Could not queue message in queue_message_callback of ipclient instance %s\n",
					INSTANCE_D_NAME(ipclient_data->thread_data));
			ret = 1;
		}
		goto out;
	}

	out:
	return ret;
}

int queue_or_delete_messages(int *send_count, struct ipclient_data *data) {
	int ret = 0;

	*send_count = 0;

	RRR_LL_ITERATE_BEGIN(&data->send_queue_intermediate, struct rrr_msg_holder);
		RRR_LL_VERIFY_HEAD(&data->send_queue_intermediate);
		RRR_LL_VERIFY_NODE(&data->send_queue_intermediate);

		rrr_msg_holder_lock(node);

		if ((ret = data->queue_method(node, data)) != 0) {
			rrr_msg_holder_unlock(node);
			ret &= ~(RRR_UDPSTREAM_ASD_NOT_READY);
			RRR_LL_ITERATE_BREAK();
		}

		(*send_count)++;

		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->send_queue_intermediate, 0; rrr_msg_holder_decref_while_locked_and_unlock(node));

	if ((*send_count) > 0) {
		RRR_DBG_2 ("ipclient instance %s queued %i packets for transmission\n",
				INSTANCE_D_NAME(data->thread_data), (*send_count));
	}

	return ret;
}

static int __ipclient_asd_reconnect (struct ipclient_data *data) {
	int ret = 0;

	if (data->udpstream_asd != NULL) {
		rrr_udpstream_asd_destroy(data->udpstream_asd);
		data->udpstream_asd = NULL;
	}

	if ((ret = rrr_udpstream_asd_new (
			&data->udpstream_asd,
			data->src_port,
			data->ip_default_remote,
			data->ip_default_remote_port,
			data->client_number,
			data->do_listen,
			data->do_disallow_remote_ip_swap,
			data->do_ipv4_only
	)) != 0) {
		RRR_MSG_0("Could not initialize ASD in ipclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct ipclient_udpstream_allocator_callback_data {
	struct ipclient_data *data;
	uint32_t size;
	const struct sockaddr *remote_addr;
	socklen_t remote_addr_len;
	int (*callback)(RRR_UDPSTREAM_RECEIVE_CALLBACK_ARGS);
	void *udpstream_callback_data;
};

static int ipclient_udpstream_allocator_intermediate (void *arg1, void *arg2) {
	struct ipclient_udpstream_allocator_callback_data *callback_data = arg1;

	(void)(arg2);

	int ret = RRR_FIFO_OK;

	struct rrr_msg_holder *entry = NULL;

	// Points to data inside entry, not to be freed except from when entry is destroyed
	void *joined_data = NULL;

	if (rrr_msg_holder_util_new_with_empty_message (
			&entry,
			callback_data->size,
			callback_data->remote_addr,
			callback_data->remote_addr_len,
			RRR_IP_UDP
	) != 0) {
		RRR_MSG_0("Could not allocate entry in ipclient_udpstream_allocator_intermediate\n");
		ret = 1;
		goto out_no_unlock;
	}

	rrr_msg_holder_lock(entry);

	pthread_cleanup_push(rrr_msg_holder_decref_while_locked_and_unlock_void, entry);

	// The innermost callback will set joined_data when it has successfully
	// filled a message into the entry, we use this for bugchecking
	joined_data = entry->message;

	if ((ret = callback_data->callback(&joined_data, entry, callback_data->udpstream_callback_data)) != 0) {
		goto out_err;
	}

	if (joined_data != NULL) {
		RRR_BUG("Callback returned non-error but still did not set joined_data to NULL in ipclient_udpstream_allocator_intermediate\n");
	}

	goto out;
	out_err:
		if (joined_data == NULL && ret != 0) {
			RRR_BUG("Callback returned error but still set joined_data to NULL in ipclient_udpstream_allocator_intermediate\n");
		}
		ret = RRR_FIFO_GLOBAL_ERR;
	out:
		pthread_cleanup_pop(1);
		if (joined_data != NULL && ret == 0) {
			RRR_BUG("Callback returned non-error but still did not set joined_data to NULL in ipclient_udpstream_allocator_intermediate\n");
		}
	out_no_unlock:
		return ret;
}

static int ipclient_udpstream_allocator (
		RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS
) {
	struct ipclient_data *data = arg;

	int ret = 0;

	struct ipclient_udpstream_allocator_callback_data callback_data = {
			data,
			size,
			remote_addr,
			remote_addr_len,
			receive_callback,
			udpstream_callback_arg
	};

	if ((ret = rrr_message_broker_with_ctx_and_buffer_lock_do (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			ipclient_udpstream_allocator_intermediate,
			&callback_data,
			NULL
	)) != 0) {
		RRR_MSG_0("Error from message broker writer in ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_ipclient (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("ipclient thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for ipclient instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	int no_polling = rrr_poll_collection_count(&thread_data->poll) > 0 ? 0 : 1;

	RRR_DBG_1 ("ipclient instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	network_restart:
	RRR_DBG_1 ("ipclient instance %s restarting network\n", INSTANCE_D_NAME(thread_data));

	// TODO : Does the following comment still apply?
	//     Only close here and not when shutting down the thread (might cause
	//     deadlock in rrr_socket). rrr_socket cleanup will close the socket if we exit.
	if (__ipclient_asd_reconnect(data) != 0) {
		RRR_MSG_0("Could not reconnect in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	uint64_t time_now = rrr_time_get_64();
	uint64_t prev_stats_time = time_now;
	int consecutive_zero_recv_and_send = 0;
	int receive_total = 0;
	int queued_total = 0;
	int send_total = 0;
	int delivered_total = 0;
	while (rrr_thread_signal_encourage_stop_check(thread) != 1) {
		rrr_thread_watchdog_time_update(thread);

		time_now = rrr_time_get_64();

		uint64_t poll_timeout = time_now + 100 * 1000; // 100ms
		while ( RRR_LL_COUNT(&data->send_queue_intermediate) < RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX &&
		        rrr_time_get_64() < poll_timeout &&
		        no_polling == 0
		) {
			if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, poll_callback, 25) != 0) {
				RRR_MSG_0("Error while polling in ipclient instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		int queue_count = 0;
		rrr_thread_watchdog_time_update(thread);
		if (queue_or_delete_messages(&queue_count, data) != 0) {
			rrr_posix_usleep (10000); // 10 ms
			goto network_restart;
		}
		queued_total += queue_count;

		int receive_count = 0;
		int send_count = 0;
		if (rrr_udpstream_asd_buffer_tick (
				&receive_count,
				&send_count,
				ipclient_udpstream_allocator,
				data,
				data->udpstream_asd
		) != 0) {
			RRR_MSG_0("UDP-stream regular tasks failed in send_packets of ipclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			rrr_posix_usleep (10000); // 10 ms
			goto network_restart;
		}
		send_total += send_count;
		receive_total += receive_count;

		if (receive_count == 0 && send_count == 0) {
			if (consecutive_zero_recv_and_send > 1000 && RRR_LL_COUNT(&data->send_queue_intermediate) < RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX) {
/*				RRR_DEBUG_MSG_2("ipclient instance %s long sleep send buffer %i\n",
						INSTANCE_D_NAME(thread_data), fifo_buffer_get_entry_count(&data->send_queue_intermediate));*/
				rrr_posix_usleep (100000); // 100 ms
			}
			else {
				if (consecutive_zero_recv_and_send++ > 10) {
					rrr_posix_usleep(10);
				}
//				printf("ipclient instance %s yield\n", INSTANCE_D_NAME(thread_data));
			}
		}
		else {
			consecutive_zero_recv_and_send = 0;
			RRR_DBG_3("ipclient instance %s receive count %i send count %i queued count %i\n",
					INSTANCE_D_NAME(thread_data), receive_count, send_count, queue_count);
		}

		int delivered_count = 0;
		if (receive_messages(&delivered_count, data) != 0) {
			RRR_MSG_0("Error while receiving messages in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		delivered_total += delivered_count;

		if (time_now - prev_stats_time > 1000000) {
			int output_buffer_count = 0;
			int ratelimit_active = 0;
			unsigned int send_queue_count = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&output_buffer_count,
					&ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_0("Error while setting ratelimit in ipclient instance %s\n",
					INSTANCE_D_NAME(thread_data));
				break;
			}

			send_queue_count = RRR_LL_COUNT(&data->send_queue_intermediate);

			if (RRR_DEBUGLEVEL_1) {
				RRR_MSG_1("-- ipclient instance %s OB %i SQ %i TP %" PRIu64 " TQ %" PRIu64 " r/s %i q/s %i s/s %i d/s %i\n",
						INSTANCE_D_NAME(thread_data),
						output_buffer_count,
						send_queue_count,
						data->total_poll_count,
						data->total_queued_count,
						receive_total,
						queued_total,
						send_total,
						delivered_total
				);
				RRR_MSG_1("--------------\n");
			}

			prev_stats_time = time_now;
			receive_total = 0;
			queued_total = 0;
			send_total = 0;
			delivered_total = 0;
		}
	}

	out_message:
	RRR_DBG_1 ("Thread ipclient %p exiting\n", thread);

//	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	pthread_exit(0);

}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_ipclient,
		NULL,
		NULL,
		NULL
};

static const char *module_name = "ipclient";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
}

void unload(void) {
	RRR_DBG_1 ("Destroy ipclient module\n");
}

