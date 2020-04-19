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
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/vl_time.h"
#include "../lib/poll_helper.h"
#include "../lib/udpstream_asd.h"
#include "../lib/rrr_socket.h"
#include "../lib/gnu.h"
#include "../lib/linked_list.h"
#include "../global.h"

// Should not be smaller than module max
#define RRR_IPCLIENT_MAX_SENDERS RRR_MODULE_MAX_SENDERS
#define RRR_IPCLIENT_DEFAULT_PORT 5555

// Max unsent messages to store from other modules
#define RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX 500

#define RRR_IPCLIENT_CONNECT_TIMEOUT_MS 5000
#define RRR_IPCLIENT_CONCURRENT_CONNECTIONS 3

struct ipclient_data {
	struct rrr_fifo_buffer local_output_buffer;
	struct rrr_fifo_buffer send_queue_intermediate;

	struct rrr_instance_thread_data *thread_data;

	uint32_t client_number;
	int disallow_remote_ip_swap;
	int listen;

	uint64_t total_poll_count;
	uint64_t total_queued_count;

	char *ip_default_remote;
	char *ip_default_remote_port;

	int (*queue_method)(struct rrr_fifo_callback_args *args, char *data, unsigned long int size);

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
	rrr_fifo_buffer_invalidate(&data->local_output_buffer);
	rrr_fifo_buffer_invalidate(&data->send_queue_intermediate);

}

int data_init(struct ipclient_data *data, struct rrr_instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	int ret = 0;
	ret |= rrr_fifo_buffer_init_custom_free(&data->local_output_buffer, rrr_ip_buffer_entry_destroy_void);
	ret |= rrr_fifo_buffer_init_custom_free(&data->send_queue_intermediate, rrr_ip_buffer_entry_destroy_void);
	if (ret != 0) {
		RRR_MSG_ERR("Could not initialize FIFO buffers in ipclient\n");
		data_cleanup(data);
		goto err;
	}

	data->thread_data = thread_data;

	err:
	return (ret != 0);
}

int delete_message_callback (struct rrr_fifo_callback_args *args, char *data, unsigned long int size);
int queue_message_callback (struct rrr_fifo_callback_args *args, char *data, unsigned long int size);

int parse_config (struct ipclient_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint client_id = 0;

	if ((ret = rrr_instance_config_read_unsigned_integer(&client_id, config, "ipclient_client_number")) != 0) {
		RRR_MSG_ERR("Error while parsing setting ipclient_client_number of instance %s, must be set to a unique number for this client\n", config->name);
		ret = 1;
		goto out;
	}

	if (client_id == 0 || client_id > 0xffffffff) {
		RRR_MSG_ERR("Error while parsing setting ipclient_client_number of instance %s, must be in the range 1-4294967295 and unique for this client\n", config->name);
		ret = 1;
		goto out;
	}

	data->client_number = client_id;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_default_remote, config, "ipclient_default_remote")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing setting ipclient_default_remote of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->ip_default_remote = NULL;
		ret = 0;
	}

	if (data->ip_default_remote == NULL || *(data->ip_default_remote) == '\0') {
		data->queue_method = delete_message_callback;
	}
	else {
		data->queue_method = queue_message_callback;
	}

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->ip_default_remote_port, config, "ipclient_default_remote_port")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing ipclient_default_remote_port settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		if (rrr_asprintf(&data->ip_default_remote_port, "%i", RRR_IPCLIENT_DEFAULT_PORT) <= 0) {
			RRR_MSG_ERR("Could not allocate string for port number in ipclient instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	rrr_setting_uint src_port;
	if ((ret = rrr_instance_config_read_port_number(&src_port, config, "ipclient_src_port")) == 0) {
		data->src_port = src_port;
	}
	else if (ret == RRR_SETTING_NOT_FOUND) {
		data->src_port = RRR_IPCLIENT_DEFAULT_PORT;
		ret = 0;
	}
	else {
		RRR_MSG_ERR("ipclient: Could not understand ipclient_src_port argument, must be numeric\n");
		ret = 1;
		goto out;
	}

	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "ipclient_disallow_remote_ip_swap"))) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Invalid value for setting ipclient_disallow_remote_ip_swap of instance %s, please specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->disallow_remote_ip_swap = yesno;

	yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "ipclient_listen"))) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Invalid value for setting ipclient_listen of instance %s, please specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->listen = yesno;

	out:
	return ret;
}

struct strip_ip_buffer_callback_args {
	struct ipclient_data *data;
	int (*final_callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE);
	struct rrr_fifo_callback_args *final_poll_data;
};

int ipclient_poll_delete_strip_ip_buffer (RRR_FIFO_CALLBACK_ARGS) {
	int ret = 0;

	(void)(size);

	struct strip_ip_buffer_callback_args *callback_data_strip = callback_data->private_data;

	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;
	struct rrr_message *message = entry->message;

	ret = callback_data_strip->final_callback(callback_data_strip->final_poll_data, (char*) message, sizeof(*message));
	entry->message = NULL;

	rrr_ip_buffer_entry_destroy(entry);

	return ret;
}

int ipclient_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct ipclient_data *ipclient_data = data->private_data;

	struct strip_ip_buffer_callback_args strip_callback_data = {
		ipclient_data,
		callback,
		poll_data
	};

	struct rrr_fifo_callback_args fifo_callback_args = {
		ipclient_data->thread_data, &strip_callback_data, 0
	};

	return rrr_fifo_read_clear_forward (
			&ipclient_data->local_output_buffer,
			NULL,
			ipclient_poll_delete_strip_ip_buffer,
			&fifo_callback_args,
			wait_milliseconds
	);
}

int ipclient_poll_delete_ip (RRR_MODULE_POLL_SIGNATURE) {
	struct ipclient_data *ipclient_data = data->private_data;

	return rrr_fifo_read_clear_forward(&ipclient_data->local_output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

static int poll_callback_final (struct ipclient_data *data, struct rrr_ip_buffer_entry *entry) {
	rrr_fifo_buffer_write(&data->send_queue_intermediate, (char *) entry, sizeof(*entry));
	return 0;
}

static int poll_callback (struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *private_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;
	struct rrr_ip_buffer_entry *entry = NULL;

	RRR_DBG_3 ("ipclient instance %s: Result from buffer: timestamp %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->timestamp, size);

	if (rrr_ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(message), NULL, 0, message) != 0) {
		RRR_MSG_ERR("Could not create ip buffer entry in ipclient poll_callback\n");
		free(data);
		return 1;
	}

	return poll_callback_final(private_data, entry);
}

static int poll_callback_ip (struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct ipclient_data *private_data = thread_data->private_data;
	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	RRR_DBG_3 ("ipclient instance %s: Result from buffer ip: size %lu\n",
			INSTANCE_D_NAME(thread_data), size);

	return poll_callback_final(private_data, entry);
}

struct receive_messages_callback_data {
	struct ipclient_data *data;
	int count;
};

static int receive_messages_callback_final(struct rrr_ip_buffer_entry *entry, void *arg) {
	struct receive_messages_callback_data *callback_data = arg;
	struct ipclient_data *data = callback_data->data;

	int ret = 0;

	struct rrr_message *message = entry->message;

//	printf ("type and class: %u\n", message->type_and_class);

	rrr_fifo_buffer_write(&data->local_output_buffer, (char*) entry, sizeof(*entry));
	callback_data->count++;

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
		RRR_MSG_ERR("Error while receiving messages from ASD in receive_messages of ipclient instance %s\n",
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

#define IPCLIENT_QUEUE_RESULT_OK			0
#define IPCLIENT_QUEUE_RESULT_ERR			(1<<0)
#define IPCLIENT_QUEUE_RESULT_DATA_ERR		(1<<1)
#define IPCLIENT_QUEUE_RESULT_STOP			(1<<2)
#define IPCLIENT_QUEUE_RESULT_NOT_QUEUED	(1<<3)

struct queue_message_callback_data {
	struct ipclient_data *data;
	struct rrr_ip_buffer_entry *entry;
	uint64_t boundary_id;
	int fifo_action;
};

struct ipclient_queue_messages_data {
	struct ipclient_data *ipclient_data;
	int count;
};


int delete_message_callback (struct rrr_fifo_callback_args *args, char *data, unsigned long int size) {
	struct ipclient_queue_messages_data *callback_data = args->private_data;
	struct ipclient_data *ipclient_data = callback_data->ipclient_data;
	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	(void)(size);

	RRR_MSG_ERR("Warning: Received a message from sender in ipclient instance %s, but remote host is not set. Dropping message.\n",
			INSTANCE_D_NAME(ipclient_data->thread_data));

	rrr_ip_buffer_entry_destroy(entry);

	return RRR_FIFO_OK|RRR_FIFO_SEARCH_GIVE;
}

int queue_message_callback (struct rrr_fifo_callback_args *args, char *data, unsigned long int size) {
	struct ipclient_queue_messages_data *callback_data = args->private_data;
	struct ipclient_data *ipclient_data = callback_data->ipclient_data;
	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	int ret = RRR_FIFO_OK;

	(void)(size);

	struct rrr_message *message = entry->message;

//	printf ("Message type and class: %u\n", message->type_and_class);

	// ASD sets entry pointer to NULL if it takes over memory
	if ((ret = rrr_udpstream_asd_queue_message(ipclient_data->udpstream_asd, &entry)) != 0) {
		if (ret == RRR_UDPSTREAM_ASD_BUFFER_FULL) {
/*			RRR_DEBUG_MSG_2("ASD-buffer full for ipclient instance %s\n",
					INSTANCE_D_NAME(ipclient_data->thread_data));*/
			ret = 0;
			goto out;
		}
		else {
			RRR_MSG_ERR("Could not queue message in queue_message_callback of ipclient instance %s\n",
					INSTANCE_D_NAME(ipclient_data->thread_data));
			ret = 1;
		}
		goto out;
	}

	(callback_data->count)++;

	out:
	return ret | (entry == NULL ? RRR_FIFO_SEARCH_GIVE : RRR_FIFO_SEARCH_KEEP|RRR_FIFO_SEARCH_STOP);
}

int queue_or_delete_messages(int *send_count, struct ipclient_data *data) {
	int ret = 0;

	*send_count = 0;

	struct ipclient_queue_messages_data callback_data = { data, 0 };

	struct rrr_fifo_callback_args fifo_callback_args = {
		data->thread_data, &callback_data, 0
	};

	if ((ret = rrr_fifo_search(&data->send_queue_intermediate, data->queue_method, &fifo_callback_args, 0)) != 0) {
		RRR_MSG_ERR("Error from buffer in ipclient send_packets\n");
		ret = 1;
		goto out;
	}

	*send_count = callback_data.count;

	if ((*send_count) > 0) {
		RRR_DBG_3 ("ipclient instance %s queued %i packets for transmission\n",
				INSTANCE_D_NAME(data->thread_data), (*send_count));
	}

	out:
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
			data->listen,
			data->disallow_remote_ip_swap
	)) != 0) {
		RRR_MSG_ERR("Could not initialize ASD in ipclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void *thread_entry_ipclient (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;
	struct poll_collection poll_ip;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initialize data in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("ipclient thread data is %p\n", thread_data);

	poll_collection_init(&poll_ip);
	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Configuration parse failed for ipclient instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_NO_SENDERS_OK);
	poll_add_from_thread_senders_ignore_error(&poll_ip, thread_data, RRR_POLL_POLL_DELETE_IP|RRR_POLL_NO_SENDERS_OK);

	poll_remove_senders_also_in(&poll, &poll_ip);

	int no_polling = poll_collection_count(&poll) + poll_collection_count(&poll_ip) > 0 ? 0 : 1;

	RRR_DBG_1 ("ipclient instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	network_restart:
	RRR_DBG_2 ("ipclient instance %s restarting network\n", INSTANCE_D_NAME(thread_data));

	// TODO : Does the following comment still apply?
	//     Only close here and not when shutting down the thread (might cause
	//     deadlock in rrr_socket). rrr_socket cleanup will close the socket if we exit.
	if (__ipclient_asd_reconnect(data) != 0) {
		RRR_MSG_ERR("Could not reconnect in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	uint64_t time_now = rrr_time_get_64();
	uint64_t prev_stats_time = time_now;
	int consecutive_zero_recv_and_send = 0;
	int receive_total = 0;
	int queued_total = 0;
	int send_total = 0;
	int delivered_total = 0;
	while (rrr_thread_check_encourage_stop(thread_data->thread) != 1) {
		rrr_update_watchdog_time(thread_data->thread);

		int err = 0;

		time_now = rrr_time_get_64();

		uint64_t poll_timeout = time_now + 100 * 1000; // 100ms
		do {
			if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 25) != 0) {
				break;
			}
			if (poll_do_poll_delete_ip_simple (&poll_ip, thread_data, poll_callback_ip, 25) != 0) {
				break;
			}
		} while (rrr_fifo_buffer_get_entry_count(&data->send_queue_intermediate) < RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX &&
				rrr_time_get_64() < poll_timeout &&
				no_polling == 0
		);
	//			RRR_DEBUG_MSG_2("ipclient instance %s receive buffer size %i\n",
	//					INSTANCE_D_NAME(thread_data), send_buffer_size_after);

//		RRR_DEBUG_MSG_2("ipclient instance %s receive\n",
//				INSTANCE_D_NAME(thread_data));

		int queue_count = 0;
		rrr_update_watchdog_time(thread_data->thread);
		if (queue_or_delete_messages(&queue_count, data) != 0) {
			usleep (10000); // 10 ms
			goto network_restart;
		}
		queued_total += queue_count;

		int receive_count = 0;
		int send_count = 0;
		if (rrr_udpstream_asd_buffer_tick(&receive_count, &send_count, data->udpstream_asd) != 0) {
			RRR_MSG_ERR("UDP-stream regular tasks failed in send_packets of ipclient instance %s\n",
					INSTANCE_D_NAME(data->thread_data));
			usleep (10000); // 10 ms
			goto network_restart;
		}
		send_total += send_count;
		receive_total += receive_count;

		if (receive_count == 0 && send_count == 0) {
			if (consecutive_zero_recv_and_send > 1000) {
/*				RRR_DEBUG_MSG_2("ipclient instance %s long sleep send buffer %i\n",
						INSTANCE_D_NAME(thread_data), fifo_buffer_get_entry_count(&data->send_queue_intermediate));*/
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
			RRR_DBG_3("ipclient instance %s receive count %i send count %i queued count %i\n",
					INSTANCE_D_NAME(thread_data), receive_count, send_count, queue_count);
		}

		int delivered_count = 0;
		if (receive_messages(&delivered_count, data) != 0) {
			RRR_MSG_ERR("Error while receiving messages in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		delivered_total += delivered_count;

		if (time_now - prev_stats_time > 1000000) {
			int output_buffer_count = rrr_fifo_buffer_get_entry_count(&data->local_output_buffer);
			if (RRR_DEBUGLEVEL_1) {
				RRR_DBG("-- ipclient instance %s OB %i SQ %i TP %" PRIu64 " TQ %" PRIu64 " r/s %i q/s %i s/s %i d/s %i\n",
						INSTANCE_D_NAME(thread_data),
						output_buffer_count,
						rrr_fifo_buffer_get_entry_count(&data->send_queue_intermediate),
						data->total_poll_count,
						data->total_queued_count,
						receive_total,
						queued_total,
						send_total,
						delivered_total
				);
				RRR_DBG("--------------\n");
			}
			prev_stats_time = time_now;
			receive_total = 0;
			queued_total = 0;
			send_total = 0;
			delivered_total = 0;

			if (data->local_output_buffer.buffer_do_ratelimit != 1 && output_buffer_count > 250000) {
				RRR_DBG_1("ipclient instance %s enabling rate limit on output buffer\n",
						INSTANCE_D_NAME(thread_data));
				data->local_output_buffer.buffer_do_ratelimit = 1;
			}
			else if (data->local_output_buffer.buffer_do_ratelimit != 0 && output_buffer_count == 0) {
				RRR_DBG_1("ipclient instance %s disabling rate limit on output buffer\n",
						INSTANCE_D_NAME(thread_data));
				data->local_output_buffer.buffer_do_ratelimit = 0;
			}
		}

		if (err != 0) {
			break;
		}
	}

	out_message:
	RRR_DBG_1 ("Thread ipclient %p exiting\n", thread_data->thread);

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

static struct rrr_module_operations module_operations = {
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

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->dl_ptr = NULL;
	data->start_priority = RRR_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
	RRR_DBG_1 ("Destroy ipclient module\n");
}

