/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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
#include "../lib/allocator.h"

#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/event/event.h"
#include "../lib/event/event_functions.h"
#include "../lib/event/event_collection.h"
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

#define RRR_IPCLIENT_DEFAULT_PORT 5555

// Max unsent messages to store from other modules
#define RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX 10000

struct ipclient_data {
	struct rrr_msg_holder_collection send_queue_intermediate;

	struct rrr_event_collection events;
	rrr_event_handle event_send_queue;

	struct rrr_instance_runtime_data *thread_data;

	uint32_t client_number;

	int do_disallow_remote_ip_swap;
	int do_ipv4_only;
	int do_listen;

	uint64_t total_poll_count;
	uint64_t total_queued_count;

	unsigned int received_per_second;
	unsigned int queued_per_second;

	char *ip_default_remote;
	char *ip_default_remote_port;

	int (*queue_method)(struct rrr_msg_holder *entry, struct ipclient_data *data);

	uint16_t src_port;
	struct rrr_udpstream_asd *udpstream_asd;

	int need_network_restart;
};

static void ipclient_data_cleanup(void *arg) {
	struct ipclient_data *data = arg;

	if (data->udpstream_asd != NULL) {
		rrr_udpstream_asd_destroy(data->udpstream_asd);
		data->udpstream_asd = NULL;
	}

	rrr_event_collection_clear(&data->events);
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote_port);
	RRR_FREE_IF_NOT_NULL(data->ip_default_remote);
	rrr_msg_holder_collection_clear(&data->send_queue_intermediate);
}

static int ipclient_data_init(struct ipclient_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(thread_data));

	return 0;
}

static int ipclient_delete_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data);
static int ipclient_queue_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data);

static int ipclient_parse_config (struct ipclient_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	rrr_setting_uint client_number;
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED_RAW("ipclient_client_number", client_number, 0);
	if (client_number == 0 || client_number > 0xffffffff) {
		RRR_MSG_0("Error while parsing setting ipclient_client_number of instance %s, must be in the range 1-4294967295 and unique for this client\n", config->name);
		ret = 1;
		goto out;
	}
	data->client_number = (uint32_t) client_number;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ipclient_default_remote", ip_default_remote);

	if (data->ip_default_remote == NULL || *(data->ip_default_remote) == '\0') {
		data->queue_method = ipclient_delete_message_callback;
	}
	else {
		data->queue_method = ipclient_queue_message_callback;
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

	if ((ret = rrr_instance_config_read_port_number(&data->src_port, config, "ipclient_src_port")) == 0) {
		// OK
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

static int ipclient_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct ipclient_data *private_data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_2 ("ipclient instance %s: Result from buffer timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&private_data->send_queue_intermediate, entry);

	rrr_msg_holder_unlock(entry);

	private_data->total_poll_count++;

	return 0;
}

static int ipclient_receive_callback(struct rrr_msg_holder *entry, void *arg) {
	struct ipclient_data *data = arg;

	int ret = 0;

	rrr_thread_watchdog_time_update(INSTANCE_D_THREAD(data->thread_data));

	// The allocator function below ensures that the entries we receive here are not dirty,
	// all writing to it was performed while the locks were held
	if ((ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			entry,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Error while writing to output buffer in ipclient instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	data->received_per_second++;

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

struct ipclient_send_packet_callback_data {
	int packet_counter;
};

static int ipclient_delete_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data) {
	RRR_MSG_0("Warning: Received a message from sender in ipclient instance %s, but remote host is not set. Dropping message.\n",
			INSTANCE_D_NAME(ipclient_data->thread_data));

	(void)(entry);
	return 0;
}

static int ipclient_queue_message_callback (struct rrr_msg_holder *entry, struct ipclient_data *ipclient_data) {
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

static int ipclient_queue_or_delete_messages(int *send_count, int *sending_complete, struct ipclient_data *data) {
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

	*sending_complete = RRR_LL_COUNT(&data->send_queue_intermediate) == 0;

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

	int ret = 0;

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
		ret = 1;
	out:
		pthread_cleanup_pop(1);
		if (joined_data != NULL && ret == 0) {
			RRR_BUG("Callback returned non-error but still did not set joined_data to NULL in ipclient_udpstream_allocator_intermediate\n");
		}
	out_no_unlock:
		return ret;
}

static int ipclient_allocator_callback (
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

static int ipclient_asd_reconnect (struct ipclient_data *data) {
	int ret = 0;

	if (data->udpstream_asd != NULL) {
		rrr_udpstream_asd_destroy(data->udpstream_asd);
		data->udpstream_asd = NULL;
	}

	if ((ret = rrr_udpstream_asd_new (
			&data->udpstream_asd,
			INSTANCE_D_EVENTS(data->thread_data),
			data->src_port,
			data->ip_default_remote,
			data->ip_default_remote_port,
			data->client_number,
			data->do_listen,
			data->do_disallow_remote_ip_swap,
			data->do_ipv4_only,
			1, // Reset remote after first connection estabilshment
			ipclient_allocator_callback,
			data,
			ipclient_receive_callback,
			data
	)) != 0) {
		RRR_MSG_0("Could not initialize ASD in ipclient instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void ipclient_event_send_queue (int fd, short flags, void *arg) {
	struct ipclient_data *data = arg;

	(void)(fd);
	(void)(flags);

	int queue_count = 0;
	int sending_complete = 0;
	if (ipclient_queue_or_delete_messages(&queue_count, &sending_complete, data) != 0) {
		data->need_network_restart = 1;
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
		// Don't return, must increment counter
	}

	data->queued_per_second += (unsigned int) queue_count;

	if (sending_complete) {
		EVENT_REMOVE(data->event_send_queue);
	}
}

static void ipclient_pause_check (RRR_EVENT_FUNCTION_PAUSE_ARGS) {
	struct ipclient_data *data = callback_arg;

	if (is_paused) {
		*do_pause = !(RRR_LL_COUNT(&data->send_queue_intermediate) < RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX * 0.75);
	}
	else {
		*do_pause = RRR_LL_COUNT(&data->send_queue_intermediate) >RRR_IPCLIENT_SEND_BUFFER_INTERMEDIATE_MAX;
	}
}

static int ipclient_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data;

	if (!EVENT_PENDING(data->event_send_queue)) {
		EVENT_ADD(data->event_send_queue);
	}
	EVENT_ACTIVATE(data->event_send_queue);

	return rrr_poll_do_poll_delete (amount, thread_data, ipclient_poll_callback);
}

static int ipclient_event_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data;

	unsigned int output_buffer_count = 0;
	int ratelimit_active = 0;

	if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
				&output_buffer_count,
				&ratelimit_active,
				thread_data
				) != 0) {
		RRR_MSG_0("Error while setting ratelimit in ipclient instance %s\n",
				INSTANCE_D_NAME(thread_data));
		return RRR_EVENT_ERR;
	}

	data->total_queued_count += data->queued_per_second;

	unsigned int sent_per_second, delivered_per_second;
	rrr_udpstream_asd_get_and_reset_counters(&sent_per_second, &delivered_per_second, data->udpstream_asd);

	if (RRR_DEBUGLEVEL_1) {
		RRR_MSG_1("ipclient instance %s OB %i SQ %i TP %" PRIu64 " TQ %" PRIu64 " r/s %u q/s %u s/s %u d/s %u\n",
				INSTANCE_D_NAME(thread_data),
				output_buffer_count,
				RRR_LL_COUNT(&data->send_queue_intermediate),
				data->total_poll_count,
				data->total_queued_count,
				data->received_per_second,
				data->queued_per_second,
				sent_per_second,
				delivered_per_second
			 );
	}

	data->received_per_second = 0;
	data->queued_per_second = 0;

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

static void *thread_entry_ipclient (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ipclient_data *data = thread_data->private_data = thread_data->private_memory;

	if (ipclient_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		return NULL;
	}

	RRR_DBG_1 ("ipclient thread data is %p\n", thread_data);

	pthread_cleanup_push(ipclient_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (ipclient_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for ipclient instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("ipclient instance %s started thread %p\n", INSTANCE_D_NAME(thread_data), thread_data);

	if (rrr_event_collection_push_periodic (
			&data->event_send_queue,
			&data->events,
			ipclient_event_send_queue,
			data,
			50 * 1000 // 50 ms
	) != 0) {
		RRR_MSG_0("Failed to create send queue event in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	network_restart:
	RRR_DBG_1 ("ipclient instance %s restarting network\n", INSTANCE_D_NAME(thread_data));
	data->need_network_restart = 0;

	if (ipclient_asd_reconnect(data) != 0) {
		RRR_MSG_0("Could not reconnect in ipclient instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_event_callback_pause_set (
			INSTANCE_D_EVENTS_H(thread_data),
			RRR_EVENT_FUNCTION_MESSAGE_BROKER_DATA_AVAILABLE,
			ipclient_pause_check,
			data
	);

	rrr_event_function_periodic_set_and_dispatch (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000,
			ipclient_event_periodic
	);

	if (data->need_network_restart) {
		rrr_posix_usleep (10000); // 10 ms
		goto network_restart;
	}

	out_message:
	RRR_DBG_1 ("Thread ipclient %p exiting\n", thread);

	pthread_cleanup_pop(1);

	return NULL;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_ipclient,
		NULL,
		NULL,
		NULL
};

struct rrr_instance_event_functions event_functions = {
	ipclient_event_broker_data_available
};

static const char *module_name = "ipclient";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy ipclient module\n");
}

