/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "../lib/log.h"
#include "../lib/allocator.h"

#include "../lib/modbus/rrr_modbus.h"
#include "../lib/event/event_collection.h"
#include "../lib/event/event_collection_struct.h"
#include "../lib/ip/ip.h"
#include "../lib/ip/ip_helper.h"
#include "../lib/ip/ip_util.h"
#include "../lib/array.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/poll_helper.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/threads.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/util/linked_list.h"
#include "../lib/socket/rrr_socket_client.h"

#define MODBUS_DEFAULT_SERVER "localhost"
#define MODBUS_DEFAULT_PORT 502
#define MODBUS_DEFAULT_FUNCTION 1 /* Read Coils */
#define MODBUS_DEFAULT_STARTING_ADDRESS 0
#define MODBUS_DEFAULT_QUANTITY_COIL 8
#define MODBUS_DEFAULT_QUANTITY_REGISTER 1

#define MODBUS_DEFAULT_INTERVAL_MS 0
#define MODBUS_DEFAULT_RESPONSE_TOPIC NULL

#define MODBUS_COMMAND_TIMEOUT_S 2 /* Update man pages if this changes */
#define MODBUS_COMMAND_SEND_TIMEOUT_S 4

#define MODBUS_SERVER_MAX 256
#define MODBUS_STARTING_ADDRESS_MAX 0xffff
#define MODBUS_QUANTITY_COIL_MIN 1
#define MODBUS_QUANTITY_COIL_MAX 2000
#define MODBUS_QUANTITY_REGISTER_MIN 1
#define MODBUS_QUANTITY_REGISTER_MAX 125

static const char *modbus_field_server            = "modbus_server";
static const char *modbus_field_port              = "modbus_port";
static const char *modbus_field_function          = "modbus_function_code";
static const char *modbus_field_exception_code    = "modbus_exception_code";
static const char *modbus_field_starting_address  = "modbus_starting_address";
static const char *modbus_field_quantity          = "modbus_quantity";
static const char *modbus_field_bytes             = "modbus_bytes";
static const char *modbus_field_status            = "modbus_status";

static const char *modbus_field_interval_ms       = "modbus_interval_ms";
static const char *modbus_field_response_topic    = "modbus_response_topic";

struct modbus_data;

static void modbus_event_command (evutil_socket_t fd, short flags, void *arg);

struct modbus_command {
	char server[MODBUS_SERVER_MAX];
	uint16_t port;
	uint8_t function;
	uint16_t starting_address;
	uint16_t quantity;
};

struct modbus_command_node {
	RRR_LL_NODE(struct modbus_command_node);
	struct modbus_data *data;
	uint64_t last_seen_time;
	uint64_t send_time;
	uint64_t interval_ms;
	char *response_topic;
	rrr_u16 response_topic_length;
	struct modbus_command command;
	struct rrr_event_collection events;
	rrr_event_handle event;
};

struct modbus_command_collection {
	RRR_LL_HEAD(struct modbus_command_node);
};

struct modbus_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_socket_client_collection *collection_tcp;
	struct rrr_modbus_client_callbacks modbus_client_callbacks;
	struct modbus_command_collection commands;
	struct rrr_event_collection events;
	rrr_event_handle event_process;
};

struct modbus_client_data {
	struct modbus_data *data;
	struct modbus_command_node *node;
	char server[MODBUS_SERVER_MAX];
	uint16_t port;
	struct rrr_modbus_client *client;
};

struct modbus_transaction_data {
	char *response_topic;
	rrr_u16 response_topic_length;
	struct modbus_command command;
};

static void modbus_command_node_destroy (struct modbus_command_node *node) {
	RRR_FREE_IF_NOT_NULL(node->response_topic);
	rrr_event_collection_clear(&node->events);
	rrr_free(node);
}

static void modbus_command_collection_destroy (struct modbus_command_collection *collection) {
	RRR_LL_DESTROY(collection, struct modbus_command_node, modbus_command_node_destroy(node));
};

static int modbus_command_node_new (
		struct modbus_command_node **target,
		struct modbus_data *data,
		struct modbus_command *command
) {
	int ret = 0;

	struct modbus_command_node *node;

	if ((node = rrr_allocate_zero(sizeof(*node))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	rrr_event_collection_init(&node->events, INSTANCE_D_EVENTS(data->thread_data));

	if ((ret = rrr_event_collection_push_periodic (
			&node->event,
			&node->events,
			modbus_event_command,
			node,
			50000 // 25 ms
	)) != 0) {
		RRR_MSG_0("Failed to create event in %s\n", __func__);
		goto out_clear_event_collection;
	}

	node->data = data;
	node->command = *command;

	*target = node;

	goto out;
	out_clear_event_collection:
		rrr_event_collection_clear(&node->events);
//	out_free:
		rrr_free(node);
	out:
		return ret;
}

static void modbus_command_node_update (
		struct modbus_command_node *node,
		uint64_t interval_ms,
		char **response_topic,
		int first
) {
	node->last_seen_time = rrr_time_get_64();

	RRR_FREE_IF_NOT_NULL(node->response_topic);
	node->response_topic_length = 0;

	if (*response_topic != NULL) {
		// Consume memory
		node->response_topic = *response_topic;
		*response_topic = NULL;
		size_t length = strlen(node->response_topic);
		assert(length <= RRR_MSG_TOPIC_MAX);
		node->response_topic_length = (rrr_u16) length;
	}

	if (interval_ms == node->interval_ms && interval_ms > 0 && !first) {
		return;
	}

	if (first) {
		EVENT_ADD(node->event);
	}
	EVENT_ACTIVATE(node->event);

	if (interval_ms > 0) {
		EVENT_INTERVAL_SET(node->event, interval_ms * 1000);
		EVENT_ADD(node->event);
	}
	else {
		/* If interval is zero, the event is removed in the command event
		 * callback. We must call this functionon repeatedly in the beginning
		 * to wait for the connection to be established. */
	}

	node->interval_ms = interval_ms;
}

static int modbus_command_collection_push_or_replace (
		struct modbus_data *data,
		const char *server,
		uint16_t port,
		uint8_t function,
		uint16_t starting_address,
		uint16_t quantity,
		uint64_t interval_ms,
		char **response_topic
) {
	int ret = 0;

	struct modbus_command_node *node;
	struct modbus_command command = {0};

	assert(server != NULL && *server != '\0');
	assert(port != 0);

	if (strlen(server) > sizeof(command.server) - 1) {
		RRR_MSG_0("Length of server exceeds maximum in %s of modbus instance %s\n",
			__func__, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	strcpy(command.server, server);
	command.port = port;
	command.function = function;
	command.starting_address = starting_address;
	command.quantity = quantity;

	RRR_LL_ITERATE_BEGIN(&data->commands, struct modbus_command_node);
		if (memcmp(&node->command, &command, sizeof(command)) != 0) {
			RRR_LL_ITERATE_NEXT();
		}

		RRR_DBG_2("Modbus instance %s updating command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 "->%" PRIu64 " response topic '%s'\n",
			INSTANCE_D_NAME(data->thread_data),
			server,
			port,
			function,
			starting_address,
			quantity,
			node->interval_ms,
			interval_ms,
			*response_topic
		);

		modbus_command_node_update(node, interval_ms, response_topic, 0 /* Not first */);

		goto out;
	RRR_LL_ITERATE_END();

	RRR_DBG_2("Modbus instance %s new command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 " response topic '%s'\n",
		INSTANCE_D_NAME(data->thread_data),
		server,
		port,
		function,
		starting_address,
		quantity,
		interval_ms,
		*response_topic
	);

	if ((ret = modbus_command_node_new (
			&node,
			data,
			&command
	)) != 0) {
		goto out;
	}

	RRR_LL_PUSH(&data->commands, node);

	modbus_command_node_update(node, interval_ms, response_topic, 1 /* First */);

	out:
	return ret;
}

static void modbus_data_init(struct modbus_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void modbus_data_cleanup(struct modbus_data *data) {
	rrr_event_collection_clear(&data->events);
	if (data->collection_tcp != NULL) {
		rrr_socket_client_collection_destroy(data->collection_tcp);
	}
	modbus_command_collection_destroy(&data->commands);
}

static int modbus_client_data_new (
		struct modbus_client_data **result
) {
	int ret = 0;

	struct modbus_client_data *client_data;

	if ((client_data = rrr_allocate_zero(sizeof(*client_data))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_modbus_client_new (&client_data->client)) != 0) {
		RRR_MSG_0("Failed to create client in %s\n", __func__);
		goto out_free;
	}

	*result = client_data;

	goto out;
	out_free:
		rrr_free(client_data);
	out:
		return ret;
}

static void modbus_client_data_destroy (
		struct modbus_client_data *client_data
) {
	rrr_modbus_client_destroy(client_data->client);
	rrr_free(client_data);
}

static void modbus_client_data_setup_initial (
		struct modbus_data *data,
		struct modbus_client_data *client_data
) {
	struct rrr_modbus_client_callbacks callbacks = data->modbus_client_callbacks;
	callbacks.arg = client_data;
	rrr_modbus_client_callbacks_set(client_data->client, &callbacks);

	client_data->data = data;
}

static int modbus_client_data_setup_final (
		struct modbus_client_data *client_data,
		const struct modbus_command *command
) {
	int ret = 0;

	if (client_data->port != 0) {
		// Already initialized
		goto out;
	}

	strcpy(client_data->server, command->server);
	client_data->port = command->port;

	out:
	return ret;
}

static int modbus_transaction_data_new (
		struct modbus_transaction_data **result,
		const struct modbus_command *command,
		const char *response_topic,
		rrr_u16 response_topic_length
) {
	int ret = 0;

	struct modbus_transaction_data *transaction_data;

	if ((transaction_data = rrr_allocate_zero(sizeof(*transaction_data))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (response_topic != NULL) {
		if ((transaction_data->response_topic = rrr_strdup(response_topic)) == NULL) {
			RRR_MSG_0("Failed to allocate response topic in %s\n", __func__);
			ret = 1;
			goto out_free;
		}
		transaction_data->response_topic_length = response_topic_length;
	}

	transaction_data->command = *command;

	*result = transaction_data;

	goto out;
	out_free:
		rrr_free(transaction_data);
	out:
		return ret;
}

static void modbus_transaction_data_destroy (
		struct modbus_transaction_data *transaction_data
) {
	RRR_FREE_IF_NOT_NULL(transaction_data->response_topic);
	rrr_free(transaction_data);
}

struct modbus_output_callback_data {
	const struct rrr_array *array;
	const char *response_topic;
	rrr_u16 response_topic_length;
};

static int modbus_output_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct modbus_output_callback_data *callback_data = arg;

	int ret = 0;

	if ((ret = rrr_array_new_message_from_array (
			(struct rrr_msg_msg **) &new_entry->message,
			callback_data->array,
			rrr_time_get_64(),
			callback_data->response_topic,
			callback_data->response_topic_length
	)) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto out;
	}

	new_entry->data_length = MSG_TOTAL_SIZE((struct rrr_msg_msg *) new_entry->message);

	out:
	rrr_msg_holder_unlock(new_entry);
	return ret;
}

static int modbus_output (
		struct modbus_data *data,
		struct rrr_array *array,
		const char *response_topic,
		rrr_u16 response_topic_length,
		const char *server,
		uint16_t port,
		uint8_t function_code
) {
	int ret = 0;

	if ((ret = rrr_array_push_value_str_with_tag (array, modbus_field_server, server)) != 0) {
		RRR_MSG_0("Failed to push value in %s\n", __func__);
		goto out;
	}
	if ((ret = rrr_array_push_value_u64_with_tag (array, modbus_field_port, port)) != 0) {
		RRR_MSG_0("Failed to push value in %s\n", __func__);
		goto out;
	}
	if ((ret = rrr_array_push_value_u64_with_tag (array, modbus_field_function, function_code)) != 0) {
		RRR_MSG_0("Failed to push value in %s\n", __func__);
		goto out;
	}

	/* Have the function code first in the array */
	rrr_array_rotate_forward(array);

	struct modbus_output_callback_data callback_data = {
		array,
		response_topic,
		response_topic_length
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			modbus_output_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct modbus_transaction_private_data_create_callback_data {
	const struct modbus_command *command;
	const char *request_topic;
	rrr_u16 request_topic_length;
};

int modbus_callback_req_transaction_private_data_create (void **result, void *private_data_arg, void *arg) {
	struct modbus_transaction_private_data_create_callback_data *callback_data = private_data_arg;
	struct modbus_data *data = arg;

	(void)(data);

	int ret = 0;

	struct modbus_transaction_data *transaction_data;

	if ((ret = modbus_transaction_data_new (
			&transaction_data,
			callback_data->command,
			callback_data->request_topic,
			callback_data->request_topic_length
	)) != 0) {
		goto out;
	}

	*result = transaction_data;

	out:
	return ret;
}

void modbus_callback_req_transaction_private_data_destroy (void *private_data) {
	struct modbus_transaction_data *transaction_data = private_data;
	modbus_transaction_data_destroy(transaction_data);
}

static int modbus_callback_res_byte_count_and_values (
		RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS
) {
	struct modbus_client_data *client_data = arg;
	struct modbus_transaction_data *transaction_data = transaction_private_data;
	struct modbus_data *data = client_data->data;

	int ret = 0;

	struct rrr_array array = {0};

	RRR_DBG_2("Response from server %s:%u in modbus instance %s: Transaction %u function %u byte count %u\n",
		client_data->server,
		client_data->port,
		INSTANCE_D_NAME(data->thread_data),
		transaction_id,
		function_code,
		byte_count);

	if ((ret = rrr_array_push_value_u64_with_tag (&array, modbus_field_bytes, byte_count)) != 0) {
		goto push_fail;
	}

	if ((ret = rrr_array_push_value_blob_with_tag_with_size (&array, modbus_field_status, (const char *) coil_status, byte_count)) != 0) {
		goto push_fail;
	}

	if ((ret = modbus_output (
			client_data->data,
			&array,
			transaction_data->response_topic,
			transaction_data->response_topic_length,
			client_data->server,
			client_data->port,
			function_code
	)) != 0) {
		goto out;
	}

	goto out;
	push_fail:
		RRR_MSG_0("Failed to push array value in %s\n", __func__);
	out:
		rrr_array_clear(&array);
		return ret;
}

static int modbus_callback_res_error (
		RRR_MODBUS_ERROR_CALLBACK_ARGS
) {
	struct modbus_client_data *client_data = arg;
	struct modbus_transaction_data *transaction_data = transaction_private_data;

	int ret = 0;

	struct rrr_array array = {0};

	RRR_MSG_0("Error response from server %s:%u in modbus instance %s: Transaction %u function 0x%02x exception %u\n",
		client_data->server,
		client_data->port,
		INSTANCE_D_NAME(client_data->data->thread_data),
		transaction_id,
		function_code,
		error_code
	);

	if ((ret = rrr_array_push_value_u64_with_tag (&array, modbus_field_exception_code, error_code)) != 0) {
		goto push_fail;
	}

	if ((ret = modbus_output (
			client_data->data,
			&array,
			transaction_data->response_topic,
			transaction_data->response_topic_length,
			client_data->server,
			client_data->port,
			function_code
	)) != 0) {
		goto out;
	}

	goto out;
	push_fail:
		RRR_MSG_0("Failed to push array value in %s\n", __func__);
	out:
		rrr_array_clear(&array);
		return ret;
}

static int modbus_callback_connect (
		int *fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *callback_data
) {
	struct modbus_data *data = callback_data;

	(void)(fd);

	int ret = 0;

	char buf[256];
	uint16_t port;

	if (rrr_ip_to_str_and_port(&port, buf, sizeof(buf), addr, addr_len) != 0) {
		RRR_MSG_0("Warning: Address to string failed in %s\n", __func__);
		goto out;
	}

	RRR_DBG_2("Connect to server %s:%u in modbus instance %s\n", buf, port, INSTANCE_D_NAME(data->thread_data));

	if ((ret = rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw_nonblock (
			fd,
			addr,
			addr_len
	)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_MSG_0("Failed to connect to server %s:%u in modbus instance %s\n",
				buf, port, INSTANCE_D_NAME(data->thread_data));
		}
		else {
			RRR_MSG_0("Hard error during connect in modbus instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		}
		goto out;
	}

	out:
	return ret;
}

struct modbus_data_prepare_callback_data {
	struct modbus_data *data;
	struct modbus_command_node *node;
	uint8_t *buf;
	rrr_biglength buf_size_orig;
};

static int modbus_callback_data_prepare (
		const void **_buf,
		rrr_biglength *_buf_size,
		void *callback_arg,
		void *private_data
) {
	struct modbus_data_prepare_callback_data *callback_data = callback_arg;
	struct modbus_client_data *client_data = private_data;
	struct modbus_command_node *node = callback_data->node;
	struct modbus_command *command = &node->command;
	struct modbus_data *data = callback_data->data;

	(void)(_buf);

	int ret = 0;

	/* NOTE : Buf pointers in callback data and argument point to same memory */

	uint8_t *buf = callback_data->buf;
	rrr_length buf_size = rrr_length_from_biglength_bug_const(callback_data->buf_size_orig);

	if (client_data == NULL) {
		ret = RRR_SOCKET_NOT_READY;
		goto out;
	}

	if ((ret = modbus_client_data_setup_final(client_data, command)) != 0) {
		goto out;
	}

	assert(callback_data->buf == *_buf);
	assert(*_buf_size == callback_data->buf_size_orig);

	struct modbus_transaction_private_data_create_callback_data private_data_create_callback_data = {
		command,
		node->response_topic,
		node->response_topic_length
	};

	switch (command->function) {
		case 0x01: // Read Coils
			ret = rrr_modbus_client_req_01_read_coils (
					client_data->client,
					command->starting_address,
					command->quantity,
					&private_data_create_callback_data
			);
			break;
		case 0x02: // Read Discrete Inputs
			ret = rrr_modbus_client_req_02_read_discrete_inputs (
					client_data->client,
					command->starting_address,
					command->quantity,
					&private_data_create_callback_data
			);
			break;
		case 0x03: // Read Holding Registers
			ret = rrr_modbus_client_req_03_read_holding_registers (
					client_data->client,
					command->starting_address,
					command->quantity,
					&private_data_create_callback_data
			);
			break;
		default:
			assert(0);
	};

	if (ret != 0) {
		if (ret == RRR_MODBUS_BUSY) {
			RRR_MSG_0("Warning: Failed to create command packet for function 0x%02x in modbus instance %s, possible full send buffer.\n",
				command->function, INSTANCE_D_NAME(data->thread_data));
			ret = 0; /* Mask error and try to write */
		}
		else if (ret == RRR_MODBUS_SOFT_ERROR) {
			RRR_MSG_0("Failed to create command packet for function 0x%02x in modbus instance %s, possible command timeout.\n",
				command->function, INSTANCE_D_NAME(data->thread_data));
			goto out; /* Return error to make client collection close the connection */
		}
		else {
			RRR_MSG_0("Failed to create command packet for function 0x%02x in modbus instance %s, return was %i\n",
				command->function, INSTANCE_D_NAME(data->thread_data), ret);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_modbus_client_write (
			client_data->client,
			buf,
			&buf_size
	)) == RRR_MODBUS_OK) {
		*_buf_size = buf_size;
	}
	else if (ret == RRR_MODBUS_DONE) {
		ret = 0;
	}
	else {
		RRR_MSG_0("Write failed in modbus instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;

}

static void modbus_event_command (evutil_socket_t fd, short flags, void *arg) {
	struct modbus_command_node *node = arg;
	struct modbus_command *command = &node->command;
	struct modbus_data *data = node->data;

	(void)(fd);
	(void)(flags);

	int ret_tmp;
	uint8_t buf[2048];

	RRR_EVENT_HOOK();

	RRR_DBG_3("Modbus instance %s send command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 "\n",
		INSTANCE_D_NAME(data->thread_data),
		command->server,
		command->port,
		command->function,
		command->starting_address,
		command->quantity,
		node->interval_ms
	);

	struct modbus_data_prepare_callback_data prepare_callback_data = {
		data,
		node,
		buf,
		sizeof(buf)
	};

	if (node->send_time == 0) {
		node->send_time = rrr_time_get_64();
	}

	rrr_length send_chunk_count;
	if ((ret_tmp = rrr_ip_socket_client_collection_send_push_const_by_host_and_port_connect_as_needed (
			&send_chunk_count,
			data->collection_tcp,
			command->server,
			command->port,
			buf,
			sizeof(buf),
			NULL,
			NULL,
			NULL,
			modbus_callback_connect,
			data,
			modbus_callback_data_prepare,
			&prepare_callback_data
	)) != 0) {
		if (ret_tmp == RRR_SOCKET_NOT_READY) {
			RRR_DBG_2("Modbus instance %s connection to %s:%u not yet ready\n",
				INSTANCE_D_NAME(data->thread_data), command->server, command->port);
		}
		else {
			if (ret_tmp == RRR_SOCKET_SOFT_ERROR) {
				RRR_MSG_0("Modbus instance %s connection to %s:%u soft error\n",
					INSTANCE_D_NAME(data->thread_data), command->server, command->port);
			}
			else {
				goto fail_send;
			}
		}
	}
	else {
		node->send_time = 0;
		if (node->interval_ms == 0) {
			EVENT_REMOVE(node->event);
		}
	}

	return;
	fail_send:
		RRR_MSG_0("Send or connection failed in modbus instance %s, return was %i\n",
			INSTANCE_D_NAME(data->thread_data), ret_tmp);
		goto fail;
	fail:
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
}

static void modbus_event_process (evutil_socket_t fd, short flags, void *arg) {
	struct modbus_data *data = arg;

	(void)(fd);
	(void)(flags);

	uint64_t command_time_limit = rrr_time_get_64() - MODBUS_COMMAND_TIMEOUT_S * 1000 * 1000;
	uint64_t send_time_limit = rrr_time_get_64() - MODBUS_COMMAND_SEND_TIMEOUT_S * 1000 * 1000;

	RRR_EVENT_HOOK();

	RRR_LL_ITERATE_BEGIN(&data->commands, struct modbus_command_node);
		if (node->last_seen_time < command_time_limit) {
			RRR_DBG_2("Modbus instance %s timeout for command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 "\n",
				INSTANCE_D_NAME(data->thread_data),
				node->command.server,
				node->command.port,
				node->command.function,
				node->command.starting_address,
				node->command.quantity,
				node->interval_ms
			);
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (node->send_time > 0 && node->send_time < send_time_limit) {
			RRR_MSG_0("Modbus instance %s send timeout for command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 ", server is not reachable.\n",
				INSTANCE_D_NAME(data->thread_data),
				node->command.server,
				node->command.port,
				node->command.function,
				node->command.starting_address,
				node->command.quantity,
				node->interval_ms
			);
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->commands, 0; modbus_command_node_destroy(node));
}

#define GET_VALUE(name,type)                                                                                     \
    do {if (rrr_array_has_tag(&array, RRR_PASTE(modbus_field_,name))) {                                          \
        if ((ret = RRR_PASTE_3(rrr_array_get_value_first_,type,_by_tag) (&RRR_PASTE(modbus_,name), &array, RRR_PASTE(modbus_field_,name))) != 0) {\
            RRR_MSG_0("Warning: Failed to get value of field %s of command message to modbus instance %s\n",     \
                RRR_QUOTE(name), INSTANCE_D_NAME(data->thread_data));                                            \
            ret = 0; /* Non-critical, probably user error */                                                     \
            goto drop;                                                                                           \
        }                                                                                                        \
    }} while(0)

#define GET_VALUE_ULL(name)  \
    GET_VALUE(name,ull)

#define GET_VALUE_STR(name)          \
    GET_VALUE(name,str)

static int modbus_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct modbus_data *data = thread_data->private_data;

	(void)(data);

	const struct rrr_msg_msg *message = entry->message;

	int ret = 0;

	uint16_t array_version;
	struct rrr_array array = {0};

	char *modbus_server = NULL;
	unsigned long long modbus_port = MODBUS_DEFAULT_PORT;
	unsigned long long modbus_function = MODBUS_DEFAULT_FUNCTION;
	unsigned long long modbus_quantity; // Default is set after we are sure about the function
	unsigned long long modbus_starting_address = MODBUS_DEFAULT_STARTING_ADDRESS;
	unsigned long long modbus_interval_ms = MODBUS_DEFAULT_INTERVAL_MS;
	char *modbus_response_topic = MODBUS_DEFAULT_RESPONSE_TOPIC;

	RRR_DBG_2("modbus instance %s received a message with timestamp %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp
	);

	if (!MSG_IS_ARRAY(message)) {
		RRR_MSG_0("Warning: Non-array message received in modbus instance %s, dropping it.\n",
			INSTANCE_D_NAME(data->thread_data));
		goto drop;
	}

	if ((ret = rrr_array_message_append_to_array (
			&array_version,
			&array,
			message
	)) != 0) {
		RRR_MSG_0("Failed to get array from message in %s\n", __func__);
		goto drop;
	}

	GET_VALUE_STR(server);
	GET_VALUE_ULL(port);
	GET_VALUE_ULL(function);

	// Default value of quantity depend on function
	modbus_quantity = modbus_function == 0x03 // Read Holding Registers
		? MODBUS_DEFAULT_QUANTITY_REGISTER
		: MODBUS_DEFAULT_QUANTITY_COIL;

	GET_VALUE_ULL(starting_address);
	GET_VALUE_ULL(quantity);
	GET_VALUE_ULL(interval_ms);
	GET_VALUE_STR(response_topic);

	if (modbus_server != NULL && strlen(modbus_server) > MODBUS_SERVER_MAX - 1) {
		RRR_MSG_0("Field 'modbus_server' exceeds maximum length in command message to modbus instance %s, dropping it.\n",
			INSTANCE_D_NAME(data->thread_data));
		goto drop;
	}

	if (modbus_port < 1 || modbus_port > 65535) {
		RRR_MSG_0("Field 'modbus_port' out of range in command message to modbus instance %s. Range is %u-%u while %" PRIu64 " was given, dropping it.\n",
			INSTANCE_D_NAME(data->thread_data), 1, 65535, modbus_port);
		goto drop;
	}

	if (modbus_response_topic != NULL && *modbus_response_topic != '\0') {
		if (strlen(modbus_response_topic) > RRR_MSG_TOPIC_MAX) {
			RRR_MSG_0("Field 'modbus_response_topic' exceeds maximum length of %u in command message to modbus instance %s, dropping it.\n",
				RRR_MSG_TOPIC_MAX, INSTANCE_D_NAME(data->thread_data));
			goto drop;
		}
	}

	if (modbus_function < 1 || modbus_function > 3) {
		RRR_MSG_0("Invalid value for field 'modbus_function' %" PRIu64 " to modbus instance %s, only a value between 1 and 3 is allowed. Dropping it.\n",
			modbus_function, INSTANCE_D_NAME(data->thread_data));
		goto drop;
	}

	if (modbus_starting_address > MODBUS_STARTING_ADDRESS_MAX) {
		RRR_MSG_0("Invalid value for field 'modbus_starting_address' %" PRIu64 " to modbus instance %s, maximum value is %u. Dropping it.\n",
			modbus_starting_address, INSTANCE_D_NAME(data->thread_data), MODBUS_STARTING_ADDRESS_MAX);
		goto drop;
	}

	switch (modbus_function) {
		case 1:
		case 2:
			if (MODBUS_QUANTITY_COIL_MIN < 1 || modbus_quantity > MODBUS_QUANTITY_COIL_MAX) {
				RRR_MSG_0("Field 'modbus_quantity' out of range in command message to modbus instance %s. Range is %u-%u for this function (%u) while %" PRIu64 " was given, dropping it.\n",
					INSTANCE_D_NAME(data->thread_data), MODBUS_QUANTITY_COIL_MIN, MODBUS_QUANTITY_COIL_MAX, modbus_function, modbus_quantity);
				goto drop;
			}
			break;
		case 3:
			if (MODBUS_QUANTITY_REGISTER_MIN < 1 || modbus_quantity > MODBUS_QUANTITY_REGISTER_MAX) {
				RRR_MSG_0("Field 'modbus_quantity' out of range in command message to modbus instance %s. Range is %u-%u for this function (%u) while %" PRIu64 " was given, dropping it.\n",
					INSTANCE_D_NAME(data->thread_data), MODBUS_QUANTITY_REGISTER_MIN, MODBUS_QUANTITY_REGISTER_MAX, modbus_function, modbus_quantity);
				goto drop;
			}
			break;
		default:
			assert(0);
	};

	if ((ret = modbus_command_collection_push_or_replace (
			data,
			modbus_server != NULL && *modbus_server != '\0'
				? modbus_server
				: MODBUS_DEFAULT_SERVER,
			(uint16_t) modbus_port,
			(uint8_t) modbus_function,
			(uint16_t) modbus_starting_address,
			(uint16_t) modbus_quantity,
			(uint64_t) modbus_interval_ms,
			&modbus_response_topic /* Memory is consumed upon success */
	)) != 0) {
		goto drop;
	}

	drop:
	RRR_FREE_IF_NOT_NULL(modbus_response_topic);
	RRR_FREE_IF_NOT_NULL(modbus_server);
	rrr_array_clear(&array);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int modbus_callback_private_data_new (void **target, int fd, void *private_arg) {
	(void)(fd);

	struct modbus_data *data = private_arg;

	int ret = 0;

	struct modbus_client_data *client_data;

	if ((ret = modbus_client_data_new (&client_data)) != 0) {
		goto out;
	}

	modbus_client_data_setup_initial (
			data,
			client_data
	);

	*target = client_data;

	out:
	return ret;
}

static void modbus_callback_private_data_destroy (void *private_data) {
	struct modbus_client_data *client_data = private_data;
	modbus_client_data_destroy (client_data);
}

static void modbus_callback_set_read_flags (RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS) {
	(void)(socket_read_flags);
	(void)(do_soft_error_propagates);
	(void)(private_data);
	(void)(arg);
}

static int modbus_callback_get_target_size (RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS) {
	int ret = RRR_READ_OK;

	(void)(addr);
	(void)(addr_len);

	struct modbus_client_data *client_data = private_data;
	struct modbus_data *data = arg;

	rrr_length data_size = rrr_length_from_biglength_bug_const(read_session->rx_buf_wpos);

	if ((ret = rrr_modbus_client_read (
			client_data->client,
			(uint8_t *) read_session->rx_buf_ptr,
			&data_size
	)) != 0) {
		if (ret != RRR_READ_INCOMPLETE) {
			RRR_MSG_0("Error %i from modbus client in %s in modbus instance %s\n",
				ret, __func__, INSTANCE_D_NAME(data->thread_data));
		}
		goto out;
	}

	read_session->target_size = data_size;

	out:
	return ret;
}

static void modbus_callback_error (RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS) {
	(void)(read_session);
	(void)(addr);
	(void)(addr_len);

	struct modbus_client_data *client_data = private_data;
	struct modbus_data *data = arg;

	RRR_MSG_0("Error %s for server %s:%u in modbus instance %s\n",
		(is_hard_err ? "hard" : "soft"), client_data->server, client_data->port, INSTANCE_D_NAME(data->thread_data));

	if (is_hard_err) {
		rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
	}
}

static int modbus_callback_complete (RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS) {
	(void)(read_session);
	(void)(addr);
	(void)(addr_len);
	(void)(private_data);
	(void)(arg);

	/* Everything is done in get_target_size callback, nothing to do here */

	return RRR_READ_OK;
}

static int modbus_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	return rrr_poll_do_poll_delete (amount, thread_data, modbus_poll_callback);
}

static int modbus_parse_config (struct modbus_data *data, struct rrr_instance_config_data *config) {
	(void)(data);
	(void)(config);

	int ret = 0;

	return ret;
}

static void *thread_entry_modbus (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct modbus_data *data = thread_data->private_data = thread_data->private_memory;
	RRR_DBG_1 ("modbus thread thread_data is %p\n", thread_data);

	rrr_thread_start_condition_helper_nofork(thread);

	modbus_data_init(data, thread_data);

	data->modbus_client_callbacks.cb_req_transaction_private_data_create = modbus_callback_req_transaction_private_data_create;
	data->modbus_client_callbacks.cb_req_transaction_private_data_destroy = modbus_callback_req_transaction_private_data_destroy;
	data->modbus_client_callbacks.cb_res_01_read_coils = modbus_callback_res_byte_count_and_values;
	data->modbus_client_callbacks.cb_res_02_read_discrete_inputs = modbus_callback_res_byte_count_and_values;
	data->modbus_client_callbacks.cb_res_03_read_holding_registers = modbus_callback_res_byte_count_and_values;
	data->modbus_client_callbacks.cb_res_error = modbus_callback_res_error;

	if (rrr_socket_client_collection_new (&data->collection_tcp, INSTANCE_D_EVENTS(thread_data), INSTANCE_D_NAME(data->thread_data)) != 0) {
		RRR_MSG_0("Failed to create TCP client collection in modbus instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (modbus_parse_config(data, INSTANCE_D_CONFIG(thread_data)) != 0) {
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("modbus instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_collection_init(&data->events, INSTANCE_D_EVENTS(data->thread_data));

	if (rrr_event_collection_push_periodic (
			&data->event_process,
			&data->events,
			modbus_event_process,
			data,
			50000 // 50 ms
	) != 0) {
		RRR_MSG_0("Failed to create event in %s\n", __func__);
		goto out_message;
	}

	EVENT_ADD(data->event_process);

	rrr_socket_client_collection_event_setup_raw (
			data->collection_tcp,
			modbus_callback_private_data_new,
			modbus_callback_private_data_destroy,
			data,
			2048, /* Read step max size */
			RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_SOCKET_READ_CHECK_EOF | RRR_SOCKET_READ_FIRST_EOF_OK,
			modbus_callback_set_read_flags,
			data,
			modbus_callback_get_target_size,
			data,
			modbus_callback_error,
			data,
			modbus_callback_complete,
			data
	);

	rrr_event_function_periodic_set_and_dispatch (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void
	);

	out_message:
	modbus_data_cleanup(data);

	RRR_DBG_1 ("Thread modbus %p exiting\n", thread);

	return NULL;
}

static int modbus_inject (RRR_MODULE_INJECT_SIGNATURE) {
	RRR_DBG_2("modbus instance %s: writing data from inject function\n", INSTANCE_D_NAME(thread_data));

	int ret = 0;

	if ((ret = rrr_message_broker_clone_and_write_entry (
			INSTANCE_D_BROKER_ARGS(thread_data),
			message,
			NULL
	)) != 0) {
		RRR_MSG_0("Error while injecting packet in modbus instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out;
	}

	out:
	rrr_msg_holder_unlock(message);
	return ret;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_modbus,
		modbus_inject,
		NULL,
		NULL
};

struct rrr_instance_event_functions event_functions = {
	modbus_event_broker_data_available
};

static const char *module_name = "modbus";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->event_functions = event_functions;
}

void unload(void) {
	RRR_DBG_1 ("Destroy modbus module\n");
}

