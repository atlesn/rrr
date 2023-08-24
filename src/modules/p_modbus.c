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
#define MODBUS_DEFAULT_QUANTITY 8
#define MODBUS_DEFAULT_INTERVAL_MS 0

#define MODBUS_COMMAND_TIMEOUT_S 2 /* Update man pages if this changes */

#define MODBUS_SERVER_MAX 256
#define MODBUS_STARTING_ADDRESS_MAX 0xffff
#define MODBUS_QUANTITY_MIN 1
#define MODBUS_QUANTITY_MAX 2000

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
	uint64_t last_seen;
	uint64_t interval_ms;
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
	struct modbus_command_collection commands;
	struct rrr_event_collection events;
	rrr_event_handle event_process;
};

struct modbus_client_data {
	struct modbus_data *data;
	char server[MODBUS_SERVER_MAX];
	uint16_t port;
	struct rrr_modbus_client *client;
};

static void modbus_command_node_destroy (struct modbus_command_node *node) {
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
			50000 /* dummy interval 50 ms */
	)) != 0) {
		RRR_MSG_0("Failed to create event in %s\n", __func__);
		goto out_clear_event_collection;
	}

	/* Do not add or activate the event! This is done in the update function. */

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
		uint64_t interval_ms
) {
	node->last_seen = rrr_time_get_64();

	if (interval_ms == node->interval_ms) {
		return;
	}

	EVENT_REMOVE(node->event);
	if (interval_ms > 0) {
		EVENT_INTERVAL_SET(node->event, interval_ms * 1000);
		EVENT_ADD(node->event);
		EVENT_ACTIVATE(node->event);
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
		uint64_t interval_ms
) {
	int ret = 0;

	struct modbus_command_node *node;
	struct modbus_command command = {0};

	assert(server != NULL && *server != '\0');
	assert(port != 0);
	assert(function == 1);
	assert(quantity < MODBUS_QUANTITY_MAX && quantity > MODBUS_QUANTITY_MIN);

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

		RRR_DBG_2("Modbus instance %s updating command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 "->%" PRIu64 "\n",
			INSTANCE_D_NAME(data->thread_data),
			server,
			port,
			function,
			starting_address,
			quantity,
			node->interval_ms,
			interval_ms
		);

		modbus_command_node_update(node, interval_ms);

		goto out;
	RRR_LL_ITERATE_END();

	RRR_DBG_2("Modbus instance %s new command server %s:%u function 0x%02x starting address %u quantity %u interval %" PRIu64 "\n",
		INSTANCE_D_NAME(data->thread_data),
		server,
		port,
		function,
		starting_address,
		quantity,
		interval_ms
	);

	if ((ret = modbus_command_node_new (
			&node,
			data,
			&command
	)) != 0) {
		goto out;
	}

	RRR_LL_PUSH(&data->commands, node);

	modbus_command_node_update(node, interval_ms);

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

static int modbus_callback_resolve (
		size_t *address_count,
		struct sockaddr ***addresses,
		socklen_t **address_lengths,
		void *callback_data
) {
	struct modbus_data *data = callback_data;

}

static int modbus_callback_connect (
		int *fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *callback_data
) {
	struct modbus_data *data = callback_data;

}

static void modbus_event_command (evutil_socket_t fd, short flags, void *arg) {
	(void)(fd);
	(void)(flags);

	const struct modbus_command_node *node = arg;
	const struct modbus_command *command = &node->command;
	const struct modbus_data *data = node->data;

	int ret_tmp;
	uint8_t buf[2048];
	char addr_string[sizeof(command->server) + 16];
	rrr_length buf_size;

	sprintf(addr_string, "%s:%u", command->server, command->port);

	RRR_DBG_3("Modbus instance %s send command server %s function 0x%02x starting address %u quantity %u interval %" PRIu64 "\n",
		INSTANCE_D_NAME(data->thread_data),
		addr_string,
		command->function,
		command->starting_address,
		command->quantity,
		node->interval_ms
	);

	switch (command->function) {
		case 0x01: // Read Coils
			if (rrr_modbus_client_req_01_read_coils (
					data->
			) != 0) {
				goto fail_function;
			}
			break;
		default:
			assert(0);
	};

	again:
		buf_size = sizeof(buf);
		if ((ret_tmp = rrr_modbus_client_write (
				data->client,
				buf,
				&buf_size
		)) == RRR_MODBUS_OK) {
			rrr_length send_chunk_count;
			if ((ret_tmp = rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
					&send_chunk_count,
					data->collection_tcp,
					addr_string,
					buf,
					buf_size,
					NULL,
					NULL,
					NULL,
					modbus_callback_resolve,
					data,
					modbus_callback_connect,
					data
			)) != 0) {
				goto fail_send;
			}
			goto again;
		}
		else if (ret_tmp != RRR_MOBUS_DONE) {
			goto fail_write;
		}

	return;
	fail_function:
		RRR_MSG_0("Command 0x%u failed in modbus instance %s\n",
			command->function, INSTANCE_D_NAME(data->thread_data));
		goto fail;
	fail_write:
		RRR_MSG_0("Write failed in modbus instance %s\n",
			command->function);
		goto fail;
	fail_send:
		RRR_MSG_0("Send failed in modbus instance %s\n",
			command->function);
		goto fail;
	fail:
	rrr_event_dispatch_break(INSTANCE_D_EVENTS(data->thread_data));
}

static void modbus_event_process (evutil_socket_t fd, short flags, void *arg) {
	(void)(fd);
	(void)(flags);

	struct modbus_data *data = arg;

	uint64_t time_limit = rrr_time_get_64() - MODBUS_COMMAND_TIMEOUT_S * 1000 * 1000;

	RRR_LL_ITERATE_BEGIN(&data->commands, struct modbus_command_node);
		if (node->last_seen < time_limit) {
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
			RRR_LL_ITERATE_NEXT();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->commands, 0; modbus_command_node_destroy(node));
}

#define GET_VALUE(name,type)                                                                                     \
    do {if (rrr_array_has_tag(&array, RRR_QUOTE(name))) {                                                        \
        if ((ret = RRR_PASTE_3(rrr_array_get_value_first_,type,_by_tag) (&name, &array, RRR_QUOTE(name))) != 0) {\
            RRR_MSG_0("Warning: Failed to get value of field %s of command message to modbus instance %s\n",     \
                RRR_QUOTE(name), INSTANCE_D_NAME(data->thread_data));                                            \
            ret = 0; /* Non-critical, probably user error */                                                     \
            goto drop;                                                                                           \
        }                                                                                                        \
    }} while(0)

#define GET_VALUE_UNSIGNED_64(name)  \
    GET_VALUE(name,unsigned_64)

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
	uint64_t modbus_port = MODBUS_DEFAULT_PORT;
	uint64_t modbus_function = MODBUS_DEFAULT_FUNCTION;
	uint64_t modbus_starting_address = MODBUS_DEFAULT_STARTING_ADDRESS;
	uint64_t modbus_quantity = MODBUS_DEFAULT_QUANTITY;
	uint64_t modbus_interval_ms = MODBUS_DEFAULT_INTERVAL_MS;

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

	GET_VALUE_STR(modbus_server);
	GET_VALUE_UNSIGNED_64(modbus_port);
	GET_VALUE_UNSIGNED_64(modbus_function);
	GET_VALUE_UNSIGNED_64(modbus_starting_address);
	GET_VALUE_UNSIGNED_64(modbus_quantity);
	GET_VALUE_UNSIGNED_64(modbus_interval_ms);

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

	if (modbus_function != 1) {
		RRR_MSG_0("Invalid value for field 'modbus_function' %" PRIu64 " to modbus instance %s, only a value of 1 is allowed. Dropping it.\n",
			modbus_function, INSTANCE_D_NAME(data->thread_data));
		goto drop;
	}

	if (modbus_starting_address > MODBUS_STARTING_ADDRESS_MAX) {
		RRR_MSG_0("Invalid value for field 'modbus_starting_address' %" PRIu64 " to modbus instance %s, maximum value is %u. Dropping it.\n",
			modbus_starting_address, INSTANCE_D_NAME(data->thread_data), MODBUS_STARTING_ADDRESS_MAX);
		goto drop;
	}

	if (MODBUS_QUANTITY_MIN < 1 || modbus_quantity > MODBUS_QUANTITY_MAX) {
		RRR_MSG_0("Field 'modbus_quantity' out of range in command message to modbus instance %s. Range is %u-%u while %" PRIu64 " was given, dropping it.\n",
			INSTANCE_D_NAME(data->thread_data), MODBUS_QUANTITY_MIN, MODBUS_QUANTITY_MAX, modbus_quantity);
		goto drop;
	}

	if ((ret = modbus_command_collection_push_or_replace (
			data,
			modbus_server != NULL && *modbus_server != '\0'
				? modbus_server
				: MODBUS_DEFAULT_SERVER,
			(uint16_t) modbus_port,
			(uint8_t) modbus_function,
			(uint16_t) modbus_starting_address,
			(uint16_t) modbus_quantity,
			(uint64_t) modbus_interval_ms
	)) != 0) {
		goto drop;
	}

	drop:
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

	if ((client_data = rrr_allocate_zero(sizeof(*client_data))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_modbus_client_new (&client_data->client)) != 0) {
		RRR_MSG_0("Failed to create client in %s\n", __func__);
		goto out_free;
	}

	client_data->data = data;

	*target = client_data;

	goto out;
//	out_destroy_client:
//		rrr_modbus_client_destroy(client_data->client);
	out_free:
		rrr_free(client_data);
	out:
		return ret;
}

static void modbus_callback_private_data_destroy (void *private_data) {
	struct modbus_client_data *client_data = private_data;
	rrr_modbus_client_destroy(client_data->client);
	rrr_free(client_data);
}

static void modbus_callback_set_read_flags (RRR_SOCKET_CLIENT_SET_READ_FLAGS_CALLBACK_ARGS) {
}

static int modbus_callback_get_target_size (RRR_SOCKET_CLIENT_RAW_GET_TARGET_SIZE_CALLBACK_ARGS) {
}

static void modbus_callback_error (RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS) {
}

static int modbus_callback_complete (RRR_SOCKET_CLIENT_RAW_COMPLETE_CALLBACK_ARGS) {
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

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_message:
	modbus_data_cleanup(data);

	RRR_DBG_1 ("Thread modbus %p exiting\n", thread);

	pthread_exit(0);
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
		modbus_inject
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

