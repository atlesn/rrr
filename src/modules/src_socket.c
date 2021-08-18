/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/settings.h"
#include "../lib/threads.h"
#include "../lib/read.h"
#include "../lib/array.h"
#include "../lib/array_tree.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/message_broker.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/socket/rrr_socket_client.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/utf8.h"
#include "../lib/util/rrr_time.h"

struct socket_data {
	struct rrr_instance_runtime_data *thread_data;
	char *socket_path;
	char *default_topic;
	uint16_t default_topic_length;
	int receive_rrr_message;
	int do_sync_byte_by_byte;
	int do_unlink_if_exists;
	struct rrr_array_tree *tree;
	struct rrr_socket_client_collection *clients;
	uint64_t message_count;
	struct rrr_array array_tmp;
};

void data_cleanup(void *arg) {
	struct socket_data *data = (struct socket_data *) arg;
	if (data->tree != NULL) {
		rrr_array_tree_destroy(data->tree);
	}
	if (data->clients != NULL) {
		rrr_socket_client_collection_destroy(data->clients);
	}
	RRR_FREE_IF_NOT_NULL(data->socket_path);
	RRR_FREE_IF_NOT_NULL(data->default_topic);
	rrr_array_clear(&data->array_tmp);
}

int data_init(struct socket_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

int parse_config (struct socket_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	// Socket path
	if (rrr_settings_get_string_noconvert(&data->socket_path, config->settings, "socket_path") != 0) {
		RRR_MSG_0("Error while parsing configuration parameter socket_path in socket instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	struct sockaddr_un addr;
	if (strlen(data->socket_path) > sizeof(addr.sun_path) - 1) {
		RRR_MSG_0("Configuration parameter socket_path in socket instance %s was too long, max length is %llu bytes\n",
				config->name, (long long unsigned) sizeof(addr.sun_path) - 1);
		ret = 1;
		goto out;
	}

	// Message default topic
	if ((ret = rrr_instance_config_parse_topic_and_length (
			&data->default_topic,
			&data->default_topic_length,
			config,
			"socket_default_topic"
	)) != 0) {
		goto out;
	}

	// Receive full rrr message
	int yesno = 0;
	if (rrr_instance_config_check_yesno (&yesno, config, "socket_receive_rrr_message") == RRR_SETTING_PARSE_ERROR) {
		RRR_MSG_0 ("mysql: Could not understand argument socket_receive_rrr_message of instance '%s', please specify 'yes' or 'no'\n",
				config->name);
		ret = 1;
		goto out;
	}
	data->receive_rrr_message = (yesno == 0 || yesno == 1 ? yesno : 0);

	// Parse expected input data
	if (rrr_instance_config_setting_exists(config, "socket_input_types")) {
		if (rrr_instance_config_parse_array_tree_definition_from_config_silent_fail(&data->tree, config, "socket_input_types") != 0) {
			RRR_MSG_0("Could not parse configuration parameter socket_input_types in socket instance %s\n",
					config->name);
			ret = 1;
			goto out;
		}
	}

	// Sync byte by byte if parsing fails
	yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "socket_sync_byte_by_byte")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing udpr_sync_byte_by_byte for udpreader instance %s, please use yes or no\n",
					config->name);
			ret = 1;
			goto out;
		}
	}
	data->do_sync_byte_by_byte = yesno;

	if (data->receive_rrr_message != 0 && data->tree != NULL) {
		RRR_MSG_0("Array definition cannot be specified with socket_input_types whith socket_receive_rrr_message being 'yes' in instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}
	else if (data->receive_rrr_message == 0 && data->tree == NULL) {
		RRR_MSG_0("No data types defined in socket_input_types for instance %s and socket_receive_rrr_message was not 'yes', can't receive anything.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("socket_unlink_if_exists", do_unlink_if_exists, 0);

	// Reset any NOT_FOUND
	ret = 0;

	out:
	return ret;
}

static int socket_read_raw_data_broker_callback (struct rrr_msg_holder *entry, void *arg) {
	struct socket_data *data = arg;

	int ret = 0;

	struct rrr_msg_msg *message = NULL;

	if ((ret = rrr_array_new_message_from_collection (
			&message,
			&data->array_tmp,
			rrr_time_get_64(),
			data->default_topic,
			data->default_topic_length
	)) != 0) {
		RRR_MSG_0("Could not create array message in socket_read_raw_data_broker_callback\n");
		goto out;
	}

	RRR_DBG_2("socket instance %s created a message form array data with timestamp %llu size %llu\n",
			INSTANCE_D_NAME(data->thread_data),
			(long long unsigned int) message->timestamp,
			(unsigned long long) MSG_TOTAL_SIZE(message)
	);

	entry->message = message;
	entry->data_length = MSG_TOTAL_SIZE(message);
	message = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int socket_read_raw_data_callback (struct rrr_read_session *read_session, void *private_data, void *arg) {
	struct socket_data *data = arg;

	(void)(private_data);
	(void)(read_session);

	return rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			socket_read_raw_data_broker_callback,
			data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	);
}

struct socket_read_message_broker_callback_data {
	struct socket_data *data;
	struct rrr_msg_msg **message;
};

static int socket_read_message_broker_callback (struct rrr_msg_holder *entry, void *arg) {
	struct socket_read_message_broker_callback_data *callback_data = arg;

	int ret = 0;

	if (MSG_TOPIC_LENGTH(*(callback_data->message)) == 0 && callback_data->data->default_topic != NULL) {
		if ((ret = rrr_msg_msg_topic_set (
				callback_data->message,
				callback_data->data->default_topic,
				callback_data->data->default_topic_length
		)) != 0) {
			RRR_MSG_0("Could not set topic of message in socket_read_message_broker_callback\n");
			goto out;
		}
	}

	RRR_DBG_2("socket instance %s received a message with timestamp %llu size %llu\n",
			INSTANCE_D_NAME(callback_data->data->thread_data),
			(long long unsigned int) (*(callback_data->message))->timestamp,
			(unsigned long long) MSG_TOTAL_SIZE(*(callback_data->message))
	);

	entry->message = *(callback_data->message);
	entry->data_length = MSG_TOTAL_SIZE(*(callback_data->message));
	*(callback_data->message) = NULL;

	callback_data->data->message_count++;

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int socket_read_rrr_msg_msg_callback (struct rrr_msg_msg **message, void *private_data, void *arg) {
	struct socket_data *data = arg;

	(void)(private_data);

	struct socket_read_message_broker_callback_data callback_data = {
		data,
		message
	};

	return rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			socket_read_message_broker_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	);
}

static int socket_start (
		struct socket_data *data,
		struct rrr_read_common_get_session_target_length_from_array_tree_data *raw_callback_data
) {
	int ret = 0;

	char socket_name[64 + 1];
	snprintf(socket_name, 64, "socket for instance %s", INSTANCE_D_NAME(data->thread_data));
	socket_name[64] = '\0';

	int fd = 0;
	if (rrr_socket_unix_create_bind_and_listen(&fd, socket_name, data->socket_path, 10, 1, 0, data->do_unlink_if_exists) != 0) {
		RRR_MSG_0("Could not create socket in socket_start of instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	RRR_DBG_1("socket instance %s listening on %s\n",
			INSTANCE_D_NAME(data->thread_data), data->socket_path);

	if ((ret = rrr_socket_client_collection_new(&data->clients, INSTANCE_D_EVENTS(data->thread_data), socket_name)) != 0) {
		goto out;
	}

	if (data->receive_rrr_message) {
		rrr_socket_client_collection_event_setup (
				data->clients,
				NULL,
				NULL,
				NULL,
				4096,
				RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
				socket_read_rrr_msg_msg_callback,
				NULL,
				NULL,
				NULL,
				NULL,
				data
		);
	}
	else {
		rrr_socket_client_collection_event_setup_raw (
				data->clients,
				NULL,
				NULL,
				NULL,
				4096,
				RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
				rrr_read_common_get_session_target_length_from_array_tree,
				raw_callback_data,
				socket_read_raw_data_callback,
				data
		);
	}

	if ((ret = rrr_socket_client_collection_listen_fd_push (data->clients, fd)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void socket_stop (void *arg) {
	struct socket_data *data = arg;
	if (data->clients != NULL) {
		rrr_socket_client_collection_destroy(data->clients);
		data->clients = NULL;
	}
}

static void *thread_entry_socket (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct socket_data *data = thread_data->private_data = thread_data->private_memory;

	pthread_cleanup_push(data_cleanup, data);

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in socket instance %s\n",
				INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("Socket thread data is %p\n", thread_data);

	pthread_cleanup_push(socket_stop, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parsing failed for socket instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	struct rrr_read_common_get_session_target_length_from_array_tree_data raw_callback_data = {
			data->tree,
			&data->array_tmp,
			data->do_sync_byte_by_byte,
			0 // No max size
	};

	if (socket_start(data, &raw_callback_data) != 0) {
		RRR_MSG_0("Could not start socket in socket instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	RRR_DBG_2("socket instance %s listening on socket %s\n",
			INSTANCE_D_NAME(thread_data), data->socket_path);

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			1 * 1000 * 1000,
			rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void,
			thread
	);

	out_message:
	RRR_DBG_1 ("socket instance %s received encourage stop\n",
			INSTANCE_D_NAME(thread_data));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int socket_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;

	(void)(thread);
	(void)(amount);

	RRR_BUG("BUG: socket_event_broker_data_available called in socket module\n");

	return 0;
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_socket,
	NULL,
	NULL,
	NULL
};

struct rrr_instance_event_functions event_functions = {
	socket_event_broker_data_available
};

static const char *module_name = "socket";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->private_data = NULL;
		data->event_functions = event_functions;
}

void unload(void) {
}


