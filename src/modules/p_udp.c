/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include <src/lib/array.h>
#include <unistd.h>

#include "../lib/settings.h"
#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/ip.h"
#include "../lib/array.h"
#include "../lib/type.h"
#include "../lib/rrr_socket.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/utf8.h"
#include "../lib/read.h"
#include "../lib/poll_helper.h"
#include "../lib/map.h"
#include "../lib/stats_instance.h"
#include "../global.h"

#define RRR_UDPREADER_DEFAULT_PORT 2222

struct udp_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_fifo_buffer send_buffer;
	struct rrr_fifo_buffer inject_buffer;
	struct rrr_fifo_buffer delivery_buffer;
	unsigned int source_port;
	unsigned int target_port;
	struct rrr_ip_data ip;
	struct rrr_array definitions;
	struct rrr_read_session_collection read_sessions;
	int do_sync_byte_by_byte;
	int do_send_rrr_message;
	int do_force_target;
	int do_extract_rrr_messages;
	char *default_topic;
	char *target_host;
	ssize_t default_topic_length;
	struct rrr_map array_send_tags;
	uint64_t messages_count_read;
	uint64_t messages_count_polled;
	uint64_t read_error_count;
};

void data_cleanup(void *arg) {
	struct udp_data *data = (struct udp_data *) arg;
	rrr_fifo_buffer_invalidate(&data->send_buffer);
	rrr_fifo_buffer_invalidate(&data->inject_buffer);
	rrr_fifo_buffer_invalidate(&data->delivery_buffer);
	rrr_array_clear(&data->definitions);
	rrr_read_session_collection_clear(&data->read_sessions);
	RRR_FREE_IF_NOT_NULL(data->default_topic);
	RRR_FREE_IF_NOT_NULL(data->target_host);
	rrr_map_clear(&data->array_send_tags);
}

int data_init(struct udp_data *data, struct rrr_instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	int ret = 0;

	ret |= rrr_fifo_buffer_init_custom_free(&data->send_buffer, rrr_ip_buffer_entry_destroy_void);
	ret |= rrr_fifo_buffer_init_custom_free(&data->inject_buffer, rrr_ip_buffer_entry_destroy_void);
	ret |= rrr_fifo_buffer_init_custom_free(&data->delivery_buffer, rrr_ip_buffer_entry_destroy_void);

	if (ret != 0) {
		data_cleanup(data);
	}

	return ret;
}

struct udp_poll_delete_callback_data {
	struct udp_data *udp_data;
	int (*callback)(RRR_MODULE_POLL_CALLBACK_SIGNATURE);
	struct rrr_fifo_callback_args *poll_data;
};

static int __poll_delete_extract_msg_callback (RRR_FIFO_CALLBACK_ARGS) {
	struct udp_poll_delete_callback_data *udp_callback_data = callback_data->private_data;
//	struct udp_data *udp_data = udp_callback_data->udp_data;

	(void)(size);

	int ret = 0;

	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	ret = udp_callback_data->callback (
			udp_callback_data->poll_data,
			entry->message,
			entry->data_length
	);

	// Ownership of message pointer is handed over to callback
	entry->message = NULL;
	rrr_ip_buffer_entry_destroy(entry);

	return ret;
}

static int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct udp_data *udp_data = data->private_data;

	struct udp_poll_delete_callback_data callback_data = {
			udp_data,
			callback,
			poll_data
	};

	struct rrr_fifo_callback_args fifo_args = {
			udp_data->thread_data,
			&callback_data,
			0
	};

	return rrr_fifo_read_clear_forward (
			&udp_data->delivery_buffer,
			NULL,
			__poll_delete_extract_msg_callback,
			&fifo_args,
			wait_milliseconds
	);
}

static int __poll_extract_msg_callback (RRR_FIFO_CALLBACK_ARGS) {
	struct udp_poll_delete_callback_data *udp_callback_data = callback_data->private_data;
//	struct udp_data *udp_data = udp_callback_data->udp_data;

	(void)(size);

	int ret = 0;

	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	ret = udp_callback_data->callback (
			udp_callback_data->poll_data,
			entry->message,
			entry->data_length
	);

	return ret;
}

static int poll (RRR_MODULE_POLL_SIGNATURE) {
	struct udp_data *udp_data = data->private_data;

	struct udp_poll_delete_callback_data callback_data = {
			udp_data,
			callback,
			poll_data
	};

	struct rrr_fifo_callback_args fifo_args = {
			udp_data->thread_data,
			&callback_data,
			0
	};

	return rrr_fifo_search(&udp_data->delivery_buffer, __poll_extract_msg_callback, &fifo_args, wait_milliseconds);
}

static int poll_delete_ip (RRR_MODULE_POLL_SIGNATURE) {
	struct udp_data *udp_data = data->private_data;

	return rrr_fifo_read_clear_forward (
			&udp_data->delivery_buffer,
			NULL,
			callback,
			poll_data,
			wait_milliseconds
	);
}

int config_parse_port (struct udp_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint tmp_uint;

	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "udp_port");
	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_ERR("Could not parse udp_port for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			// Listening not being done
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Error while parsing udp_port setting for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	data->source_port = tmp_uint;

	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "udp_target_port");
	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_ERR("Could not parse udp_remote_port for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			// No remote port specified
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Error while parsing udp_remote_port setting for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	data->target_port = tmp_uint;

	out:
	return ret;
}

int parse_config (struct udp_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	// Parse listen port
	if ((ret = config_parse_port (data, config)) != 0) {
		goto out;
	}

	// Default target host
	if ((ret = rrr_settings_get_string_noconvert_silent(&data->target_host, config->settings, "udp_target_host")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing configuration parameter udp_target_host in udp instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}

	if (data->target_port != 0 && (data->target_host == NULL || *(data->target_host) == '\0')) {
		RRR_MSG_ERR("udp_target_port was set but udp_target_host was not, both of them must be either set or left unset in udp instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (data->target_port == 0 && (data->target_host != NULL && *(data->target_host) != '\0')) {
		RRR_MSG_ERR("udp_target_host was set but udp_target_port was not, both of them must be either set or left unset in udp instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	// Parse expected input data
	if ((ret = rrr_instance_config_parse_array_definition_from_config_silent_fail(&data->definitions, config, "udp_input_types")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Could not parse command line argument udp_input_types in udp\n");
			ret = 1;
			goto out;
		}
	}

	if (data->definitions.node_count > 0 && data->source_port == 0) {
		RRR_MSG_ERR("udp_input_types was set but udp_port was not, this is an invalid configuraton in udp instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else if (data->definitions.node_count == 0) {
		// Listening disabled
	}

	// Message default topic
	if ((ret = rrr_settings_get_string_noconvert_silent(&data->default_topic, config->settings, "udp_default_topic")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing configuration parameter udp_default_topic in udp instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		if (rrr_utf8_validate(data->default_topic, strlen(data->default_topic)) != 0) {
			RRR_MSG_ERR("udp_default_topic for instance %s was not valid UTF-8\n", config->name);
			ret = 1;
			goto out;
		}
		data->default_topic_length = strlen(data->default_topic);
	}

	// Sync byte by byte if parsing fails
	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udp_sync_byte_by_byte")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udp_sync_byte_by_byte for udp instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		data->do_sync_byte_by_byte = yesno;
	}

	// Send complete RRR message
	yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udp_send_rrr_message")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udp_send_rrr_message for udp instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		data->do_send_rrr_message = yesno;
	}

	// Force target
	yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udp_force_target")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udp_force_target for udp instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		data->do_force_target = yesno;
	}

	if (data->do_force_target != 0 && data->target_port == 0) {
		RRR_MSG_ERR("udp_force_target was set to yes but no target was specified in udp_target_host and udp_target_port in udp instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}

	// Extract RRR messages from arrays
	yesno = 0;
	if ((ret = rrr_instance_config_check_yesno(&yesno, config, "udp_extract_rrr_messages")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Error while parsing udp_extract_rrr_messages for udp instance %s, please use yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
	}
	else {
		data->do_extract_rrr_messages = yesno;
	}

	// Array columns to send if we receive array messages from other modules
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->array_send_tags, config, "udp_array_send_tags");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_ERR("Error while parsing udp_array_send_tags of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i blob write columns specified for udp instance %s\n", RRR_MAP_COUNT(&data->array_send_tags), config->name);

	out:
	return ret;
}

struct udp_read_callback_data {
	struct udp_data *udp_data;
	const struct rrr_ip_buffer_entry *entry_orig;
};

int read_data_receive_message_callback (struct rrr_message *message, void *arg) {
	struct udp_read_callback_data *callback_data = arg;
	struct udp_data *data = callback_data->udp_data;

	int ret = 0;

	struct rrr_ip_buffer_entry *new_entry = NULL;

	if (rrr_ip_buffer_entry_new (
			&new_entry,
			MSG_TOTAL_SIZE(message),
			&callback_data->entry_orig->addr,
			callback_data->entry_orig->addr_len,
			message
	) != 0) {
		RRR_MSG_ERR("Could not create new ip buffer entry in read_data_receive_message_callback\n");
		ret = 1;
		goto out;
	}

	RRR_DBG_3("udp instance %s created a message with timestamp %llu size %lu\n",
			INSTANCE_D_NAME(data->thread_data), (long long unsigned int) message->timestamp_from, (long unsigned int) sizeof(*message));

	// Now managed by ip buffer entry
	message = NULL;

	rrr_fifo_buffer_write(&data->delivery_buffer, (char*)new_entry, sizeof(*new_entry));

	// Now managed by fifo buffer
	new_entry = NULL;

	data->messages_count_read++;

	out:
	if (new_entry != NULL) {
		rrr_ip_buffer_entry_destroy(new_entry);
	}
	if (message != NULL) {
		free(message);
	}
	return ret;
}

int read_data_receive_extract_messages_callback (const struct rrr_array *array, void *arg) {
	struct udp_read_callback_data *callback_data = arg;
	struct udp_data *data = callback_data->udp_data;

	int ret = 0;

	int found_messages = 0;
	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (RRR_TYPE_IS_MSG(node->definition->type)) {
			const struct rrr_message *message = (struct rrr_message *) node->data;
			struct rrr_message *message_new = rrr_message_duplicate(message);
			if (message_new == NULL) {
				RRR_MSG_ERR("Could not allocate new message in udp read_data_receive_array_callback\n");
				ret = 1;
				goto out;
			}

			if ((ret = read_data_receive_message_callback(message_new, arg)) != 0) {
				goto out;
			}

			found_messages++;
		}
	RRR_LL_ITERATE_END();

	RRR_DBG_3("udp instance %s extracted %i RRR messages from an array\n",
			INSTANCE_D_NAME(data->thread_data), found_messages);

	if (found_messages == 0) {
		RRR_MSG_ERR("No RRR message found in array definition in udp instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int read_raw_data_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct udp_data *data = arg;
	int ret = 0;

	struct udp_read_callback_data callback_data = {
			data, entry
	};

	if (data->do_extract_rrr_messages) {
		ret = rrr_array_parse_from_buffer_with_callback (
			entry->message,
			entry->data_length,
			&data->definitions,
			read_data_receive_extract_messages_callback,
			&callback_data
		);
	}
	else {
		ret = rrr_array_new_message_from_buffer_with_callback (
			entry->message,
			entry->data_length,
			data->default_topic,
			data->default_topic_length,
			&data->definitions,
			read_data_receive_message_callback,
			&callback_data
		);
	}

	if (ret != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			RRR_MSG_ERR("Could not create message in udp instance %s read_data_callback, soft error probably caused by invalid input data\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 0;
		}
		else {
			RRR_MSG_ERR("Could not create message in udp instance %s read_data_callback\n",
					INSTANCE_D_NAME(data->thread_data));
		}
		goto out;
	}

	out:
	rrr_ip_buffer_entry_destroy_void(entry);
	return ret;
}

int inject_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	RRR_DBG_4("udp inject callback size %lu\n", size);
	struct udp_data *udp_data = poll_data->private_data;
	return read_raw_data_callback((struct rrr_ip_buffer_entry *) data, udp_data);
}

int read_data(struct udp_data *data) {
	int ret = 0;

	for (int i = 0; i < 10; i++) {
		if ((ret = rrr_ip_receive_array (
			&data->read_sessions,
			data->ip.fd,
			RRR_READ_F_NO_SLEEPING,
			&data->definitions,
			data->do_sync_byte_by_byte,
			read_raw_data_callback,
			data,
			NULL
		)) != 0) {
			if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
				RRR_MSG_ERR("Received invalid data in ip_receive_packets in udp instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				// Don't allow invalid data to stop processing
				ret = 0;
				data->read_error_count++;
			}
			else {
				RRR_MSG_ERR("Error from ip_receive_packets in udp instance %s return was %i\n",
						INSTANCE_D_NAME(data->thread_data), ret);
				ret = 1;
				goto out;
			}
		}
	}

	struct rrr_fifo_callback_args callback_data = {NULL, data, 0};
	if ((ret = rrr_fifo_read_clear_forward(&data->inject_buffer, NULL, inject_callback, &callback_data, 0)) != 0) {
		RRR_MSG_ERR("Error from inject buffer in udp instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	return ret;
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	struct udp_data *data = thread_data->private_data;
	RRR_DBG_2("udp: writing data from inject function\n");

	if (data->inject_buffer.invalid) {
		return 1;
	}

	rrr_fifo_buffer_write(&data->inject_buffer, (char *) message, sizeof(*message));

	return 0;
}

static int poll_callback_final (struct udp_data *data, struct rrr_ip_buffer_entry *entry) {
	data->messages_count_polled++;
	rrr_fifo_buffer_write(&data->send_buffer, (char *) entry, sizeof(*entry));
	return 0;
}

static int poll_callback (struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct udp_data *private_data = thread_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;
	struct rrr_ip_buffer_entry *entry = NULL;

	RRR_DBG_3 ("udp instance %s: Result from buffer: timestamp %" PRIu64 " measurement %" PRIu64 " size %lu\n",
			INSTANCE_D_NAME(thread_data), message->timestamp_from, message->data_numeric, size);

	if (rrr_ip_buffer_entry_new(&entry, MSG_TOTAL_SIZE(message), NULL, 0, message) != 0) {
		RRR_MSG_ERR("Could not create ip buffer entry in udp poll_callback\n");
		free(data);
		return 1;
	}

	return poll_callback_final(private_data, entry);
}

static int poll_callback_ip (struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct udp_data *private_data = thread_data->private_data;
	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	RRR_DBG_3 ("udp instance %s: Result from buffer ip: size %lu\n",
			INSTANCE_D_NAME(thread_data), size);

	return poll_callback_final(private_data, entry);
}

static int input_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_instance_thread_data *thread_data = poll_data->source;
	struct udp_data *udp_data = poll_data->private_data;
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct rrr_ip_buffer_entry *entry = (struct rrr_ip_buffer_entry *) data;

	char *tmp_data = NULL; // Freed upon function return

	const void *send_data = NULL; // Just a pointer to data managed elsewhere, not freed
	ssize_t send_size = 0;

	struct rrr_array array_tmp = {0};
	struct rrr_message *message = entry->message;

	// We modify the data in the buffer here, no need to copy as the memory is always
	// freed after this function.
	if (udp_data->do_send_rrr_message != 0) {
		if (entry->data_length < (long int) sizeof(*message) - 1) {
			RRR_MSG_ERR("udp instance %s had send_rrr_message set but received a message which was too short (%li<%li), dropping it\n",
					INSTANCE_D_NAME(thread_data), entry->data_length, (long int) sizeof(*message));
			ret = 0; // Non-critical error
			goto out;
		}

		ssize_t final_size = MSG_TOTAL_SIZE(message);

		if (entry->data_length != final_size) {
			RRR_BUG("message size mismatch in udp input_callback %li vs %li\n", entry->data_length, final_size);
		}

		RRR_DBG_3 ("udp instance %s sends packet with rrr message timestamp from %" PRIu64 " size %li\n",
				INSTANCE_D_NAME(thread_data), message->timestamp_from, final_size);

		rrr_message_prepare_for_network(message);

		rrr_socket_msg_populate_head (
				(struct rrr_socket_msg *) message,
				RRR_SOCKET_MSG_TYPE_RRR_MESSAGE,
				final_size,
				0
		);

		rrr_socket_msg_checksum_and_to_network_endian (
				(struct rrr_socket_msg *) message
		);

		send_data = message;
		send_size = final_size;
	}
	else {
		if (!MSG_IS_ARRAY(message)) {
			if (RRR_MAP_COUNT(&udp_data->array_send_tags) > 0) {
				RRR_MSG_ERR("udp instance %s received a non-array message while setting udp_array_send_tags was defined, dropping it\n",
						INSTANCE_D_NAME(thread_data));
				ret = 0; // Non-critical error
				goto out;
			}

			send_data = message->data;
			send_size = MSG_DATA_LENGTH(message);

			if (send_size == 0) {
				ret = 0; // Nothing to send
				goto out;
			}

			RRR_DBG_3 ("udp instance %s sends packet with raw data from message with timestamp from %" PRIu64 " %li bytes\n",
					INSTANCE_D_NAME(thread_data), message->timestamp_from, send_size);
		}
		else {
			int tag_count = RRR_MAP_COUNT(&udp_data->array_send_tags);

			if (rrr_array_message_to_collection(&array_tmp, message) != 0) {
				RRR_MSG_ERR("Could not convert array message to collection in udp instance %s\n", INSTANCE_D_NAME(thread_data));
				ret = 1; // Probably bug in some other module or with array parsing
				goto out;
			}

			RRR_FREE_IF_NOT_NULL(tmp_data);
			ssize_t target_size = 0;
			int found_tags = 0;
			struct rrr_map *tag_map = (tag_count > 0 ? &udp_data->array_send_tags : NULL);
			if (rrr_array_selected_tags_export (
					&tmp_data,
					&target_size,
					&found_tags,
					&array_tmp,
					tag_map
			) != 0) {
				RRR_MSG_ERR("Error while converting array to raw in udp instance %s\n", INSTANCE_D_NAME(thread_data));
				ret = 1; // Probably bug in some other module or with array parsing
				goto out;
			}

			if (tag_count != 0 && found_tags != tag_count) {
				RRR_MSG_ERR("Array message to send in udp instance %s did not contain all tags specified in configuration, dropping it (%i tags missing)\n",
						INSTANCE_D_NAME(thread_data), tag_count - found_tags);
				ret = 0; // Non-critical
				goto out;
			}

			RRR_DBG_3 ("udp instance %s sends packet with array data from message with timestamp from %" PRIu64 " %i array tags size %li\n",
					INSTANCE_D_NAME(thread_data), message->timestamp_from, found_tags, target_size);

			send_data = tmp_data;
			send_size = target_size;
		}
	}

	if ((udp_data->target_port != 0 && (udp_data->target_host == NULL || *(udp_data->target_host) == '\0')) ||
	    (udp_data->target_port == 0 && (udp_data->target_host != NULL && *(udp_data->target_host) != '\0'))
	) {
		RRR_BUG("Invalid target_port/target_host configuration in udp input_callback\n");
	}

	// Configuration validation should produce an error if do_force_target is set
	// but no target_port/target_host
	if (udp_data->do_force_target == 1 || entry->addr_len == 0) {
		if (udp_data->target_port == 0) {
			RRR_MSG_ERR("Warning: A message from a sender in udp instance %s had no address information and we have no default remote host set, dropping it\n", INSTANCE_D_NAME(thread_data));
			goto out;
		}
		ret = rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
			&udp_data->ip,
			udp_data->target_port,
			udp_data->target_host,
			(void *) send_data, // Cast away const OK
			send_size
		);
	}
	else {
		ret = rrr_ip_send (
			udp_data->ip.fd,
			&entry->addr,
			entry->addr_len,
			(void *) send_data, // Cast away const OK
			send_size
		);
	}

	if (ret != 0) {
		RRR_MSG_ERR("Could not send data in udp instance %s", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(tmp_data);
	rrr_array_clear(&array_tmp);
	return ret | RRR_FIFO_SEARCH_FREE;
}

static void *thread_entry_udp (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct udp_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;
	struct poll_collection poll_ip;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in udp instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("UDP thread data is %p\n", thread_data);

	poll_collection_init(&poll_ip);
	poll_collection_init(&poll);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(poll_collection_clear_void, &poll_ip);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	// Don't set running here, wait until listening has started

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Configuration parsing failed for udp instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	poll_add_from_thread_senders_ignore_error(&poll, thread_data, RRR_POLL_POLL_DELETE|RRR_POLL_NO_SENDERS_OK);
	poll_add_from_thread_senders_ignore_error(&poll_ip, thread_data, RRR_POLL_POLL_DELETE_IP|RRR_POLL_NO_SENDERS_OK);
	poll_remove_senders_also_in(&poll, &poll_ip);

	int has_senders = (poll_collection_count(&poll) + poll_collection_count(&poll_ip) > 0 ? 1 : 0);

	if (has_senders == 0 && RRR_LL_COUNT(&data->definitions) == 0) {
		RRR_MSG_ERR("Error: udp instance %s has no senders defined and also has no array definition. Cannot do anything with this configuration.\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (data->source_port == 0) {
		if (rrr_ip_network_start_udp_ipv4_nobind(&data->ip) != 0) {
			RRR_MSG_ERR("Could not initialize network in udp instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		RRR_DBG_1("udp instance %s started, not listening on any port\n", INSTANCE_D_NAME(thread_data));
	}
	else {
		data->ip.port = data->source_port;
		if (rrr_ip_network_start_udp_ipv4(&data->ip) != 0) {
			RRR_MSG_ERR("Could not initialize network in udp instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
		RRR_DBG_1("udp instance %s listening on and/or sending from port %d\n", INSTANCE_D_NAME(thread_data), data->source_port);
	}

	pthread_cleanup_push(rrr_ip_network_cleanup, &data->ip);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	rrr_fifo_buffer_set_do_ratelimit(&data->delivery_buffer, 1);

	uint64_t prev_read_error_count = 0;
	uint64_t prev_read_count = 0;
	uint64_t prev_polled_count = 0;

	uint64_t next_stats_time = 0;
	unsigned int tick = 0;
	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_update_watchdog_time(thread_data->thread);

		if (has_senders != 0) {
			if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 0) != 0) {
				break;
			}
			if (poll_do_poll_delete_ip_simple (&poll_ip, thread_data, poll_callback_ip, 0) != 0) {
				break;
			}
		}

		struct rrr_fifo_callback_args callback_args = {
			thread_data, data, 0
		};

		if (rrr_fifo_read_clear_forward(&data->send_buffer, NULL, input_callback, &callback_args, 0) != 0) {
			RRR_MSG_ERR("Error while iterating input buffer in udp instance %s\n", INSTANCE_D_NAME(thread_data));
			break;
		}

		if (data->source_port > 0 && RRR_LL_COUNT(&data->definitions) > 0) {
			if (read_data(data) != 0) {
				break;
			}
		}

		// Sleep if nothing happened
		if (prev_read_count == data->messages_count_read &&
			prev_polled_count == data->messages_count_polled &&
			prev_read_error_count == data->read_error_count
		) {
			usleep(25000);
		}

		uint64_t time_now = rrr_time_get_64();

		if (stats != NULL && time_now > next_stats_time) {
			rrr_stats_instance_update_rate(stats, 1, "read_error_count", data->read_error_count);
			rrr_stats_instance_update_rate(stats, 2, "read_count", data->messages_count_read);
			rrr_stats_instance_update_rate(stats, 3, "polled_count", data->messages_count_polled);
			rrr_stats_instance_post_unsigned_base10_text (
					stats,
					"delivery_buffer_count",
					0,
					rrr_fifo_buffer_get_entry_count(&data->delivery_buffer)
			);
			tick = 0;
			data->read_error_count = 0;
			data->messages_count_read = 0;
			data->messages_count_polled = 0;
			next_stats_time = time_now + 1000000;
		}

		prev_read_error_count = data->read_error_count;
		prev_read_count = data->messages_count_read;
		prev_polled_count = data->messages_count_polled;

		tick++;
	}

	pthread_cleanup_pop(1);

	out_message:

	RRR_DBG_1 ("udp instance %s stopping\n", thread_data->init_data.instance_config->name);
	// Set running in case we failed before getting around to do that
	if (!rrr_thread_check_state(thread, RRR_THREAD_STATE_RUNNING)) {
		rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);
	}
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct udp_data data;
	int ret = 0;
	if ((ret = data_init(&data, NULL)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_udp,
	NULL,
	poll,
	NULL,
	poll_delete,
	poll_delete_ip,
	test_config,
	inject,
	NULL
};

static const char *module_name = "udp";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_FLEXIBLE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
		data->start_priority = RRR_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
}


