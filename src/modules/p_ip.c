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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/rrr_strerror.h"
#include "../lib/settings.h"
#include "../lib/array.h"
#include "../lib/array_tree.h"
#include "../lib/type.h"
#include "../lib/socket/rrr_socket.h"
#include "../lib/instances.h"
#include "../lib/instance_config.h"
#include "../lib/read.h"
#include "../lib/poll_helper.h"
#include "../lib/map.h"
#include "../lib/message_broker.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/utf8.h"
#include "../lib/util/rrr_endian.h"
#include "../lib/util/posix.h"
#include "../lib/ip/ip.h"
#include "../lib/ip/ip_util.h"
#include "../lib/socket/rrr_socket_common.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/ip/ip_accept_data.h"

#define IP_DEFAULT_PORT				2222
#define IP_DEFAULT_PROTOCOL			RRR_IP_UDP
#define IP_SEND_TIME_LIMIT_MS		1000
#define IP_DEFAULT_MAX_MESSAGE_SIZE	4096

enum ip_action {
	IP_ACTION_RETRY,
	IP_ACTION_DROP,
	IP_ACTION_RETURN
};

struct ip_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_msg_msg_holder_collection send_buffer;
//	struct rrr_msg_msg_holder_collection delivery_buffer;
	unsigned int source_udp_port;
	unsigned int source_tcp_port;
	struct rrr_ip_data ip_udp;
	struct rrr_ip_data ip_tcp_listen;
	int ip_tcp_default_target_fd;
	struct rrr_array_tree *definitions;
	struct rrr_read_session_collection read_sessions_udp;
	struct rrr_read_session_collection read_sessions_tcp;
	int do_sync_byte_by_byte;
	int do_send_rrr_msg_msg;
	int do_force_target;
	int do_extract_rrr_msg_msgs;
	int do_ordered_send;
	int do_persistent_connections;
	int do_multiple_per_connection;
	char *timeout_action_str;
	enum ip_action timeout_action;
	rrr_setting_uint message_send_timeout_s;
	rrr_setting_uint message_max_size;
	char *default_topic;
	char *target_host;
	unsigned int target_port;
	int target_protocol;
	ssize_t default_topic_length;
	struct rrr_map array_send_tags;
	uint64_t messages_count_read;
	uint64_t messages_count_polled;
	uint64_t read_error_count;
};

static void ip_data_cleanup(void *arg) {
	struct ip_data *data = (struct ip_data *) arg;
	rrr_msg_msg_holder_collection_clear(&data->send_buffer);
	if (data->definitions != NULL) {
		rrr_array_tree_destroy(data->definitions);
	}
	rrr_read_session_collection_clear(&data->read_sessions_udp);
	rrr_read_session_collection_clear(&data->read_sessions_tcp);
	RRR_FREE_IF_NOT_NULL(data->default_topic);
	RRR_FREE_IF_NOT_NULL(data->target_host);
	RRR_FREE_IF_NOT_NULL(data->timeout_action_str);
	rrr_map_clear(&data->array_send_tags);
}

static int ip_data_init(struct ip_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

static int ip_config_parse_port (struct ip_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	rrr_setting_uint tmp_uint;

	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "ip_udp_port");
	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_0("Could not parse ip_udp_port for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			// Listening not being done
		}
		else {
			RRR_MSG_0("Error while parsing ip_udp_port setting for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	data->source_udp_port = tmp_uint;

	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "ip_tcp_port");
	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_0("Could not parse ip_tcp_port for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			// Listening not being done
		}
		else {
			RRR_MSG_0("Error while parsing ip_tcp_port setting for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	data->source_tcp_port = tmp_uint;

	ret = rrr_instance_config_read_port_number (&tmp_uint, config, "ip_target_port");
	if (ret != 0) {
		if (ret == RRR_SETTING_PARSE_ERROR) {
			RRR_MSG_0("Could not parse ip_remote_port for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		else if (ret == RRR_SETTING_NOT_FOUND) {
			// No remote port specified
		}
		else {
			RRR_MSG_0("Error while parsing ip_remote_port setting for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	data->target_port = tmp_uint;

	// Reset any NOT_FOUND
	ret = 0;

	out:
	return ret;
}

static int ip_parse_config (struct ip_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;
	char *protocol = NULL;

	// Parse listen and target port
	if ((ret = ip_config_parse_port (data, config)) != 0) {
		goto out;
	}

	// Default target protocol
	if ((ret = rrr_settings_get_string_noconvert_silent(&protocol, config->settings, "ip_target_protocol")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing configuration parameter ip_target_protocol in ip instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		data->target_protocol = IP_DEFAULT_PROTOCOL;
	}
	else {
		if (rrr_posix_strcasecmp(protocol, "udp") == 0) {
			data->target_protocol = RRR_IP_UDP;
		}
		else if (rrr_posix_strcasecmp(protocol, "tcp") == 0) {
			data->target_protocol = RRR_IP_TCP;
		}
		else {
			RRR_MSG_0("Unknown protocol '%s' specified in ip_target_protocol in ip instance %s. Must be tcp or udp.\n",
					protocol, config->name);
			ret = 1;
			goto out;
		}
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ip_target_host", target_host);

	if (data->target_port != 0 && (data->target_host == NULL || *(data->target_host) == '\0')) {
		RRR_MSG_0("ip_target_port was set but ip_target_host was not, both of them must be either set or left unset in ip instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	if (data->target_port == 0 && (data->target_host != NULL && *(data->target_host) != '\0')) {
		RRR_MSG_0("ip_target_host was set but ip_target_port was not, both of them must be either set or left unset in ip instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	// Parse expected input data
	if ((ret = rrr_instance_config_parse_array_tree_definition_from_config_silent_fail(
			&data->definitions,
			config,
			"ip_input_types"
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not parse command line argument ip_input_types in udp\n");
			ret = 1;
			goto out;
		}
	}

	if (data->definitions != NULL && data->source_udp_port == 0 && data->source_tcp_port == 0) {
		RRR_MSG_0("ip_input_types was set but ip_port was not, this is an invalid configuraton in ip instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else if (data->definitions == NULL) {
		// Listening disabled
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ip_default_topic", default_topic);

	if (data->default_topic != NULL) {
		data->default_topic_length = strlen(data->default_topic);
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_sync_byte_by_byte", do_sync_byte_by_byte, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_send_rrr_msg_msg", do_send_rrr_msg_msg, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_force_target", do_force_target, 0);

	if (data->do_force_target == 1 && data->target_port == 0) {
		RRR_MSG_0("ip_force_target was set to yes but no target was specified in ip_target_host and ip_target_port in ip instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_extract_rrr_msg_msgs", do_extract_rrr_msg_msgs, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_preserve_order", do_ordered_send, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_persistent_connections", do_persistent_connections, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_send_multiple_per_connection", do_multiple_per_connection, 0);

	if (	RRR_INSTANCE_CONFIG_EXISTS("ip_send_multiple_per_connection") &&
			data->do_multiple_per_connection == 0 &&
			data->do_persistent_connections != 0
	) {
		RRR_MSG_0("ip_send_multiple_per_connection is explicitly set to 'no' while ip_persistent_connections is set to 'yes' in ip instance %s, this is a configuration error.\n",
				config->name);
		ret = 1;
		goto out;
	}

	// Array columns to send if we receive array messages from other modules
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->array_send_tags, config, "ip_array_send_tags");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing ip_array_send_tags of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i array tags specified for ip instance %s to send\n", RRR_MAP_COUNT(&data->array_send_tags), config->name);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_send_timeout", message_send_timeout_s, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ip_timeout_action", timeout_action_str);

	// Default action
	data->timeout_action = IP_ACTION_RETRY;

	if (data->timeout_action_str != NULL) {
		if (rrr_posix_strcasecmp(data->timeout_action_str, "retry") == 0) {
			data->timeout_action = IP_ACTION_RETRY;
		}
		else if (rrr_posix_strcasecmp(data->timeout_action_str, "drop") == 0) {
			data->timeout_action = IP_ACTION_DROP;
		}
		else if (rrr_posix_strcasecmp(data->timeout_action_str, "return") == 0) {
			data->timeout_action = IP_ACTION_RETURN;
		}
		else {
			RRR_MSG_0("Invalid value '%s' for parameter ip_timeout_action in instance %s, must be retry, drop or return\n",
					data->timeout_action_str, config->name);
			ret = 1;
			goto out;
		}
	}

	// Just to make things look nice in error messages
	if (data->timeout_action_str != NULL) {
		rrr_utf8_strtoupper(data->timeout_action_str);
	}

	if (data->message_send_timeout_s != 0 && data->timeout_action == IP_ACTION_RETRY) {
		RRR_MSG_0("Parameter ip_send_timeout in instance %s was >0 while ip_timeout_action was 'retry'. This does not make sense and is a configuration error.\n",
				config->name);
		ret = 1;
		goto out;
	}

	if (data->message_send_timeout_s == 0 && data->timeout_action != IP_ACTION_RETRY) {
		RRR_MSG_0("Parameter ip_send_timeout in instance %s was 0 while ip_timeout_action was 'drop' or 'return'. This does not make sense, a timeout must be set.\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_receive_message_max", message_max_size, IP_DEFAULT_MAX_MESSAGE_SIZE);

	// Clear any NOT_FOUND
	ret = 0;

	out:
	RRR_FREE_IF_NOT_NULL(protocol);
	return ret;
}

/*
struct ip_read_callback_data {
	struct ip_data *ip_data;
	const struct rrr_msg_msg_holder *entry_orig;
};
*/

static int ip_read_receive_message (
		struct ip_data *data,
		const struct rrr_msg_holder *entry_orig,
		struct rrr_msg_msg *message
) {
	int ret = 0;

	struct rrr_msg_holder *new_entry = NULL;

	if (rrr_msg_holder_new (
			&new_entry,
			MSG_TOTAL_SIZE(message),
			(struct sockaddr *) &entry_orig->addr,
			entry_orig->addr_len,
			entry_orig->protocol,
			message
	) != 0) {
		RRR_MSG_0("Could not create new ip buffer entry in read_data_receive_message_callback\n");
		ret = 1;
		goto out;
	}

	rrr_msg_holder_lock(new_entry);

	RRR_DBG_3("ip instance %s created a message with timestamp %llu size %lu\n",
			INSTANCE_D_NAME(data->thread_data), (long long unsigned int) message->timestamp, (long unsigned int) sizeof(*message));

	// Now managed by ip buffer entry
	message = NULL;

	// Unsafe is ok, we are in context. Must also use delayed write
	// as write lock is already held on the buffer.

	if ((ret = rrr_message_broker_incref_and_write_entry_delayed_unsafe_no_unlock (
			INSTANCE_D_BROKER(data->thread_data),
			INSTANCE_D_HANDLE(data->thread_data),
			new_entry
	)) != 0) {
		RRR_MSG_0("Could not write message to output buffer in ip instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	data->messages_count_read++;

	out:
	rrr_msg_holder_decref_while_locked_and_unlock(new_entry);
	if (message != NULL) {
		free(message);
	}
	return ret;
}

static int ip_read_data_receive_extract_messages (
		struct ip_data *data,
		const struct rrr_msg_holder *entry_orig,
		const struct rrr_array *array
) {
	int ret = 0;

	int found_messages = 0;
	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (RRR_TYPE_IS_MSG(node->definition->type)) {
			const struct rrr_msg_msg *message = (struct rrr_msg_msg *) node->data;
			struct rrr_msg_msg *message_new = rrr_msg_msg_duplicate(message);
			if (message_new == NULL) {
				RRR_MSG_0("Could not allocate new message in ip read_data_receive_array_callback\n");
				ret = 1;
				goto out;
			}

			// Guarantees to free message also upon errors
			if ((ret = ip_read_receive_message(data, entry_orig, message_new)) != 0) {
				goto out;
			}

			found_messages++;
		}
	RRR_LL_ITERATE_END();

	RRR_DBG_3("ip instance %s extracted %i RRR messages from an array\n",
			INSTANCE_D_NAME(data->thread_data), found_messages);

	if (found_messages == 0) {
		RRR_MSG_0("No RRR message found in array definition in ip instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct ip_read_array_callback_data {
	struct rrr_msg_holder *template_entry;
	struct ip_data *data;
	int handle_soft_error;
	int return_value_from_array;
	int fd;
	struct rrr_read_session_collection *read_sessions;
	int loops;
};

static int __rrr_ip_receive_array_tree_callback (
		struct rrr_read_session *read_session,
		struct rrr_array *array_final,
		void *arg
) {
	struct ip_read_array_callback_data *callback_data = arg;
	struct ip_data *data = callback_data->data;

	int ret = 0;

	if (read_session->read_complete == 0) {
		RRR_BUG("Read complete was 0 in __ip_receive_packets_callback\n");
	}

	int protocol = 0;

	switch (read_session->socket_options) {
		case SOCK_DGRAM:
			protocol = RRR_IP_UDP;
			break;
		case SOCK_STREAM:
			protocol = RRR_IP_TCP;
			break;
		default:
			RRR_MSG_0("Unknown SO_TYPE %i in __ip_receive_callback\n", read_session->socket_options);
			ret = 1;
			goto out;
	}

	RRR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);

	rrr_msg_holder_set_unlocked (
			callback_data->template_entry,
			NULL,
			0,
			(const struct sockaddr *) &read_session->src_addr,
			read_session->src_addr_len,
			protocol
	);

	if (data->do_extract_rrr_msg_msgs) {
		if ((ret = ip_read_data_receive_extract_messages (
				data,
				callback_data->template_entry,
				array_final
		)) != 0) {
			goto out;
		}
	}
	else {
		struct rrr_msg_msg *message_new = NULL;

		if ((ret = rrr_array_new_message_from_collection (
				&message_new,
				array_final,
				rrr_time_get_64(),
				data->default_topic,
				data->default_topic_length
		)) != 0) {
			goto out;
		}

		// Guarantees to free message also upon errors
		if ((ret = ip_read_receive_message(data, callback_data->template_entry, message_new)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int ip_read_array_intermediate (struct rrr_msg_holder *entry, void *arg) {
	struct ip_read_array_callback_data *callback_data = arg;
	struct ip_data *data = callback_data->data;

	int ret = RRR_MESSAGE_BROKER_OK;

	// Used only to store address information, always dropped after this callback
	callback_data->template_entry = entry;

	struct rrr_array array_tmp = {0};

	if ((ret = rrr_socket_common_receive_array_tree (
			callback_data->read_sessions,
			callback_data->fd,
			RRR_READ_F_NO_SLEEPING,
			RRR_SOCKET_READ_METHOD_RECVFROM,
			&array_tmp,
			data->definitions,
			data->do_sync_byte_by_byte,
			data->message_max_size,
			__rrr_ip_receive_array_tree_callback,
			callback_data
	)) != 0) {
		if (ret == RRR_ARRAY_SOFT_ERROR) {
			if (callback_data->handle_soft_error) {
				// Caller handles return value
				callback_data->return_value_from_array = ret;
				ret = RRR_MESSAGE_BROKER_OK;
				goto out_no_loop;
			}
			else {
				RRR_MSG_0("Received invalid data in ip instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				// Don't allow invalid data to stop processing
				ret = RRR_MESSAGE_BROKER_OK;
				data->read_error_count++;
			}
		}
		else {
			RRR_MSG_0("Error from rrr_ip_receive_array in ip_read_array_intermediate in ip instance %s return was %i\n",
					INSTANCE_D_NAME(data->thread_data), ret);
			ret = RRR_MESSAGE_BROKER_ERR;
			goto out;
		}
	}

	out:
		if (--(callback_data->loops) > 0 && ret == 0) {
			ret = RRR_MESSAGE_BROKER_AGAIN;
		}

	out_no_loop:
		if (ret != RRR_MESSAGE_BROKER_ERR) {
			// Always destroy, entry is never used by callbacks except for as reference
			ret |= RRR_MESSAGE_BROKER_DROP;
		}

		callback_data->template_entry = NULL;

		rrr_msg_holder_unlock(entry);
		rrr_array_clear(&array_tmp);
		return ret;
}

static int ip_read_loop (
		struct ip_data *data,
		int handle_soft_error,
		int fd,
		struct rrr_read_session_collection *read_sessions
) {
	int ret = 0;

	struct ip_read_array_callback_data callback_data = {
			NULL, // Set in first callback
			data,
			handle_soft_error,
			0,
			fd,
			read_sessions,
			4
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER(data->thread_data),
			INSTANCE_D_HANDLE(data->thread_data),
			NULL,
			0,
			0,
			ip_read_array_intermediate,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error while writing entries to broker while reading in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (ret == 0 && handle_soft_error) {
		ret = callback_data.return_value_from_array;
	}

	out:
	return ret;
}

static int ip_tcp_read_data (
		struct ip_data *data,
		struct rrr_ip_accept_data_collection *accept_data_collection
) {
	int ret = 0;
	if (data->source_tcp_port == 0) {
		goto out;
	}

	struct rrr_ip_accept_data *accept_data = NULL;

	if (rrr_ip_accept (
			&accept_data,
			&data->ip_tcp_listen,
			"ip",
			0
	) != 0) {
		RRR_MSG_0("Error while accepting TCP connection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	if (accept_data != NULL) {
		RRR_LL_APPEND(accept_data_collection, accept_data);
		accept_data = NULL;
	}

	RRR_LL_ITERATE_BEGIN(accept_data_collection, struct rrr_ip_accept_data);
		if ((ret = ip_read_loop (data, 1, node->ip_data.fd, &data->read_sessions_tcp)) != 0) {
			if (ret == RRR_SOCKET_SOFT_ERROR) {
				RRR_DBG_1("Closing tcp connection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
				RRR_LL_ITERATE_SET_DESTROY();
				ret = 0;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(accept_data_collection, 0; rrr_ip_accept_data_close_and_destroy(node));

	out:
	return ret;
}

static int ip_udp_read_data(struct ip_data *data) {
	int ret = 0;

	if (data->source_udp_port > 0) {
		if ((ret = ip_read_loop (data, 0, data->ip_udp.fd, &data->read_sessions_udp)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int poll_callback_ip (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct ip_data *data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_3 ("ip instance %s: Result from buffer timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	rrr_msg_holder_incref_while_locked(entry);

	entry->send_time = 0;
	RRR_LL_APPEND(&data->send_buffer, entry);

	rrr_msg_holder_unlock(entry);

	return 0;
}

static int ip_send_message_tcp (
		struct ip_data *ip_data,
		struct rrr_ip_accept_data *accept_data,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	int ret = 0;

	if (accept_data->custom_data != 0) {
		ret = RRR_SOCKET_SOFT_ERROR;
		goto out;
	}

	int err;
	if ((ret = rrr_ip_send(&err, accept_data->ip_data.fd, NULL, 0, (void*) send_data, send_size)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS) {
				RRR_DBG_1("Sending of message to remote blocked for ip instance %s, putting message back into send queue\n",
						INSTANCE_D_NAME(thread_data));

				if (ip_data->do_ordered_send) {
					// Don't use this connection anymore this round, enforce ordered send.
					accept_data->custom_data = 1;
				}
			}
			else {
				RRR_MSG_0("Connection problem with TCP connection while sending in ip instance %s, return was %i\n",
						INSTANCE_D_NAME(thread_data), ret);

				// This connection is not to be used anymore this round due
				// to errors. After this round, it should be removed.
				accept_data->custom_data = -1;
			}
		}
		else {
			RRR_MSG_0("Error while sending TCP message in ip instance %s\n",
					INSTANCE_D_NAME(thread_data));
		}
		goto out;
	}

	if (ip_data->do_multiple_per_connection || ip_data->do_persistent_connections) {
		// Allow more to be sent on this connection
	}
	else {
		// Disallow more use of this connection and tag for closing
		accept_data->custom_data = -1;
	}

	out:
	return ret;
}

static int ip_send_message_raw_default_target (
		struct ip_data *ip_data,
		struct rrr_ip_accept_data_collection *tcp_connect_data,
		struct rrr_ip_graylist *graylist,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	int ret = 0;

	struct rrr_ip_accept_data *accept_data_to_free = NULL;

	if (ip_data->target_port == 0) {
		RRR_MSG_0("Warning: A message from a sender in ip instance %s had no address information and we have no default remote host set, dropping it\n",
				INSTANCE_D_NAME(thread_data));
		goto out;
	}

	if (ip_data->target_protocol == RRR_IP_TCP) {
		struct rrr_ip_accept_data *accept_data = rrr_ip_accept_data_collection_find_by_fd (
				tcp_connect_data,
				ip_data->ip_tcp_default_target_fd
		);

		if (accept_data == NULL) {
			if (rrr_ip_network_connect_tcp_ipv4_or_ipv6 (
					&accept_data_to_free,
					ip_data->target_port,
					ip_data->target_host,
					graylist
			) != 0) {
				RRR_DBG_1("Could not connect with TCP to remote %s port %u in ip instance %s, postponing send\n",
						ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(thread_data));
				ret = RRR_READ_SOFT_ERROR;
				goto out;
			}

			ip_data->ip_tcp_default_target_fd = accept_data_to_free->ip_data.fd;

			accept_data = accept_data_to_free;
			RRR_LL_APPEND(tcp_connect_data, accept_data_to_free);
			accept_data_to_free = NULL;
		}

		ret = ip_send_message_tcp (
				ip_data,
				accept_data,
				send_data,
				send_size
		);
	}
	else {
		ret = rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
			&ip_data->ip_udp,
			ip_data->target_port,
			ip_data->target_host,
			(void *) send_data, // Cast away const OK
			send_size
		);
	}

	out:
		if (accept_data_to_free != NULL) {
			rrr_ip_accept_data_close_and_destroy_void(accept_data_to_free);
		}
		return ret;
}

static int ip_send_raw (
		struct ip_data *ip_data,
		struct rrr_ip_accept_data_collection *tcp_connect_data,
		struct rrr_ip_graylist *graylist,
		int protocol,
		const struct sockaddr *addr_orig,
		const socklen_t addr_len_orig,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	// If no translation is needed, the original address is copied
	rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed(&addr, &addr_len, addr_orig, addr_len_orig);
	
	int ret = 0;

	struct rrr_ip_accept_data *accept_data_to_free = NULL;

	// Configuration validation should produce an error if do_force_target is set
	// but no target_port/target_host
	if (ip_data->do_force_target == 1 || addr_len == 0) {
		//////////////////////////////////////////////////////
		// FORCED TARGET OR NO ADDRESS IN ENTRY, TCP OR UDP
		//////////////////////////////////////////////////////

		ret = ip_send_message_raw_default_target (
				ip_data,
				tcp_connect_data,
				graylist,
				send_data,
				send_size
		);
	}
	else if (protocol == RRR_IP_TCP) {
		//////////////////////////////////////////////////////
		// ADDRESS FROM ENTRY, TCP
		//////////////////////////////////////////////////////

		struct rrr_ip_accept_data *accept_data = rrr_ip_accept_data_collection_find (
				tcp_connect_data,
				(const struct sockaddr *) &addr,
				addr_len
		);

		if (accept_data == NULL) {
			if ((ret = rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw (
					&accept_data_to_free,
					(struct sockaddr *) &addr,
					addr_len,
					graylist
			)) != 0) {
				if (ret == RRR_SOCKET_HARD_ERROR) {
					char ip_str[256];
					rrr_ip_to_str(ip_str, 256, (const struct sockaddr *) &addr, addr_len);
					RRR_DBG_1("Connection to remote '%s' failed in ip instance %s\n",
							ip_str,
							INSTANCE_D_NAME(thread_data)
					);
					ret = RRR_SOCKET_SOFT_ERROR;
				}
				goto out;
			}

			accept_data = accept_data_to_free;
			RRR_LL_APPEND(tcp_connect_data, accept_data_to_free);
			accept_data_to_free = NULL;
		}

		ret = ip_send_message_tcp (
				ip_data,
				accept_data,
				send_data,
				send_size
		);
	}
	else {
		//////////////////////////////////////////////////////
		// ADDRESS FROM ENTRY, UDP
		//////////////////////////////////////////////////////

		int err; // errno, not checked for UDP
		ret = rrr_ip_send (
			&err,
			ip_data->ip_udp.fd,
			(const struct sockaddr *) &addr,
			addr_len,
			(void *) send_data, // Cast away const OK
			send_size
		);

		if (ret != 0) {
			RRR_MSG_0("Warning: Sending of a message failed in ip instance %s family was %u fd was %i: %s\n",
					INSTANCE_D_NAME(thread_data), ((const struct sockaddr *) &addr)->sa_family, ip_data->ip_udp.fd, rrr_strerror(err));
			goto out;
		}
	}

	//////////////////////////////////////////////////////
	// OUT
	//////////////////////////////////////////////////////

	out:
		if (accept_data_to_free != NULL) {
			rrr_ip_accept_data_close_and_destroy_void(accept_data_to_free);
		}
		return ret;
}
		
static int ip_send_message (
		struct ip_data *ip_data,
		struct rrr_ip_accept_data_collection *tcp_connect_data,
		struct rrr_ip_graylist *graylist,
		struct rrr_msg_holder *entry
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;
	int ret = 0;

	// Do not modify send_status here

	// Freed upon function return
	char *tmp_data = NULL;

	// Just a pointer to data managed elsewhere, not freed
	const void *send_data = NULL;
	ssize_t send_size = 0;
	
	struct rrr_array array_tmp = {0};
	struct rrr_msg_msg *message = entry->message;

	// We modify the data in the buffer here, no need to copy as the memory is always
	// freed after this function.
	if (ip_data->do_send_rrr_msg_msg != 0) {
		if (entry->data_length < (long int) sizeof(*message) - 1) {
			RRR_MSG_0("ip instance %s had send_rrr_msg_msg set but received a message which was too short (%li<%li), dropping it\n",
					INSTANCE_D_NAME(thread_data), entry->data_length, (long int) sizeof(*message));
			goto out;
		}

		ssize_t final_size = 0;

		// Check for second send attempt, message is then already in network order
		if (entry->send_time != 0) {
			final_size = entry->data_length;

			RRR_DBG_3 ("ip instance %s sends packet (new attempt) with rrr message timestamp from %" PRIu64 " size %li\n",
					INSTANCE_D_NAME(thread_data), rrr_be64toh(message->timestamp), final_size);
		}
		else {
			final_size = MSG_TOTAL_SIZE(message);

			// Since we need this parameter any successive send attempts, make sure it's the correct value
			entry->data_length = final_size;

			if (entry->data_length != final_size) {
				RRR_BUG("message size mismatch in ip input_callback %li vs %li\n", entry->data_length, final_size);
			}

			RRR_DBG_3 ("ip instance %s sends packet with rrr message timestamp from %" PRIu64 " size %li\n",
					INSTANCE_D_NAME(thread_data), message->timestamp, final_size);

			rrr_msg_msg_prepare_for_network(message);

			rrr_msg_populate_head (
					(struct rrr_msg *) message,
					RRR_MSG_TYPE_MESSAGE,
					final_size,
					0
			);

			rrr_msg_checksum_and_to_network_endian (
					(struct rrr_msg *) message
			);
		}

		send_data = message;
		send_size = final_size;
	}
	else if (MSG_IS_ARRAY(message)) {
		int tag_count = RRR_MAP_COUNT(&ip_data->array_send_tags);

		if (rrr_array_message_append_to_collection(&array_tmp, message) != 0) {
			RRR_MSG_0("Could not convert array message to collection in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(tmp_data);
		ssize_t target_size = 0;
		int found_tags = 0;
		struct rrr_map *tag_map = (tag_count > 0 ? &ip_data->array_send_tags : NULL);
		if (rrr_array_selected_tags_export (
				&tmp_data,
				&target_size,
				&found_tags,
				&array_tmp,
				tag_map
		) != 0) {
			RRR_MSG_0("Error while converting array to raw in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		if (tag_count != 0 && found_tags != tag_count) {
			RRR_MSG_0("Array message to send in ip instance %s did not contain all tags specified in configuration, dropping it (%i tags missing)\n",
					INSTANCE_D_NAME(thread_data), tag_count - found_tags);
			goto out;
		}

		RRR_DBG_3 ("ip instance %s sends packet with array data from message with timestamp from %" PRIu64 " %i array tags size %li\n",
				INSTANCE_D_NAME(thread_data), message->timestamp, found_tags, target_size);

		send_data = tmp_data;
		send_size = target_size;
	}
	else if (RRR_MAP_COUNT(&ip_data->array_send_tags) > 0) {
		RRR_MSG_0("ip instance %s received a non-array message while setting ip_array_send_tags was defined, dropping it\n",
				INSTANCE_D_NAME(thread_data));
		goto out;
	}
	else {
		send_data = MSG_DATA_PTR(message);
		send_size = MSG_DATA_LENGTH(message);

		if (send_size == 0) {
			RRR_DBG_3 ("ip instance %s received a message with 0 bytes with timestamp %" PRIu64 ", not sending it\n",
				INSTANCE_D_NAME(thread_data), message->timestamp);
			goto out;
		}

		RRR_DBG_3 ("ip instance %s sends packet with raw data from message with timestamp from %" PRIu64 " %li bytes\n",
				INSTANCE_D_NAME(thread_data), message->timestamp, send_size);
	}

	if ((ip_data->target_port != 0 && (ip_data->target_host == NULL || *(ip_data->target_host) == '\0')) ||
	    (ip_data->target_port == 0 && (ip_data->target_host != NULL && *(ip_data->target_host) != '\0'))
	) {
		RRR_BUG("Invalid target_port/target_host configuration in ip input_callback\n");
	}

	// Used to check for successive send attempts and timeout
	if (entry->send_time == 0) {
		entry->send_time = rrr_time_get_64();
	}

	ret = ip_send_raw (
			ip_data,
			tcp_connect_data,
			graylist,
			entry->protocol,
			(struct sockaddr *) &entry->addr,
			entry->addr_len,
			send_data,
			send_size
	);

	out:
		RRR_FREE_IF_NOT_NULL(tmp_data);
		rrr_array_clear(&array_tmp);
		return ret;
}

static int ip_send_loop (
		int *did_do_something,
		struct ip_data *data,
		struct rrr_ip_accept_data_collection *tcp_connect_data,
		struct rrr_ip_graylist *tcp_graylist
) {
	int ret_tmp = 0;

	if (data->do_ordered_send) {
		rrr_msg_msg_holder_collection_sort(&data->send_buffer, rrr_msg_msg_timestamp_compare_void);
	}

//		printf ("TCP connect count: %i\n", RRR_LL_COUNT(&tcp_connect_data));

	// We use the custom data field to tag connections with problems. If there are errors detected
	// on a particular connection detected during the send queue iteration,
	// we don't attempt any more sends on this connection until next send
	// queue iteration. A connection attempt counts as an error, no send
	// attempts will be performed until the next round.

	// We must also, to preserve order, postpone the destruction on any connection until
	// the iteration has finished. Broken connections are tagged and destroyed
	// here.

	uint64_t timeout_limit = rrr_time_get_64() - (data->message_send_timeout_s * 1000000);
	uint64_t send_loop_time_limit = rrr_time_get_64() + (IP_SEND_TIME_LIMIT_MS * 1000);
	int max_iterations = 500;
	int timeout_count = 0;
	RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_msg_holder);
		enum ip_action action = IP_ACTION_RETRY;

		if (--max_iterations == 0 || rrr_time_get_64() > send_loop_time_limit) {
			RRR_LL_ITERATE_LAST();
		}

		rrr_msg_holder_lock(node);

		int message_was_sent = 1;
		int timeout_reached = 0;

		if (data->message_send_timeout_s > 0 && node->send_time > 0 && node->send_time < timeout_limit) {
			timeout_count++;
			RRR_DBG_1("Message timed out after %u seconds in ip instance %s, performing timeout action %s.\n",
					data->message_send_timeout_s, INSTANCE_D_NAME(data->thread_data), data->timeout_action_str);
			timeout_reached = 1;
		}
		else if ((ret_tmp = ip_send_message(data, tcp_connect_data, tcp_graylist, node)) != 0) {
			if (ret_tmp == RRR_SOCKET_SOFT_ERROR) {
				message_was_sent = 0;
				ret_tmp = 0;
			}
			else {
				RRR_MSG_0("Error while iterating input buffer in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
				RRR_LL_ITERATE_LAST();
			}
		}

		// ip_send functions does not always set send_time parameter
		if (node->send_time == 0) {
			node->send_time = rrr_time_get_64();
		}

		if (message_was_sent) {
			action = IP_ACTION_DROP;
		}

		// Timeout overrides retry. Note that the configuration parser should check that
		// default action is not retry while send_timeout is >0, would otherwise cause us
		// to spam timed out messages. We do not reset the send_time in the entry.
		if (timeout_reached) {
			action = data->timeout_action;
		}

		//printf("Node send time: %" PRIu64 "\n", node->send_time);
		//printf("Timeout action: %i, send status: %i\n", action, send_status);

		// Make sure we always unlock, ether in ITERATE_END destroy or here if we
		// do not destroy
		if (action == IP_ACTION_RETRY) {
			// Just retry
			rrr_msg_holder_unlock(node);
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
			*did_do_something = 1;

			if (action == IP_ACTION_RETURN) {
				if ((ret_tmp = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
						INSTANCE_D_BROKER_ARGS(data->thread_data),
						node
				)) != 0) {
					RRR_MSG_0("Error while adding message to buffer in buffer instance %s\n",
							INSTANCE_D_NAME(data->thread_data));
					RRR_LL_ITERATE_LAST(); // Destroy function must run and unlock
				}
			}
			else {
				// IP_ACTION_DROP, do nothing and just continue with destroy
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->send_buffer, 0; rrr_msg_holder_decref_while_locked_and_unlock(node));

	if (timeout_count > 0) {
		RRR_MSG_0("Send timeout for %i messages in ip instance %s\n",
				timeout_count, INSTANCE_D_NAME(data->thread_data));
	}

	if (ret_tmp != 0) {
		RRR_MSG_ERR("Error while sending messages in ip instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(tcp_connect_data, struct rrr_ip_accept_data);
		// < 0 == close now
		// 0 == follow persistent settings
		// other: temorary block, do not close yet
		if ((data->do_persistent_connections == 0 && node->custom_data == 0) || node->custom_data < 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else {
			node->custom_data = 0;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(tcp_connect_data, 0; rrr_ip_accept_data_close_and_destroy(node));

	out:
	return ret_tmp;
}

static void *thread_entry_ip (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ip_data *data = thread_data->private_data = thread_data->private_memory;

	struct rrr_ip_accept_data_collection tcp_accept_data = {0};
	struct rrr_ip_accept_data_collection tcp_connect_data = {0};
	struct rrr_ip_graylist tcp_graylist = {0};

	if (ip_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in ip instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("ip thread data is %p\n", thread_data);

	pthread_cleanup_push(ip_data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread, RRR_THREAD_SIGNAL_START);

	// Don't set running here, wait until listening has started

	if (ip_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parsing failed for ip instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message_no_network_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	int has_senders = (rrr_poll_collection_count(&thread_data->poll) > 0 ? 1 : 0);

	if (has_senders == 0 && data->definitions == NULL) {
		RRR_MSG_0("Error: ip instance %s has no senders defined and also has no array definition. Cannot do anything with this configuration.\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message_no_network_cleanup;
	}

	if (data->source_udp_port == 0) {
		if (rrr_ip_network_start_udp_ipv4_nobind(&data->ip_udp) != 0) {
			RRR_MSG_0("Could not initialize network in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message_no_network_cleanup;
		}
		RRR_DBG_1("ip instance %s started, not listening on any UDP port\n", INSTANCE_D_NAME(thread_data));
	}
	else {
		data->ip_udp.port = data->source_udp_port;
		if (rrr_ip_network_start_udp_ipv4(&data->ip_udp) != 0) {
			RRR_MSG_0("Could not initialize UDP network in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_message_no_network_cleanup;
		}
		RRR_DBG_1("ip instance %s listening on and/or sending from UDP port %d\n",
				INSTANCE_D_NAME(thread_data), data->source_udp_port);
	}

	pthread_cleanup_push(rrr_ip_network_cleanup, &data->ip_udp);

	if (data->source_tcp_port > 0) {
		data->ip_tcp_listen.port = data->source_tcp_port;
		if (rrr_ip_network_start_tcp_ipv4_and_ipv6(&data->ip_tcp_listen, 10) != 0) {
			RRR_MSG_0("Could not initialize TCP network in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			goto out_cleanup_udp;
		}
		RRR_DBG_1("ip instance %s listening on TCP port %d\n",
				INSTANCE_D_NAME(thread_data), data->source_tcp_port);
	}

	pthread_cleanup_push(rrr_ip_network_cleanup, &data->ip_tcp_listen);
	pthread_cleanup_push(rrr_ip_accept_data_collection_clear_void, &tcp_accept_data);
	pthread_cleanup_push(rrr_ip_accept_data_collection_clear_void, &tcp_connect_data);
	pthread_cleanup_push(rrr_ip_graylist_clear_void, &tcp_graylist);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	uint64_t prev_read_error_count = 0;
	uint64_t prev_read_count = 0;
	uint64_t prev_polled_count = 0;

	unsigned int consecutive_nothing_happened = 0;
	uint64_t next_stats_time = 0;
	unsigned int tick = 0;
	while (!rrr_thread_check_encourage_stop(thread)) {
		rrr_thread_update_watchdog_time(thread);

//		printf ("IP ticks: %u\n", tick);

		if (has_senders != 0) {
			if (rrr_poll_do_poll_delete (thread_data, &thread_data->poll, poll_callback_ip, 0) != 0) {
				RRR_MSG_ERR("Error while polling in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		int did_send_something = 0;
		if (ip_send_loop (
				&did_send_something,
				data,
				&tcp_connect_data,
				&tcp_graylist
		) != 0) {
			break;
		}

		if (data->definitions != NULL) {
			if (ip_udp_read_data(data) != 0) {
				RRR_MSG_ERR("Error while reading udp data in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
			if (ip_tcp_read_data(data, &tcp_accept_data) != 0) {
				RRR_MSG_ERR("Error while reading tcp data in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		// Sleep if nothing happened
		if (prev_read_count == data->messages_count_read &&
			prev_polled_count == data->messages_count_polled &&
			prev_read_error_count == data->read_error_count &&
			did_send_something == 0
		) {
			if (++consecutive_nothing_happened > 10) {
//				printf ("Sleep: %u\n", consecutive_nothing_happened);
				rrr_posix_usleep(25000);
			}
		}
		else {
			consecutive_nothing_happened = 0;
		}

		uint64_t time_now = rrr_time_get_64();

		if (INSTANCE_D_STATS(thread_data) != NULL && time_now > next_stats_time) {
			int delivery_entry_count = 0;
			int delivery_ratelimit_active = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&delivery_entry_count,
					&delivery_ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_ERR("Error while setting ratelimit in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}

			rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 1, "read_error_count", data->read_error_count);
			rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 2, "read_count", data->messages_count_read);
			rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 3, "polled_count", data->messages_count_polled);
			rrr_stats_instance_post_unsigned_base10_text (
					INSTANCE_D_STATS(thread_data),
					"delivery_buffer_count",
					0,
					delivery_entry_count
			);

			tick = 0;
			data->read_error_count = 0;
			data->messages_count_read = 0;
			data->messages_count_polled = 0;

			next_stats_time = time_now + 1000000;

			/*
			printf ("-- Dump send buffer -----------------------------------\n");
			RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_msg_msg_holder);
				struct rrr_msg_msg *message = node->message;

				printf ("timestamp %" PRIu64 "\n", (node->send_time > 0 ? be64toh(message->timestamp) : message->timestamp));
			RRR_LL_ITERATE_END();
			printf ("-- Dump send buffer end --------------------------------\n");
*/
		}

		prev_read_error_count = data->read_error_count;
		prev_read_count = data->messages_count_read;
		prev_polled_count = data->messages_count_polled;

		tick++;
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	out_cleanup_udp:

	pthread_cleanup_pop(1);

	out_message_no_network_cleanup:

	RRR_DBG_1 ("ip instance %s stopping\n", thread_data->init_data.instance_config->name);
	// Set running in case we failed before getting around to do that
	if (!rrr_thread_check_state(thread, RRR_THREAD_STATE_RUNNING)) {
		rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);
	}
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_ip,
	NULL,
	NULL,
	NULL
};

static const char *module_name = "ip";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_FLEXIBLE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
		data->start_priority = RRR_THREAD_START_PRIORITY_NETWORK;
}

void unload(void) {
}


