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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../lib/settings.h"
#include "../lib/vl_time.h"
#include "../lib/messages.h"
#include "../lib/ip.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/ip_accept_data.h"
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
#include "../lib/message_broker.h"
#include "../lib/rrr_endian.h"
#include "../lib/log.h"

#define IP_DEFAULT_PORT			2222
#define IP_DEFAULT_PROTOCOL		RRR_IP_UDP
#define IP_SEND_TIME_LIMIT_MS	1000
#define IP_TCP_GRAYLIST_TIME_MS	2000

struct ip_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_ip_buffer_entry_collection send_buffer;
//	struct rrr_ip_buffer_entry_collection delivery_buffer;
	unsigned int source_udp_port;
	unsigned int source_tcp_port;
	struct rrr_ip_data ip_udp;
	struct rrr_ip_data ip_tcp_listen;
	int ip_tcp_default_target_fd;
	struct rrr_array definitions;
	struct rrr_read_session_collection read_sessions_udp;
	struct rrr_read_session_collection read_sessions_tcp;
	int do_sync_byte_by_byte;
	int do_send_rrr_message;
	int do_force_target;
	int do_extract_rrr_messages;
	int do_ordered_send;
	int do_drop_on_error;
	int do_persistent_connections;
	rrr_setting_uint message_send_timeout_s;
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

void data_cleanup(void *arg) {
	struct ip_data *data = (struct ip_data *) arg;
	rrr_ip_buffer_entry_collection_clear(&data->send_buffer);
	rrr_array_clear(&data->definitions);
	rrr_read_session_collection_clear(&data->read_sessions_udp);
	rrr_read_session_collection_clear(&data->read_sessions_tcp);
	RRR_FREE_IF_NOT_NULL(data->default_topic);
	RRR_FREE_IF_NOT_NULL(data->target_host);
	rrr_map_clear(&data->array_send_tags);
}

int data_init(struct ip_data *data, struct rrr_instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

int config_parse_port (struct ip_data *data, struct rrr_instance_config *config) {
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
			ret = 0;
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
			ret = 0;
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
			ret = 0;
		}
		else {
			RRR_MSG_0("Error while parsing ip_remote_port setting for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}
	data->target_port = tmp_uint;

	out:
	return ret;
}

int parse_config (struct ip_data *data, struct rrr_instance_config *config) {
	int ret = 0;
	char *protocol = NULL;

	// Parse listen and target port
	if ((ret = config_parse_port (data, config)) != 0) {
		goto out;
	}

	// Default target protocol
	if ((ret = rrr_settings_get_string_noconvert_silent(&protocol, config->settings, "ip_target_protocol")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing configuration parameter ip_target_protocol in ip instance %s\n", config->name);
			ret = 1;
			goto out;
		}
		ret = 0;
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

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ip_target_host", target_host);

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
	if ((ret = rrr_instance_config_parse_array_definition_from_config_silent_fail(&data->definitions, config, "ip_input_types")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Could not parse command line argument ip_input_types in udp\n");
			ret = 1;
			goto out;
		}
	}

	if (data->definitions.node_count > 0 && data->source_udp_port == 0 && data->source_tcp_port == 0) {
		RRR_MSG_0("ip_input_types was set but ip_port was not, this is an invalid configuraton in ip instance %s\n", config->name);
		ret = 1;
		goto out;
	}
	else if (data->definitions.node_count == 0) {
		// Listening disabled
	}

	RRR_SETTINGS_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("ip_default_topic", default_topic);

	if (data->default_topic != NULL) {
		data->default_topic_length = strlen(data->default_topic);
	}

	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_sync_byte_by_byte", do_sync_byte_by_byte, 0);
	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_send_rrr_message", do_send_rrr_message, 0);
	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_force_target", do_force_target, 0);

	if (data->do_force_target == 1 && data->target_port == 0) {
		RRR_MSG_0("ip_force_target was set to yes but no target was specified in ip_target_host and ip_target_port in ip instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_extract_rrr_messages", do_extract_rrr_messages, 0);
	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_preserve_order", do_ordered_send, 0);
	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_drop_on_error", do_drop_on_error, 0);
	RRR_SETTINGS_PARSE_OPTIONAL_YESNO("ip_persistent_connections", do_persistent_connections, 0);

	// Array columns to send if we receive array messages from other modules
	ret = rrr_instance_config_parse_comma_separated_to_map(&data->array_send_tags, config, "ip_array_send_tags");
	if (ret != 0 && ret != RRR_SETTING_NOT_FOUND) {
		RRR_MSG_0("Error while parsing ip_array_send_tags of instance %s\n", config->name);
		goto out;
	}
	RRR_DBG_1("%i array tags specified for ip instance %s to send\n", RRR_MAP_COUNT(&data->array_send_tags), config->name);

	RRR_SETTINGS_PARSE_OPTIONAL_UNSIGNED("ip_send_timeout", message_send_timeout_s, 0);

	out:
	RRR_FREE_IF_NOT_NULL(protocol);
	return ret;
}

struct ip_read_callback_data {
	struct ip_data *ip_data;
	const struct rrr_ip_buffer_entry *entry_orig;
};

int ip_read_data_receive_message_callback (struct rrr_message *message, void *arg) {
	struct ip_read_callback_data *callback_data = arg;
	struct ip_data *data = callback_data->ip_data;

	int ret = 0;

	struct rrr_ip_buffer_entry *new_entry = NULL;

	if (rrr_ip_buffer_entry_new (
			&new_entry,
			MSG_TOTAL_SIZE(message),
			(struct sockaddr *) &callback_data->entry_orig->addr,
			callback_data->entry_orig->addr_len,
			callback_data->entry_orig->protocol,
			message
	) != 0) {
		RRR_MSG_0("Could not create new ip buffer entry in read_data_receive_message_callback\n");
		ret = 1;
		goto out;
	}

	rrr_ip_buffer_entry_lock(new_entry);

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
	rrr_ip_buffer_entry_decref_while_locked_and_unlock(new_entry);
	if (message != NULL) {
		free(message);
	}
	return ret;
}

int read_data_receive_extract_messages_callback (const struct rrr_array *array, void *arg) {
	struct ip_read_callback_data *callback_data = arg;
	struct ip_data *data = callback_data->ip_data;

	int ret = 0;

	int found_messages = 0;
	RRR_LL_ITERATE_BEGIN(array, const struct rrr_type_value);
		if (RRR_TYPE_IS_MSG(node->definition->type)) {
			const struct rrr_message *message = (struct rrr_message *) node->data;
			struct rrr_message *message_new = rrr_message_duplicate(message);
			if (message_new == NULL) {
				RRR_MSG_0("Could not allocate new message in ip read_data_receive_array_callback\n");
				ret = 1;
				goto out;
			}

			if ((ret = ip_read_data_receive_message_callback(message_new, arg)) != 0) {
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

int ip_read_raw_data_callback (struct rrr_ip_buffer_entry *entry, void *arg) {
	struct ip_data *data = arg;
	int ret = 0;
	struct ip_read_callback_data callback_data = {
			data,
			entry // Only used for reference by callbacks,
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
			ip_read_data_receive_message_callback,
			&callback_data
		);
	}

	if (ret != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			RRR_MSG_0("Could not create message in ip instance %s read_data_callback, soft error probably caused by invalid input data\n",
					INSTANCE_D_NAME(data->thread_data));
			ret = 0;
		}
		else {
			RRR_MSG_0("Could not create message in ip instance %s read_data_callback\n",
					INSTANCE_D_NAME(data->thread_data));
		}
		goto out;
	}

	out:
	return ret;
}

struct ip_read_array_intermediate_callback_data {
	struct ip_data *data;
	int handle_soft_error;
	int return_value_from_array;
	int fd;
	struct rrr_read_session_collection *read_sessions;
	int loops;
};

int ip_read_array_intermediate(struct rrr_ip_buffer_entry *entry, void *arg) {
	struct ip_read_array_intermediate_callback_data *callback_data = arg;
	struct ip_data *data = callback_data->data;

	int ret = RRR_MESSAGE_BROKER_OK;

	if ((ret = rrr_ip_receive_array (
			entry,
			callback_data->read_sessions,
			callback_data->fd,
			RRR_READ_F_NO_SLEEPING,
			&data->definitions,
			data->do_sync_byte_by_byte,
			ip_read_raw_data_callback,
			data,
			NULL
	)) != 0) {
		if (ret == RRR_ARRAY_PARSE_SOFT_ERR) {
			if (callback_data->handle_soft_error) {
				// Caller handles return value
				callback_data->return_value_from_array = ret;
				ret = RRR_MESSAGE_BROKER_OK;
				goto out_no_loop;
			}
			else {
				RRR_MSG_0("Received invalid data in ip_receive_packets in ip instance %s\n",
						INSTANCE_D_NAME(data->thread_data));
				// Don't allow invalid data to stop processing
				ret = RRR_MESSAGE_BROKER_OK;
				data->read_error_count++;
			}
		}
		else {
			RRR_MSG_0("Error from ip_receive_packets in ip instance %s return was %i\n",
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

		rrr_ip_buffer_entry_unlock(entry);
		return ret;
}

int ip_read_loop (struct ip_data *data, int handle_soft_error, int fd, struct rrr_read_session_collection *read_sessions) {
	int ret = 0;

	struct ip_read_array_intermediate_callback_data callback_data = {
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

int tcp_read_data (struct ip_data *data, struct rrr_ip_accept_data_collection *accept_data_collection) {
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

int udp_read_data(struct ip_data *data) {
	int ret = 0;

	if (data->source_udp_port > 0) {
		if ((ret = ip_read_loop (data, 0, data->ip_udp.fd, &data->read_sessions_udp)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}

static int inject_callback(void *arg1, void *arg2) {
	struct ip_data *data = arg1;
	struct rrr_ip_buffer_entry *entry = arg2;

	return ip_read_raw_data_callback(entry, data);
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	struct ip_data *data = thread_data->private_data;

	RRR_DBG_2("ip instance %s writing data from inject function\n", INSTANCE_D_NAME(thread_data));

	int ret = rrr_message_broker_with_ctx_do (
			INSTANCE_D_BROKER(thread_data),
			INSTANCE_D_HANDLE(thread_data),
			inject_callback,
			data,
			message
	);

	rrr_ip_buffer_entry_unlock(message);

	return ret;
}

static int poll_callback_ip (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct ip_data *data = thread_data->private_data;

	struct rrr_message *message = entry->message;

	RRR_DBG_3 ("ip instance %s: Result from buffer timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	rrr_ip_buffer_entry_incref_while_locked(entry);

	entry->send_time = 0;
	RRR_LL_APPEND(&data->send_buffer, entry);

	rrr_ip_buffer_entry_unlock(entry);

	return 0;
}

static int ip_send_message_tcp (
		int *put_back,
		int *close_connection_now,
		struct ip_data *ip_data,
		struct rrr_ip_accept_data *accept_data,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_thread_data *thread_data = ip_data->thread_data;

	int ret = 0;

	int err;

	// Always close if message was sent unless preserve connections is set
	*close_connection_now = (ip_data->do_persistent_connections ? 0 : 1);

	// Default flow is that message was successfully sent
	*put_back = 0;

	if (accept_data->custom_data == 1) {
		// Connection tagged for destruction or should not be used due to
		// earlier error this round
		goto out_put_back;
	}
	else if (accept_data->custom_data == -1) {
		// Properly handle putback or drop
		goto out_close_connection_error;
	}

	if ((ret = rrr_socket_send_check(accept_data->ip_data.fd)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_DBG_3("Connection not ready while sending in ip instance %s, putting message back into send queue\n",
					INSTANCE_D_NAME(thread_data));
			goto out_put_back;
		}

		RRR_MSG_0("Connection problem with TCP connection in ip instance %s\n",
				INSTANCE_D_NAME(thread_data));

		goto out_close_connection_error;
	}
	else if ((ret = rrr_ip_send(&err, accept_data->ip_data.fd, NULL, 0, (void*) send_data, send_size)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			if (err == EAGAIN || err == EWOULDBLOCK) {
				RRR_DBG_1("Sending of message to remote blocked for ip instance %s, putting message back into send queue\n",
						INSTANCE_D_NAME(thread_data));

				if (ip_data->do_ordered_send) {
					goto out_put_back;
				}
				else {
					goto out_put_back_retry_immediately;
				}
			}

			RRR_MSG_0("Connection problem with TCP connection while sending in ip instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto out_close_connection_error;
		}
		else {
			RRR_MSG_0("Error while sending TCP message in ip instance %s\n",
					INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out;
		}
	}

	goto out;

	out_close_connection_error:
		// This connection is not to be used any more this round due
		// to errors. Afterwards, it should be removed.
		accept_data->custom_data = -1;

		// To preserve send order, do not remove the connection from the list now. This
		// would otherwise cause packets later in the queue to re-connect
		*close_connection_now = 0;

		if (ip_data->do_drop_on_error == 1) {
			RRR_DBG_1("Dropping message following error in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			*put_back = 0;
		}
		else {
			*put_back = 1;
		}

		// Any error is now handled
		ret = 0;

		goto out;

	out_put_back:
		// Don't use this connection anymore this round (for instance when waiting for establishment)
		accept_data->custom_data = 1;

	out_put_back_retry_immediately:
		// Preserve send order
		*close_connection_now = 0;

		// Don't delete this message from queue
		*put_back = 1;

		// Any error is now handled
		ret = 0;

	out:
		return ret;
}

static int ip_send_message_raw (
		int *do_destroy,
		struct ip_data *ip_data,
		struct rrr_ip_accept_data_collection *tcp_connect_data,
		struct rrr_ip_graylist *graylist,
		int protocol,
		struct sockaddr *addr,
		socklen_t addr_len,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_thread_data *thread_data = ip_data->thread_data;
	
	int ret = 0;
	int put_back = 0;
	int close_connection_now = 0;

	struct rrr_ip_accept_data *accept_data_to_free = NULL;

	// Have this const to avoid mixing it up with the other one in this function
	const struct rrr_ip_accept_data *accept_data_to_use = NULL;

	
	//////////////////////////////////////////////////////
	// FORCED TARGET OR NO ADDRESS IN ENTRY, TCP OR UDP
	//////////////////////////////////////////////////////

	// Configuration validation should produce an error if do_force_target is set
	// but no target_port/target_host
	if (ip_data->do_force_target == 1 || addr_len == 0) {
		if (ip_data->target_port == 0) {
			RRR_MSG_0("Warning: A message from a sender in ip instance %s had no address information and we have no default remote host set, dropping it\n",
					INSTANCE_D_NAME(thread_data));
			goto out;
		}

		if (ip_data->target_protocol == RRR_IP_TCP) {
			accept_data_to_use = rrr_ip_accept_data_collection_find_by_fd (
					tcp_connect_data,
					ip_data->ip_tcp_default_target_fd
			);

			if (accept_data_to_use == NULL) {
				if (rrr_ip_network_connect_tcp_ipv4_or_ipv6 (
						&accept_data_to_free,
						ip_data->target_port,
						ip_data->target_host,
						graylist
				) != 0) {
					RRR_DBG_1("Could not connect with TCP to remote %s port %u in ip instance %s, postponing send\n",
							ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(thread_data));
					goto out_put_back;
				}

				ip_data->ip_tcp_default_target_fd = accept_data_to_free->ip_data.fd;

				// Blocks more attempts of using this connection until next round
				accept_data_to_free->custom_data = 1;

				accept_data_to_use = accept_data_to_free;
				RRR_LL_APPEND(tcp_connect_data, accept_data_to_free);
				accept_data_to_free = NULL;
			}

			goto ip_tcp_send;
		}

		ret = rrr_ip_network_sendto_udp_ipv4_or_ipv6 (
			&ip_data->ip_udp,
			ip_data->target_port,
			ip_data->target_host,
			(void *) send_data, // Cast away const OK
			send_size
		);

		goto out;
	}

	//////////////////////////////////////////////////////
	// ADDRESS FROM ENTRY, TCP
	//////////////////////////////////////////////////////

	if (protocol == RRR_IP_TCP) {
		accept_data_to_use = rrr_ip_accept_data_collection_find (
				tcp_connect_data,
				(struct sockaddr *) addr,
				addr_len
		);

		if (accept_data_to_use == NULL) {
			if (rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw(
					&accept_data_to_free,
					(struct sockaddr *) addr,
					addr_len,
					graylist
			) != 0) {
				char ip_str[256];
				rrr_ip_to_str(ip_str, 256, addr, addr_len);
				RRR_DBG_1("Could not connect to default remote '%s' in ip instance %s, graylisting for %u ms\n",
						ip_str,
						INSTANCE_D_NAME(thread_data),
						IP_TCP_GRAYLIST_TIME_MS
				);
				goto out_put_back;
			}

			// Blocks more attempts of using this connection untill next round
			accept_data_to_free->custom_data = 1;

			accept_data_to_use = accept_data_to_free;
			RRR_LL_APPEND(tcp_connect_data, accept_data_to_free);
			accept_data_to_free = NULL;
		}

		goto ip_tcp_send;
	}

	//////////////////////////////////////////////////////
	// ADDRESS FROM ENTRY, UDP
	//////////////////////////////////////////////////////

	int err; // errno, not checked for UDP
	ret = rrr_ip_send (
		&err,
		ip_data->ip_udp.fd,
		(struct sockaddr *) addr,
		addr_len,
		(void *) send_data, // Cast away const OK
		send_size
	);

	if (ret != 0) {
		RRR_MSG_0("Warning: Sending of a message failed in ip instance %s family was %u fd was %i: %s\n",
				INSTANCE_D_NAME(thread_data), addr->sa_family, ip_data->ip_udp.fd, rrr_strerror(err));
		// Ignore errors
		ret	= 0;
	}

	goto out;

	//////////////////////////////////////////////////////
	// OUT, PUT BACK, TCP SEND
	//////////////////////////////////////////////////////

	ip_tcp_send:
		if ((ret = ip_send_message_tcp (
				&put_back,
				&close_connection_now,
				ip_data,
				(struct rrr_ip_accept_data *) accept_data_to_use, // Cast away const OK
				send_data,
				send_size
		)) != 0) {
			goto out;
		}
		if (put_back) {
			goto out_put_back;
		}
	goto out;

	out_put_back:
		// Don't stop and block others, continue reading from the buffer in
		// case there are other targets
		ret = 0;
		*do_destroy = 0;

	out:
		if (close_connection_now) {
			RRR_LL_REMOVE_NODE_IF_EXISTS (
					tcp_connect_data,
					struct rrr_ip_accept_data,
					accept_data_to_use,
					rrr_ip_accept_data_close_and_destroy(node)
			);
		}

		if (accept_data_to_free != NULL) {
			rrr_ip_accept_data_close_and_destroy_void(accept_data_to_free);
		}
		return ret;
}
		
static int ip_send_message (
		int *do_destroy,
		struct ip_data *ip_data,
		struct rrr_ip_accept_data_collection *tcp_connect_data,
		struct rrr_ip_graylist *graylist,
		struct rrr_ip_buffer_entry *entry
) {
	struct rrr_instance_thread_data *thread_data = ip_data->thread_data;
	int ret = 0;

	// Default is that message was handled correctly or had errors and should in any casebe destroyed
	*do_destroy = 1;

	// Freed upon function return
	char *tmp_data = NULL;

	// Just a pointer to data managed elsewhere, not freed
	const void *send_data = NULL;
	ssize_t send_size = 0;
	
	struct rrr_array array_tmp = {0};
	struct rrr_message *message = entry->message;

	// We modify the data in the buffer here, no need to copy as the memory is always
	// freed after this function.
	if (ip_data->do_send_rrr_message != 0) {
		if (entry->data_length < (long int) sizeof(*message) - 1) {
			RRR_MSG_0("ip instance %s had send_rrr_message set but received a message which was too short (%li<%li), dropping it\n",
					INSTANCE_D_NAME(thread_data), entry->data_length, (long int) sizeof(*message));
			ret = 0; // Non-critical error
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

			rrr_message_prepare_for_network(message);

			rrr_socket_msg_populate_head (
					(struct rrr_socket_msg *) message,
					RRR_SOCKET_MSG_TYPE_MESSAGE,
					final_size,
					0
			);

			rrr_socket_msg_checksum_and_to_network_endian (
					(struct rrr_socket_msg *) message
			);
		}

		send_data = message;
		send_size = final_size;
	}
	else if (MSG_IS_ARRAY(message)) {
		int tag_count = RRR_MAP_COUNT(&ip_data->array_send_tags);

		if (rrr_array_message_to_collection(&array_tmp, message) != 0) {
			RRR_MSG_0("Could not convert array message to collection in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			ret = 1; // Probably bug in some other module or with array parsing
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
			ret = 1; // Probably bug in some other module or with array parsing
			goto out;
		}

		if (tag_count != 0 && found_tags != tag_count) {
			RRR_MSG_0("Array message to send in ip instance %s did not contain all tags specified in configuration, dropping it (%i tags missing)\n",
					INSTANCE_D_NAME(thread_data), tag_count - found_tags);
			ret = 0; // Non-critical
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
		ret = 0; // Non-critical error
		goto out;
	}
	else {
		send_data = message->data;
		send_size = MSG_DATA_LENGTH(message);

		if (send_size == 0) {
			ret = 0; // Nothing to send
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

	if ((ret = ip_send_message_raw (
			do_destroy,
			ip_data,
			tcp_connect_data,
			graylist,
			entry->protocol,
			(struct sockaddr *) &entry->addr,
			entry->addr_len,
			send_data,
			send_size
	)) != 0) {
		RRR_MSG_0("Could not send data in ip instance %s\n", INSTANCE_D_NAME(thread_data));
		ret = 1;
		goto out;
	}

	goto out;
	out:
		RRR_FREE_IF_NOT_NULL(tmp_data);
		rrr_array_clear(&array_tmp);
		return ret;
}

static void *thread_entry_ip (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct ip_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_poll_collection poll;

	struct rrr_ip_accept_data_collection tcp_accept_data = {0};
	struct rrr_ip_accept_data_collection tcp_connect_data = {0};
	struct rrr_ip_graylist tcp_graylist = {0};

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initalize data in ip instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("ip thread data is %p\n", thread_data);

	rrr_poll_collection_init(&poll);
	RRR_STATS_INSTANCE_INIT_WITH_PTHREAD_CLEANUP_PUSH;
	pthread_cleanup_push(rrr_poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);

	// Don't set running here, wait until listening has started

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parsing failed for ip instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message_no_network_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_poll_add_from_thread_senders(&poll, thread_data);

	int has_senders = (rrr_poll_collection_count(&poll) > 0 ? 1 : 0);

	if (has_senders == 0 && RRR_LL_COUNT(&data->definitions) == 0) {
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

	RRR_STATS_INSTANCE_POST_DEFAULT_STICKIES;

	uint64_t prev_read_error_count = 0;
	uint64_t prev_read_count = 0;
	uint64_t prev_polled_count = 0;

	unsigned int consecutive_nothing_happened = 0;
	uint64_t next_stats_time = 0;
	unsigned int tick = 0;
	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_thread_update_watchdog_time(thread_data->thread);

//		printf ("IP ticks: %u\n", tick);

		if (has_senders != 0) {
			if (rrr_poll_do_poll_delete (thread_data, &poll, poll_callback_ip, 0) != 0) {
				RRR_MSG_ERR("Error while polling in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		if (data->do_ordered_send) {
			rrr_ip_buffer_entry_collection_sort(&data->send_buffer, rrr_message_timestamp_compare_void);
		}

//		printf ("TCP connect count: %i\n", RRR_LL_COUNT(&tcp_connect_data));

		// We use the counter to count send errors. If there are errors detected
		// on a particular connection detected during the send queue iteration,
		// we don't attempt any more sends on this connection until next send
		// queue iteration. A connection attempt counts as an error, no send
		// attempts will be performed untill the next round.

		// We must also, to preserve order, postpone the destruction on any connection until
		// the iteration has finished. Broken connections are tagged and destroyed
		// here.
		RRR_LL_ITERATE_BEGIN(&tcp_connect_data, struct rrr_ip_accept_data);
			if (node->custom_data < 0) {
				RRR_LL_ITERATE_SET_DESTROY();
			}
			node->custom_data = 0;
		RRR_LL_ITERATE_END_CHECK_DESTROY(&tcp_connect_data, 0; rrr_ip_accept_data_close_and_destroy(node));

		uint64_t timeout_limit = rrr_time_get_64() - (data->message_send_timeout_s * 1000000);
		uint64_t send_loop_time_limit = rrr_time_get_64() + (IP_SEND_TIME_LIMIT_MS * 1000);
		int max_iterations = 500;
		int did_do_something = 0;
		int timeout_count = 0;
		int ret_tmp = 0;
		RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_ip_buffer_entry);
			int do_destroy = 0;
			rrr_ip_buffer_entry_lock(node);

			if (data->message_send_timeout_s > 0 && node->send_time > 0 && node->send_time < timeout_limit) {
				timeout_count++;
				do_destroy = 1;
			}
			else if ((ret_tmp = ip_send_message(&do_destroy, data, &tcp_connect_data, &tcp_graylist, node)) != 0) {
				RRR_MSG_0("Error while iterating input buffer in ip instance %s\n", INSTANCE_D_NAME(thread_data));
				RRR_LL_ITERATE_LAST();
			}

			if (--max_iterations == 0 || rrr_time_get_64() > send_loop_time_limit) {
				RRR_LL_ITERATE_LAST();
			}

			if (do_destroy) {
				RRR_LL_ITERATE_SET_DESTROY();
				did_do_something = 1;
			}
			else {
				rrr_ip_buffer_entry_unlock(node);
			}
		RRR_LL_ITERATE_END_CHECK_DESTROY(&data->send_buffer, 0; rrr_ip_buffer_entry_decref_while_locked_and_unlock(node));

		if (timeout_count > 0) {
			RRR_MSG_0("Send timeout for %i messages in ip instance %s\n",
					timeout_count, INSTANCE_D_NAME(thread_data));
		}

		if (ret_tmp != 0) {
			RRR_MSG_ERR("Error while sending messages in ip instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		if (RRR_LL_COUNT(&data->definitions) > 0) {
			if (udp_read_data(data) != 0) {
				RRR_MSG_ERR("Error while reading udp data in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
			if (tcp_read_data(data, &tcp_accept_data) != 0) {
				RRR_MSG_ERR("Error while reading tcp data in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}

		// Sleep if nothing happened
		if (prev_read_count == data->messages_count_read &&
			prev_polled_count == data->messages_count_polled &&
			prev_read_error_count == data->read_error_count &&
			did_do_something == 0
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

		if (stats != NULL && time_now > next_stats_time) {
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

			rrr_stats_instance_update_rate(stats, 1, "read_error_count", data->read_error_count);
			rrr_stats_instance_update_rate(stats, 2, "read_count", data->messages_count_read);
			rrr_stats_instance_update_rate(stats, 3, "polled_count", data->messages_count_polled);
			rrr_stats_instance_post_unsigned_base10_text (
					stats,
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
			RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_ip_buffer_entry);
				struct rrr_message *message = node->message;

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
//	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	RRR_STATS_INSTANCE_CLEANUP_WITH_PTHREAD_CLEANUP_POP;
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct ip_data data;
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
	thread_entry_ip,
	NULL,
	test_config,
	inject,
	NULL
};

static const char *module_name = "ip";

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


