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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <event2/event.h>

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
#include "../lib/util/gnu.h"
#include "../lib/ip/ip.h"
#include "../lib/ip/ip_util.h"
#include "../lib/socket/rrr_socket_common.h"
#include "../lib/socket/rrr_socket_client.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/ip/ip_accept_data.h"

#define IP_DEFAULT_PORT                    2222
#define IP_DEFAULT_PROTOCOL                RRR_IP_UDP
#define IP_SEND_TIME_LIMIT_MS              1000
#define IP_RECEIVE_TIME_LIMIT_MS           1000
#define IP_DEFAULT_MAX_MESSAGE_SIZE        4096
#define IP_DEFAULT_GRAYLIST_TIMEOUT_MS     2000
#define IP_DEFAULT_CLOSE_GRACE_MS          5

enum ip_action {
	IP_ACTION_RETRY,
	IP_ACTION_DROP,
	IP_ACTION_RETURN
};

struct ip_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_msg_holder_collection send_buffer;

	struct event *event_send_buffer_iterate;

	struct rrr_socket_client_collection *collection;

	int ip_udp_send_fd;

	struct rrr_ip_graylist tcp_graylist;

	struct rrr_read_session_collection read_sessions_udp;
	struct rrr_read_session_collection read_sessions_tcp;

	struct rrr_array_tree *definitions;

	int do_strip_array_separators;
	int do_smart_timeout;
	int do_sync_byte_by_byte;
	int do_send_rrr_msg_msg;
	int do_force_target;
	int do_extract_rrr_messages;
	int do_preserve_order;
	int do_persistent_connections; // TODO : Implement
	int do_multiple_per_connection; // TODO : Implement

	rrr_setting_uint close_grace_ms;

	char *timeout_action_str;
	enum ip_action timeout_action;

	rrr_setting_uint graylist_timeout_ms;
	rrr_setting_uint message_send_timeout_s;
	rrr_setting_uint message_ttl_us;
	rrr_setting_uint message_max_size;

	unsigned int source_udp_port;
	unsigned int source_tcp_port;

	ssize_t default_topic_length;
	char *default_topic;

	char *target_host;
	unsigned int target_port;
	char *target_host_and_port;
	int target_protocol;

	struct rrr_map array_send_tags;

	uint64_t messages_count_read;
	uint64_t messages_count_polled;
	uint64_t read_error_count;
};

static void ip_data_cleanup(void *arg) {
	struct ip_data *data = (struct ip_data *) arg;

	if (data->collection != NULL) {
		rrr_socket_client_collection_destroy(data->collection);
	}
	if (data->event_send_buffer_iterate != NULL) {
		event_free(data->event_send_buffer_iterate);
	}
	rrr_msg_holder_collection_clear(&data->send_buffer);
	if (data->definitions != NULL) {
		rrr_array_tree_destroy(data->definitions);
	}
	rrr_read_session_collection_clear(&data->read_sessions_udp);
	rrr_read_session_collection_clear(&data->read_sessions_tcp);
	RRR_FREE_IF_NOT_NULL(data->default_topic);
	RRR_FREE_IF_NOT_NULL(data->target_host);
	RRR_FREE_IF_NOT_NULL(data->target_host_and_port);
	RRR_FREE_IF_NOT_NULL(data->timeout_action_str);
	rrr_map_clear(&data->array_send_tags);
	rrr_ip_graylist_clear(&data->tcp_graylist);
}

static int ip_data_init(struct ip_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

struct ip_private_data {
	int dummy;
};

static int ip_private_data_new (void **result, int fd, void *arg) {
	(void)(fd);
	(void)(arg);

	*result = NULL;

	struct ip_private_data *private_data = malloc(sizeof(*private_data));
	if (private_data == NULL) {
		RRR_MSG_0("Failed to allocate memory in ip_private_data_new\n");
		return 1;
	}

	memset(private_data, '\0', sizeof(*private_data));

	*result = private_data;

	return 0;
}

static void ip_private_data_destroy (void *private_data) {
	free(private_data);
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

	if (data->target_port > 0) {
		if (rrr_asprintf(&data->target_host_and_port, "%s:%u", data->target_host, data->target_port) <= 0) {
			RRR_MSG_0("Failed to allocate target:port string in ip instance %s\n", config->name);
			ret = 1;
			goto out;
		}
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
		RRR_MSG_0("ip_input_types was set but ip_tcp_port and/or ip_udp_port was not, this is an invalid configuration in ip instance %s\n", config->name);
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

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_smart_timeout", do_smart_timeout, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_graylist_timeout_ms", graylist_timeout_ms, IP_DEFAULT_GRAYLIST_TIMEOUT_MS);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_sync_byte_by_byte", do_sync_byte_by_byte, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_send_rrr_message", do_send_rrr_msg_msg, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_force_target", do_force_target, 0);

	if (data->do_force_target == 1 && data->target_port == 0) {
		RRR_MSG_0("ip_force_target was set to yes but no target was specified in ip_target_host and ip_target_port in ip instance %s\n",
				config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_strip_array_separators", do_strip_array_separators, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_extract_rrr_messages", do_extract_rrr_messages, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_preserve_order", do_preserve_order, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_persistent_connections", do_persistent_connections, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_send_multiple_per_connection", do_multiple_per_connection, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_close_grace_ms", close_grace_ms, IP_DEFAULT_CLOSE_GRACE_MS);

	if (data->do_strip_array_separators && data->definitions == NULL) {
		RRR_MSG_0("ip_strip_array_separators was 'yes' while no array definition was set in ip_input_types in ip instance %s, this is a configuration error.\n",
				config->name);
		ret = 1;
		goto out;
	}

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

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_ttl_seconds", message_ttl_us, 0);
	data->message_ttl_us *= 1000LLU * 1000LLU;

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

static int ip_read_receive_message (
		struct rrr_msg_holder_collection *new_entries,
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

	RRR_DBG_2("ip instance %s created a message with timestamp %llu size %lu\n",
			INSTANCE_D_NAME(data->thread_data), (long long unsigned int) message->timestamp, (long unsigned int) sizeof(*message));

	// Now managed by ip buffer entry
	message = NULL;

	rrr_msg_holder_incref_while_locked(new_entry);
	RRR_LL_APPEND(new_entries, new_entry);

	data->messages_count_read++;

	out:
	rrr_msg_holder_decref_while_locked_and_unlock(new_entry);
	if (message != NULL) {
		free(message);
	}
	return ret;
}

static int ip_read_data_receive_extract_messages (
		struct rrr_msg_holder_collection *new_entries,
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
			if ((ret = ip_read_receive_message(new_entries, data, entry_orig, message_new)) != 0) {
				goto out;
			}

			found_messages++;
		}
	RRR_LL_ITERATE_END();

	RRR_DBG_2("ip instance %s extracted %i RRR messages from an array\n",
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
	struct ip_data *data;
	struct rrr_array *array_final;
	struct rrr_read_session *read_session;
	struct rrr_msg_holder_collection new_entries;
};

static int ip_array_callback_broker (struct rrr_msg_holder *entry, void *arg) {
	struct ip_read_array_callback_data *callback_data = arg;

	// Note that the provided entry is never saved, we add all new entries to the collection in callback data

	int ret = 0;

	int protocol = 0;

	switch (callback_data->read_session->socket_options) {
		case SOCK_DGRAM:
			protocol = RRR_IP_UDP;
			break;
		case SOCK_STREAM:
			protocol = RRR_IP_TCP;
			break;
		default:
			RRR_MSG_0("Unknown SO_TYPE %i in __ip_receive_callback\n", callback_data->read_session->socket_options);
			ret = 1;
			goto out;
	}

	rrr_msg_holder_set_unlocked (
			entry,
			NULL,
			0,
			(const struct sockaddr *) &callback_data->read_session->src_addr,
			callback_data->read_session->src_addr_len,
			protocol
	);

	if (callback_data->data->do_extract_rrr_messages) {
		if ((ret = ip_read_data_receive_extract_messages (
				&callback_data->new_entries,
				callback_data->data,
				entry,
				callback_data->array_final
		)) != 0) {
			goto out;
		}
	}
	else {
		struct rrr_msg_msg *message_new = NULL;

		if (callback_data->data->do_strip_array_separators) {
			rrr_array_strip_type(callback_data->array_final, &rrr_type_definition_sep);
		}

		if ((ret = rrr_array_new_message_from_collection (
				&message_new,
				callback_data->array_final,
				rrr_time_get_64(),
				callback_data->data->default_topic,
				callback_data->data->default_topic_length
		)) != 0) {
			goto out;
		}

		// Guarantees to free message also upon errors
		if ((ret = ip_read_receive_message (
				&callback_data->new_entries,
				callback_data->data,
				entry,
				message_new
		)) != 0) {
			goto out;
		}
	}

	out:
	rrr_msg_holder_unlock(entry);
	return ret | RRR_MESSAGE_BROKER_DROP;
}

static int ip_array_callback (
		struct rrr_read_session *read_session,
		struct rrr_array *array_final,
		void *private_data,
		void *arg
) {
	struct ip_data *data = arg;

	(void)(private_data);

	int ret = 0;

	struct ip_read_array_callback_data callback_data = {
			data,
			array_final,
			read_session,
			{0}
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			ip_array_callback_broker,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Error while writing entries to broker while reading in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if ((ret = rrr_message_broker_write_entries_from_collection_unsafe (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			&callback_data.new_entries,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		goto out;
	}

	out:
	rrr_msg_holder_collection_clear(&callback_data.new_entries);
	return ret;
}

/*
static int ip_tcp_read_data (
		struct ip_data *data,
		struct rrr_ip_data *listen_data,
		struct rrr_ip_accept_data_collection *accept_data_collection,
		uint64_t end_time
) {
	int ret = 0;
	if (data->source_tcp_port == 0) {
		goto out;
	}

	struct rrr_ip_accept_data *accept_data = NULL;

	if (rrr_ip_accept (
			&accept_data,
			listen_data,
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
		if ((ret = ip_read_loop (data, 1, node->ip_data.fd, &data->read_sessions_tcp, end_time)) != 0) {
			if (ret == RRR_SOCKET_SOFT_ERROR || ret == RRR_READ_EOF) {
				RRR_DBG_1("Closing tcp connection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
				RRR_LL_ITERATE_SET_DESTROY();
				ret = 0;
			}
			else {
				RRR_DBG_1("Error %i while reading TCP data in ip instance %s\n", ret, INSTANCE_D_NAME(data->thread_data));
				RRR_LL_ITERATE_LAST();
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(accept_data_collection, 0; rrr_ip_accept_data_close_and_destroy(node));

	out:
	return ret;
}
static int ip_udp_read_data (
		struct ip_data *data,
		uint64_t end_time
) {
	int ret = 0;

	if (data->source_udp_port > 0) {
		if (data->ip_udp_4.fd != 0 && (ret = ip_read_loop (data, 0, data->ip_udp_4.fd, &data->read_sessions_udp, end_time)) != 0) {
			goto out;
		}
		if (data->ip_udp_6.fd != 0 && (ret = ip_read_loop (data, 0, data->ip_udp_6.fd, &data->read_sessions_udp, end_time)) != 0) {
			goto out;
		}
	}

	out:
	return ret;
}
*/
static int ip_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct ip_data *ip_data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	RRR_DBG_2 ("ip instance %s result from buffer timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp);

	entry->send_time = 0;
	entry->bytes_sent = 0;

	rrr_msg_holder_incref_while_locked(entry);
	RRR_LL_APPEND(&ip_data->send_buffer, entry);

	rrr_msg_holder_unlock(entry);

	event_active(ip_data->event_send_buffer_iterate, 0, 0);

	return 0;
}

static int ip_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	(void)(flags);

	return rrr_poll_do_poll_delete (amount, thread_data, ip_poll_callback, 0);
}

struct ip_resolve_suggestion_callback_data {
	struct ip_data *ip_data;
	size_t address_count;
	struct sockaddr **addresses;
	socklen_t *address_lengths;
};

static int ip_resolve_suggestion_callback (
		const char *host,
		unsigned int port,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *arg
) {
	struct ip_resolve_suggestion_callback_data *callback_data = arg;

	int ret = 0;

	if (RRR_DEBUGLEVEL_7) {
		char buf[256];
		*buf = '\0';
		rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);
		RRR_DBG_7("ip instance %s resolve[%llu] %s:%u => [%s]\n",
				INSTANCE_D_NAME(callback_data->ip_data->thread_data),
				(long long unsigned int) callback_data->address_count,
				host,
				port,
				buf
		);
	}

	{
		struct sockaddr **addresses_new = realloc(callback_data->addresses, sizeof(void *) * callback_data->address_count + 1);
		if (addresses_new == NULL) {
			RRR_MSG_0("Failed to allocate memory in ip_resolve_suggestion_callback A\n");
			ret = 1;
			goto out;
		}
		callback_data->addresses = addresses_new;
	}

	{
		socklen_t *address_lengths_new = realloc(callback_data->address_lengths, sizeof(void *) * callback_data->address_count + 1);
		if (address_lengths_new == NULL) {
			RRR_MSG_0("Failed to allocate memory in ip_resolve_suggestion_callback B\n");
			ret = 1;
			goto out;
			
		}
		callback_data->address_lengths = address_lengths_new;
	}

	if ((callback_data->addresses[callback_data->address_count] = (struct sockaddr *) malloc(sizeof(struct sockaddr_storage))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in ip_resolve_suggestion_callback C\n");
		ret = 1;
		goto out;
	}

	memcpy(callback_data->addresses[callback_data->address_count], addr, addr_len);
	callback_data->address_lengths[callback_data->address_count] = addr_len;

	callback_data->address_count++;

	out:
	return ret;
}

struct ip_resolve_callback_data {
	struct ip_data *ip_data;
	const char *host;
	unsigned int port;
};

static int ip_resolve_callback (
		size_t *address_count,
		struct sockaddr ***addresses,
		socklen_t **address_lengths,
		void *arg
) {
	int ret = 0;

	struct ip_resolve_callback_data *callback_data = arg;

	struct ip_resolve_suggestion_callback_data suggestion_callback_data = {
		callback_data->ip_data,
		0,
		NULL,
		NULL
	};

	if ((ret = rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
			callback_data->port,
			callback_data->host,
			ip_resolve_suggestion_callback,
			&suggestion_callback_data
	)) != 0) {
		goto out;
	}

	*address_count = suggestion_callback_data.address_count;
	*addresses = suggestion_callback_data.addresses;
	*address_lengths = suggestion_callback_data.address_lengths;

	address_count = 0;
	addresses = NULL;
	address_lengths = NULL;

	out:
	for (size_t i = 0; i < suggestion_callback_data.address_count; i++) {
		free(suggestion_callback_data.addresses[i]);
	}
	RRR_FREE_IF_NOT_NULL(suggestion_callback_data.addresses);
	RRR_FREE_IF_NOT_NULL(suggestion_callback_data.address_lengths);
	return ret;
}

static int ip_connect_raw_callback (
		int *fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *callback_data
) {
	struct ip_data *ip_data = callback_data;
	
	int ret = 0;

	if ((ret = rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw_nonblock (
			fd,
			addr,
			addr_len,
			&ip_data->tcp_graylist
	)) != 0) {
		if (ret == RRR_SOCKET_SOFT_ERROR) {
			RRR_DBG_7("Could not connect with TCP to remote %s port %u in ip instance %s, postponing send\n",
					ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(ip_data->thread_data));
		}
		else {
			RRR_MSG_0("Hard error during TCP connect in ip instance %s\n", INSTANCE_D_NAME(ip_data->thread_data));
		}
		goto out;
	}

	out:
	return ret;
}

struct ip_resolve_sendto_callback_data {
	struct ip_data *ip_data;
	int fd;
	const void *send_data;
	ssize_t send_size;
	struct rrr_msg_holder *entry_orig;
};

static int ip_resolve_sendto_callback (
		const char *host,
		unsigned int port,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *arg
) {
	int ret = 0;

	struct ip_resolve_sendto_callback_data *callback_data = arg;

	const char *dummy_data = "";

	char buf[256];
	*buf = '\0';
	rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);

	// Test send to validate address
	if ((ret = sendto(callback_data->fd, dummy_data, 0, 0, addr, addr_len)) != 0) {
		RRR_DBG_7("ip instance %s resolve %s:%u => [%s] (sendto) failed: %s\n",
				INSTANCE_D_NAME(callback_data->ip_data->thread_data),
				host,
				port,
				buf,
				rrr_strerror(errno)
		);
		// Try next suggestion
		ret = 0;
		goto out;
	}

	RRR_DBG_7("ip instance %s resolve %s:%u => [%s] (sendto)\n",
			INSTANCE_D_NAME(callback_data->ip_data->thread_data),
			host,
			port,
			buf
	);

	if ((ret = rrr_socket_client_collection_sendto_push_const (
			callback_data->ip_data->collection,
			callback_data->fd,
			addr,
			addr_len,
			callback_data->send_data,
			callback_data->send_size,
			callback_data->entry_orig,
			rrr_msg_holder_decref_void
	)) == 0) {
		// EOF breaks out from resolve iteration and indicates success
		rrr_msg_holder_incref_while_locked(callback_data->entry_orig);
		ret = RRR_SOCKET_READ_EOF;
	}
	else {
		RRR_MSG_0("Failed to push send data in ip_resolve_sendto_callback of ip instance %s\n",
				INSTANCE_D_NAME(callback_data->ip_data->thread_data));
	}

	out:
	return ret;
}

static int ip_send_message_raw_default_target (
		struct ip_data *ip_data,
		struct rrr_msg_holder *entry_orig,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	int ret = 0;

	if (ip_data->target_port == 0) {
		RRR_MSG_0("Warning: A message from a sender in ip instance %s had no address information and we have no default remote host set, dropping it\n",
				INSTANCE_D_NAME(thread_data));
		goto out;
	}

	if (ip_data->target_protocol == RRR_IP_TCP) {
		struct ip_resolve_callback_data resolve_callback_data = {
			ip_data,
			ip_data->target_host,
			ip_data->target_port
		};
		if ((ret = rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
				ip_data->collection,
				ip_data->target_host_and_port,
				send_data,
				send_size,
				entry_orig,
				rrr_msg_holder_decref_void,
				ip_resolve_callback,
				&resolve_callback_data,
				ip_connect_raw_callback,
				ip_data
		)) == 0) {
			rrr_msg_holder_incref_while_locked(entry_orig);
		}
	}
	else {
		struct ip_resolve_sendto_callback_data resolve_callback_data = {
			ip_data,
			ip_data->ip_udp_send_fd,
			send_data,
			send_size,
			entry_orig
		};

		if ((ret = rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
				ip_data->target_port,
				ip_data->target_host,
				ip_resolve_sendto_callback,
				&resolve_callback_data
		)) != RRR_SOCKET_READ_EOF) {
			RRR_MSG_0("Error while sending message to default remote %s:%u using UDP in ip instance %s\n",
					ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(ip_data->thread_data));
		}
		else if (ret == 0) {
			// No address suggestions could be used
			RRR_MSG_0("Error while sending message to default remote %s:%u using UDP in ip instance %s, no resolve suggestions could be used\n",
					ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(ip_data->thread_data));
			ret = RRR_SOCKET_SOFT_ERROR;
		}
	}

	out:
		return ret;
}

static int ip_send_raw (
		struct ip_data *ip_data,
		struct rrr_msg_holder *entry_orig,
		int protocol,
		const void *send_data,
		ssize_t send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	// If no translation is needed, the original address is copied
	rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed(&addr, &addr_len, (const struct sockaddr *) &entry_orig->addr, entry_orig->addr_len);
	
	int ret = 0;

	if (send_size == 0) {
		goto out;
	}
	if (send_size <= 0) {
		RRR_BUG("BUG: Send size was < 0 in ip_send_raw\n");
	}

	// Configuration validation should produce an error if do_force_target is set
	// but no target_port/target_host
	if (ip_data->do_force_target == 1 || addr_len == 0) {
		//////////////////////////////////////////////////////
		// FORCED TARGET OR NO ADDRESS IN ENTRY, TCP OR UDP
		//////////////////////////////////////////////////////

		ret = ip_send_message_raw_default_target (
				ip_data,
				entry_orig,
				send_data,
				send_size
		);
	}
	else if (protocol == RRR_IP_TCP) {
		//////////////////////////////////////////////////////
		// ADDRESS FROM ENTRY, TCP
		//////////////////////////////////////////////////////

		if ((ret = rrr_socket_client_collection_send_push_const_by_address_connect_as_needed (
				ip_data->collection,
				(const struct sockaddr *) &addr,
				addr_len,
				send_data,
				send_size,
				entry_orig,
				rrr_msg_holder_decref_void,
				ip_connect_raw_callback,
				ip_data
		)) == 0) {
			rrr_msg_holder_incref_while_locked(entry_orig);
		}
	}
	else {
		//////////////////////////////////////////////////////
		// ADDRESS FROM ENTRY, UDP
		//////////////////////////////////////////////////////

		if ((ret = rrr_socket_client_collection_sendto_push_const (
				ip_data->collection,
				ip_data->ip_udp_send_fd,
				(const struct sockaddr *) &addr,
				addr_len,
				send_data,
				send_size,
				entry_orig,
				rrr_msg_holder_decref_void
		)) == 0) {
			rrr_msg_holder_incref_while_locked(entry_orig);
		}
	}

	if (ret != 0) {
		RRR_MSG_0("Failed to push message to send queue in ip instance %s\n",
				INSTANCE_D_NAME(thread_data)
		);
		goto out;
	}

	//////////////////////////////////////////////////////
	// OUT
	//////////////////////////////////////////////////////

	out:
	return ret;
}

static int ip_send_message (
		struct ip_data *ip_data,
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
		if (entry->endian_indicator != 0) {
			final_size = entry->bytes_to_send;

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

			entry->endian_indicator = 1;
		}

		send_data = message;
		send_size = final_size;
	}
	else if (MSG_IS_ARRAY(message)) {
		int tag_count = RRR_MAP_COUNT(&ip_data->array_send_tags);

		uint16_t array_version_dummy;
		if (rrr_array_message_append_to_collection(&array_version_dummy, &array_tmp, message) != 0) {
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

	ssize_t written_bytes = 0;

	ret = ip_send_raw (
			ip_data,
			entry,
			entry->protocol,
			send_data + entry->bytes_sent,
			send_size - entry->bytes_sent
	);

	entry->bytes_to_send = send_size;
	entry->bytes_sent += written_bytes;

	RRR_DBG_7("ip instance %s send status for entry: %li/%li bytes\n",
			INSTANCE_D_NAME(ip_data->thread_data), entry->bytes_sent, entry->bytes_to_send);

	if (entry->bytes_sent == entry->bytes_to_send) {
		RRR_DBG_2("ip instance %s a message of %li bytes was completely sent\n",
				INSTANCE_D_NAME(ip_data->thread_data), entry->bytes_to_send);
	}

	out:
		RRR_FREE_IF_NOT_NULL(tmp_data);
		rrr_array_clear(&array_tmp);
		return ret;
}
/*

static int ip_preserve_order_list_push (
		struct rrr_msg_holder_collection *collection,
		const struct rrr_msg_holder *template
) {
	struct rrr_msg_holder *new_entry = NULL;

	if (rrr_msg_holder_clone_no_data(&new_entry, template) != 0) {
		return 1;
	}

	RRR_LL_PUSH(collection, new_entry);

	return 0;
}

static int ip_preserve_order_list_has (
		struct rrr_msg_holder_collection *collection,
		const struct rrr_msg_holder *template
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_msg_holder);
		if (rrr_msg_holder_address_matches(template, node)) {
				return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

static void ip_preserve_order_list_clear (
		struct rrr_msg_holder_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_msg_holder, rrr_msg_holder_decref(node));
}

*/
static int ip_send_loop (
		struct ip_data *data
) {
	int ret = 0;

//	struct rrr_msg_holder_collection preserve_order_list = {0};

	if (data->do_preserve_order) {
		rrr_msg_holder_collection_sort(&data->send_buffer, rrr_msg_msg_timestamp_compare_void);
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
	int ttl_reached_count = 0;
	RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_msg_holder);
		enum ip_action action = IP_ACTION_RETRY;

		if (--max_iterations == 0 || rrr_time_get_64() > send_loop_time_limit) {
			RRR_LL_ITERATE_LAST();
		}

		// Send time must be set prior to preserve order check to allow timer to start

		rrr_msg_holder_lock(node);

		int message_was_sent = 1;
		int timeout_reached = 0;

		if (data->message_ttl_us > 0 && !rrr_msg_msg_ttl_ok(node->message, data->message_ttl_us)) {
			ttl_reached_count++;
			RRR_DBG_1("TTL expired for a message after %" PRIrrrbl " seconds in ip instance %s, dropping it.\n",
					data->message_ttl_us / 1000 / 1000, INSTANCE_D_NAME(data->thread_data));
			action = IP_ACTION_DROP;
			goto perform_action;
		}
		else if (data->message_send_timeout_s > 0 && node->send_time > 0 && node->send_time < timeout_limit) {
			timeout_count++;
			RRR_DBG_1("Message timed out after %" PRIrrrbl " seconds in ip instance %s, performing timeout action %s.\n",
					data->message_send_timeout_s, INSTANCE_D_NAME(data->thread_data), data->timeout_action_str);
			timeout_reached = 1;
			goto perform_timeout_action;
		}
/*		else if (data->do_preserve_order && ip_preserve_order_list_has(&preserve_order_list, node)) {
			// If another message to the same destaination blocks our send, make sure send_time is initialized
			if (node->send_time == 0) {
				node->send_time = rrr_time_get_64();
			}
			action = IP_ACTION_RETRY;
			goto perform_action;
		}*/

		ssize_t bytes_sent_orig = node->bytes_sent;

		if ((ret = ip_send_message(data, node)) != 0) {
			if (ret == RRR_SOCKET_SOFT_ERROR) {
				message_was_sent = 0;
				ret = 0;
			}
			else {
				RRR_MSG_0("Error while iterating input buffer in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
				RRR_LL_ITERATE_LAST();
			}
		}

		if (node->bytes_sent < node->bytes_to_send) {
			message_was_sent = 0;
		}

		if (node->send_time == 0 || bytes_sent_orig != node->bytes_sent || message_was_sent) {
			node->send_time = rrr_time_get_64();
		}

//		printf("Sent for %p: %li/%li\n", node, node->bytes_sent, node->bytes_to_send);

		if (message_was_sent) {
			if (data->do_smart_timeout) {
				const struct rrr_msg_holder *node_orig = node;
				RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_msg_holder);
					if (node == node_orig) {
						RRR_LL_ITERATE_NEXT();
					}
					rrr_msg_holder_lock(node);
					if (	data->do_force_target == 1 ||
							rrr_msg_holder_address_matches(node, node_orig)
					) {
						node->send_time = node_orig->send_time;
					}
					rrr_msg_holder_unlock(node);
				RRR_LL_ITERATE_END();
			}
			action = IP_ACTION_DROP;
		}
/*		else {
			if (data->do_preserve_order) {
				if ((ret = ip_preserve_order_list_push(&preserve_order_list, node)) != 0) {
					RRR_MSG_0("Failed to add entry to preserve order list in ip_send_loop\n");
					RRR_LL_ITERATE_LAST();
					goto perform_action;
				}
			}
		}*/

		// Timeout overrides retry. Note that the configuration parser should check that
		// default action is not retry while send_timeout is >0, would otherwise cause us
		// to spam timed out messages. We do not reset the send_time in the entry.
		perform_timeout_action:
		if (timeout_reached) {
			action = data->timeout_action;
		}

//		printf("Node send time: %" PRIu64 "\n", node->send_time);
//		printf("Timeout action: %i, send status: %i\n", action, message_was_sent);

		// Make sure we always unlock, ether in ITERATE_END destroy or here if we
		// do not destroy
		perform_action:
		if (ret != 0 || action == IP_ACTION_RETRY) {
			rrr_msg_holder_unlock(node);
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();

			if (action == IP_ACTION_RETURN) {
				if (node->endian_indicator != 0) {
					if (rrr_msg_head_to_host_and_verify(node->message, node->data_length) != 0 ||
						rrr_msg_msg_to_host_and_verify(node->message, node->data_length) != 0
					) {
						RRR_BUG("BUG: Message endian reversion failed in ip_send_loop\n");
					}
					node->endian_indicator = 0;
				}

				if ((ret = rrr_message_broker_incref_and_write_entry_unsafe_no_unlock (
						INSTANCE_D_BROKER_ARGS(data->thread_data),
						node,
						INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
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

	if (ret != 0) {
		RRR_MSG_0("Error while sending messages in ip instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	if (timeout_count > 0) {
		RRR_MSG_0("Send timeout for %i messages in ip instance %s\n",
				timeout_count, INSTANCE_D_NAME(data->thread_data));
	}
	if (ttl_reached_count > 0) {
		RRR_MSG_0("TTL reached for %i messages in ip instance %s, they have been dropped.\n",
				ttl_reached_count, INSTANCE_D_NAME(data->thread_data));
	}

	out:
//	ip_preserve_order_list_clear(&preserve_order_list);
	return ret;
}

static int ip_start_udp (struct ip_data *data) {
	int ret = 0;

	struct rrr_ip_data ip_udp_6 = {0};
	struct rrr_ip_data ip_udp_4 = {0};

	ip_udp_6.port = data->source_udp_port;
	ip_udp_4.port = data->source_udp_port;

	if ((ret = rrr_socket_client_collection_new(&data->collection, INSTANCE_D_NAME(data->thread_data))) != 0) {
		RRR_MSG_0("Failed to create UDP client collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	rrr_socket_client_collection_event_setup_array_tree (
			data->collection,
			INSTANCE_D_EVENTS(data->thread_data),
			ip_private_data_new,
			ip_private_data_destroy,
			data,
			RRR_SOCKET_READ_METHOD_RECVFROM | RRR_SOCKET_READ_CHECK_POLLHUP,
			data->definitions,
			data->do_sync_byte_by_byte,
			4096,
			0, // No message max size
			ip_array_callback,
			data
	);

	if (data->source_udp_port == 0) {
		int ret_4, ret_6 = 0;

		if ((ret_6 = rrr_ip_network_start_udp_nobind(&ip_udp_6, 1)) != 0) {
			RRR_DBG_1("Note: Could not initialize UDP IPv6 network in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		}

		if ((ret_4 = rrr_ip_network_start_udp_nobind(&ip_udp_4, 0)) != 0) {
			RRR_DBG_1("Note: Could not initialize UDP IPv4 network in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		}

		if (ret_6 != 0 && ret_4 != 0) {
			RRR_MSG_0("UDP socket creation failed for both IPv4 and IPv6 on port %u in ip instance %s\n",
					data->source_udp_port, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}

		RRR_DBG_1("ip instance %s not bound on any UDP port\n", INSTANCE_D_NAME(data->thread_data));
	}
	else {
		int ret_4, ret_6 = 0;
		if ((ret_6 = rrr_ip_network_start_udp(&ip_udp_6, 1)) != 0) {
			RRR_DBG_1("Note: Could not initialize UDP IPv6 network in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		}
		else {
			RRR_DBG_1("ip instance %s listening on and/or sending from UDP port %d IPv6 (possibly dual-stack)\n",
					INSTANCE_D_NAME(data->thread_data), data->source_udp_port);
		}

		if ((ret_4 = rrr_ip_network_start_udp(&ip_udp_4, 0)) != 0) {
			RRR_DBG_1("Note: Could not initialize UDP IPv4 network in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		}
		else {
			RRR_DBG_1("ip instance %s listening on and/or sending from UDP port %d IPv4\n",
					INSTANCE_D_NAME(data->thread_data), data->source_udp_port);
		}

		if (ret_6 != 0 && ret_4 != 0) {
			RRR_MSG_0("Bind failed for both IPv4 and IPv6 on port %u in ip instance %s\n",
					data->source_udp_port, INSTANCE_D_NAME(data->thread_data));
			ret = 1;
			goto out;
		}
		else if (ret_6) {
			RRR_DBG_1("Note: Bind failed for IPv6 on port %u, but IPv4 listening succedded in ip instance %s. Assuming IPv4-only stack.\n",
					data->source_udp_port, INSTANCE_D_NAME(data->thread_data));
		}
		else if (ret_4) {
			RRR_DBG_1("Note: Bind failed for IPv4 on port %u, but IPv6 listening succedded in ip instance %s. Assuming dual-stack.\n",
					data->source_udp_port, INSTANCE_D_NAME(data->thread_data));
		}
	}

	data->ip_udp_send_fd = ip_udp_6.fd != 0 ? ip_udp_6.fd : ip_udp_4.fd;

	if (ip_udp_6.fd != 0) {
		if ((ret = rrr_socket_client_collection_connected_fd_push(data->collection, ip_udp_6.fd)) != 0) {
			RRR_MSG_0("Failed to push UDP IPv6 fd to collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		ip_udp_6.fd = 0;
	}

	if (ip_udp_4.fd != 0) {
		if ((ret = rrr_socket_client_collection_connected_fd_push(data->collection, ip_udp_4.fd)) != 0) {
			RRR_MSG_0("Failed to push UDP IPv4 fd to collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		ip_udp_4.fd = 0;
	}

	goto out;
	out:
		rrr_ip_network_cleanup(&ip_udp_6);
		rrr_ip_network_cleanup(&ip_udp_4);
		return ret;
}

static int ip_start_tcp (struct ip_data *data) {
	int ret = 0;

	struct rrr_ip_data ip_tcp_listen_4 = {0};
	struct rrr_ip_data ip_tcp_listen_6 = {0};

	if (data->source_tcp_port == 0) {
		goto out;
	}

	ip_tcp_listen_4.port = data->source_tcp_port;
	ip_tcp_listen_6.port = data->source_tcp_port;

	int ret_4, ret_6 = 0;

	if ((ret_6 = rrr_ip_network_start_tcp(&ip_tcp_listen_6, 10, 1)) != 0) {
		RRR_DBG_1("Note: Could not initialize TCP IPv6 network in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
	}
	else {
		RRR_DBG_1("ip instance %s listening on IPv6 (possibly dual-stack) TCP port %d\n",
				INSTANCE_D_NAME(data->thread_data), data->source_tcp_port);
	}

	if ((ret_4 = rrr_ip_network_start_tcp(&ip_tcp_listen_4, 10, 0)) != 0) {
		RRR_DBG_1("Note: Could not initialize TCP IPv4 network in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
	}
	else {
		RRR_DBG_1("ip instance %s listening on IPv4 TCP port %d\n",
				INSTANCE_D_NAME(data->thread_data), data->source_tcp_port);
	}

	if (ret_6 != 0 && ret_4 != 0) {
		RRR_MSG_0("Listening failed for both IPv4 and IPv6 on port %u in ip instance %s\n",
				data->source_tcp_port, INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}
	else if (ret_6) {
		RRR_DBG_1("Note: Listening failed for IPv6 on port %u, but IPv4 listening succedded in ip instance %s. Assuming IPv4-only stack.\n",
				data->source_tcp_port, INSTANCE_D_NAME(data->thread_data));
	}
	else if (ret_4) {
		RRR_DBG_1("Note: Listening failed for IPv4 on port %u, but IPv6 listening succedded in ip instance %s. Assuming dual-stack.\n",
				data->source_tcp_port, INSTANCE_D_NAME(data->thread_data));
	}

	if (ip_tcp_listen_6.fd != 0) {
		if ((ret = rrr_socket_client_collection_listen_fd_push(data->collection, ip_tcp_listen_6.fd)) != 0) {
			RRR_MSG_0("Failed to push TCP IPv6 fd to collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		ip_tcp_listen_6.fd = 0;
	}

	if (ip_tcp_listen_4.fd != 0) {
		if ((ret = rrr_socket_client_collection_listen_fd_push(data->collection, ip_tcp_listen_4.fd)) != 0) {
			RRR_MSG_0("Failed to push TCP IPv4 fd to collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		ip_tcp_listen_4.fd = 0;
	}

	out:
	rrr_ip_network_cleanup(&ip_tcp_listen_6);
	rrr_ip_network_cleanup(&ip_tcp_listen_4);
	return ret;
}

static void ip_event_send_buffer (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct ip_data *ip_data = arg;

	(void)(fd);
	(void)(flags);

	if (ip_send_loop(ip_data) != 0) {
		event_base_loopbreak (
			rrr_event_queue_base_get(INSTANCE_D_EVENTS(ip_data->thread_data))
		);
	}

	if (RRR_LL_COUNT(&ip_data->send_buffer) > 0) {
		// Short wait
		struct timeval tv = {0, 10 * 1000}; // 10 ms
		event_add(ip_data->event_send_buffer_iterate, &tv);
	}
}
		
static int ip_function_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ip_data *ip_data = thread_data->private_data;

	int ret = 0;

	if (rrr_thread_signal_encourage_stop_check(thread)) {
		return RRR_EVENT_EXIT;
	}
	rrr_thread_watchdog_time_update(thread);

	if (RRR_LL_COUNT(&ip_data->send_buffer) > 0) {
		event_active(ip_data->event_send_buffer_iterate, 0, 0);
	}

	return ret;
}

static void *thread_entry_ip (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct ip_data *data = thread_data->private_data = thread_data->private_memory;

	if (ip_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in ip instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("ip thread data is %p\n", thread_data);

	pthread_cleanup_push(ip_data_cleanup, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if ((data->event_send_buffer_iterate = event_new (
			rrr_event_queue_base_get(INSTANCE_D_EVENTS(thread_data)),
			-1,
			EV_TIMEOUT,
			ip_event_send_buffer,
			data
	)) == NULL) {
		RRR_MSG_0("Failed to create send buffer event in ip instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	if (ip_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parsing failed for ip instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	int has_senders = rrr_message_broker_senders_count(INSTANCE_D_BROKER_ARGS(thread_data)) > 0 ? 1 : 0;

	if (has_senders == 0 && data->definitions == NULL) {
		RRR_MSG_0("Error: ip instance %s has no senders defined and also has no array definition. Cannot do anything with this configuration.\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_ip_graylist_init(&data->tcp_graylist, data->graylist_timeout_ms * 1000LLU);

	if (ip_start_udp(data) != 0) {
		goto out_message;
	}

	if (ip_start_tcp(data) != 0) {
		goto out_message;
	}

	rrr_event_dispatch (
			INSTANCE_D_EVENTS(thread_data),
			100 * 1000, // 100 ms
			ip_function_periodic,
			thread
	);

/*
	uint64_t prev_read_error_count = 0;
	uint64_t prev_read_count = 0;
	uint64_t prev_polled_count = 0;

	unsigned int consecutive_nothing_happened = 0;
	uint64_t next_stats_time = 0;
	unsigned int tick = 0;
	while (!rrr_thread_signal_encourage_stop_check(thread)) {
		rrr_thread_watchdog_time_update(thread);

//		printf ("IP ticks: %u\n", tick);

		if (has_senders != 0) {
			uint16_t amount = 100;
			if (rrr_poll_do_poll_delete (&amount, thread_data, poll_callback_ip, 0) != 0) {
				RRR_MSG_0("Error while polling in ip instance %s\n",
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

		uint64_t time_now = rrr_time_get_64();

		if (data->definitions != NULL) {
			uint64_t end_time = time_now + (IP_RECEIVE_TIME_LIMIT_MS * 1000);
			if (ip_udp_read_data(data, end_time) != 0) {
				RRR_MSG_0("Error while reading udp data in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
			if (data->ip_tcp_listen_4.fd != 0 && ip_tcp_read_data(data, &data->ip_tcp_listen_4, &tcp_accept_data, end_time) != 0) {
				RRR_MSG_0("Error while reading tcp data on IPv4 in ip instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
			if (data->ip_tcp_listen_6.fd != 0 && ip_tcp_read_data(data, &data->ip_tcp_listen_6, &tcp_accept_data, end_time) != 0) {
				RRR_MSG_0("Error while reading tcp data on IPv6 in ip instance %s\n",
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

		if (INSTANCE_D_STATS(thread_data) != NULL && time_now > next_stats_time) {
			int delivery_entry_count = 0;
			int delivery_ratelimit_active = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&delivery_entry_count,
					&delivery_ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_0("Error while setting ratelimit in ip instance %s\n",
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

			printf ("-- Dump send buffer -----------------------------------\n");
			RRR_LL_ITERATE_BEGIN(&data->send_buffer, struct rrr_msg_msg_holder);
				struct rrr_msg_msg *message = node->message;

				printf ("timestamp %" PRIu64 "\n", (node->send_time > 0 ? be64toh(message->timestamp) : message->timestamp));
			RRR_LL_ITERATE_END();
			printf ("-- Dump send buffer end --------------------------------\n");
		}

		prev_read_error_count = data->read_error_count;
		prev_read_count = data->messages_count_read;
		prev_polled_count = data->messages_count_polled;

		tick++;
	}
*/
	out_message:

	pthread_cleanup_pop(1);

	RRR_DBG_1 ("ip instance %s stopping\n", thread_data->init_data.instance_config->name);

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
	NULL,
	thread_entry_ip,
	NULL,
	NULL,
	NULL
};

struct rrr_instance_event_functions event_functions = {
	ip_event_broker_data_available
};

static const char *module_name = "ip";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_FLEXIBLE;
		data->operations = module_operations;
		data->private_data = NULL;
		data->event_functions = event_functions;
}

void unload(void) {
}

