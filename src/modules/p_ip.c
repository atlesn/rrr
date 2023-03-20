/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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
#include "../lib/allocator.h"
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
#include "../lib/send_loop.h"
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
#include "../lib/socket/rrr_socket_graylist.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/ip/ip_accept_data.h"

#define IP_DEFAULT_PORT                    2222
#define IP_DEFAULT_PROTOCOL                RRR_IP_UDP
#define IP_SEND_TIME_LIMIT_MS              1000
#define IP_RECEIVE_TIME_LIMIT_MS           1000
#define IP_DEFAULT_MAX_MESSAGE_SIZE        4096
#define IP_DEFAULT_GRAYLIST_TIMEOUT_MS     100
#define IP_DEFAULT_CLOSE_GRACE_MS          5
#define IP_DEFAULT_PERSISTENT_TIMEOUT_MS   5000
#define IP_SEND_CHUNK_COUNT_LIMIT          10000

struct ip_data {
	struct rrr_instance_runtime_data *thread_data;
	struct rrr_send_loop *send_loop;

	struct rrr_socket_client_collection *collection_udp;
	struct rrr_socket_client_collection *collection_tcp;

	int udp_send_fd_ip4;
	int udp_send_fd_ip6;

	struct rrr_socket_graylist tcp_graylist;

	struct rrr_array_tree *definitions;

	int do_strip_array_separators;
	int do_smart_timeout;
	int do_sync_byte_by_byte;
	int do_send_rrr_msg_msg;
	int do_force_target;
	int do_extract_rrr_messages;
	int do_preserve_order;

	int do_multiple_per_connection;

	rrr_setting_uint close_grace_ms;
	rrr_setting_uint persistent_timeout_ms;

	char *timeout_action_str;
	enum rrr_send_loop_action timeout_action;

	rrr_setting_uint graylist_timeout_ms;
	rrr_setting_uint message_send_timeout_s;
	rrr_setting_uint message_ttl_us;
	rrr_setting_uint message_max_size;

	uint16_t source_udp_port;
	uint16_t source_tcp_port;

	char *default_topic;
	uint16_t default_topic_length;
	char *accept_topic;
	uint16_t accept_topic_length;

	char *target_host;
	uint16_t target_port;
	char *target_host_and_port;
	int target_protocol;

	struct rrr_map array_send_tags;

	uint64_t messages_count_read;
	uint64_t messages_count_polled;

	uint64_t entry_send_index_pos;
};

static void ip_data_cleanup(void *arg) {
	struct ip_data *data = (struct ip_data *) arg;

	if (data->collection_tcp != NULL) {
		rrr_socket_client_collection_destroy(data->collection_tcp);
	}
	if (data->collection_udp != NULL) {
		rrr_socket_client_collection_destroy(data->collection_udp);
	}
	if (data->send_loop != NULL) {
		rrr_send_loop_destroy(data->send_loop);
	}
	if (data->definitions != NULL) {
		rrr_array_tree_destroy(data->definitions);
	}
	RRR_FREE_IF_NOT_NULL(data->default_topic);
	RRR_FREE_IF_NOT_NULL(data->accept_topic);
	RRR_FREE_IF_NOT_NULL(data->target_host);
	RRR_FREE_IF_NOT_NULL(data->target_host_and_port);
	RRR_FREE_IF_NOT_NULL(data->timeout_action_str);
	rrr_map_clear(&data->array_send_tags);
	rrr_socket_graylist_clear(&data->tcp_graylist);
}

static int ip_data_init(struct ip_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

struct ip_private_data {
	struct ip_data *ip_data;
};

static int ip_private_data_new (void **result, int fd, void *arg) {
	(void)(fd);
	(void)(arg);

	*result = NULL;

	struct ip_private_data *private_data = rrr_allocate(sizeof(*private_data));
	if (private_data == NULL) {
		RRR_MSG_0("Failed to allocate memory in ip_private_data_new\n");
		return 1;
	}

	memset(private_data, '\0', sizeof(*private_data));

	private_data->ip_data = arg;

	*result = private_data;

	return 0;
}

static void ip_private_data_destroy (void *private_data) {
	rrr_free(private_data);
}

static int ip_config_parse_port (struct ip_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	ret = rrr_instance_config_read_port_number (&data->source_udp_port, config, "ip_udp_port");
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

	ret = rrr_instance_config_read_port_number (&data->source_tcp_port, config, "ip_tcp_port");
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

	ret = rrr_instance_config_read_port_number (&data->target_port, config, "ip_target_port");
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

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("ip_default_topic", default_topic, default_topic_length);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("ip_accept_topic", accept_topic, accept_topic_length);
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
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("ip_send_multiple_per_connection", do_multiple_per_connection, 1); // Default yes
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_close_grace_ms", close_grace_ms, IP_DEFAULT_CLOSE_GRACE_MS);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("ip_persistent_timeout_ms", persistent_timeout_ms, IP_DEFAULT_PERSISTENT_TIMEOUT_MS);

	if (data->do_preserve_order && data->persistent_timeout_ms == 0) {
		RRR_DBG_1("Note: ip_preserve_order is set while ip_persistent_timeout_ms is zero in ip instance %s, send order may not be guaranteed in all situations.\n",
				config->name);
	}

	if (data->do_preserve_order && data->do_multiple_per_connection == 0) {
		RRR_DBG_1("Note: ip_preserve_order is set while do_multiple_per_connection is 'no' in ip instance %s, send order may not be guaranteed in all situations.\n",
				config->name);
	}

	if (data->do_strip_array_separators && data->definitions == NULL) {
		RRR_MSG_0("ip_strip_array_separators was 'yes' while no array definition was set in ip_input_types in ip instance %s, this is a configuration error.\n",
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
	data->timeout_action = RRR_SEND_LOOP_ACTION_RETRY;

	if (data->timeout_action_str != NULL) {
		if ((ret = rrr_send_loop_action_from_str(&data->timeout_action, data->timeout_action_str)) != 0) {
			RRR_MSG_0("Invalid value '%s' for parameter ip_timeout_action in instance %s, must be retry, drop or return\n",
					data->timeout_action_str, config->name);
			ret = 1;
			goto out;
		}
	}

	if (data->message_send_timeout_s != 0 && data->timeout_action == RRR_SEND_LOOP_ACTION_RETRY) {
		RRR_MSG_0("Parameter ip_send_timeout in instance %s was >0 while ip_timeout_action was 'retry'. This does not make sense and is a configuration error.\n",
				config->name);
		ret = 1;
		goto out;
	}

	if (data->message_send_timeout_s == 0 && data->timeout_action != RRR_SEND_LOOP_ACTION_RETRY) {
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
		rrr_free(message);
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
	const struct sockaddr *addr;
	socklen_t addr_len;
	struct rrr_msg_holder_collection new_entries;
};

static int ip_array_callback_broker (struct rrr_msg_holder *entry, void *arg) {
	struct ip_read_array_callback_data *callback_data = arg;

	// Note that the provided entry is never saved, we add all new entries to the collection in callback data

	int ret = 0;

	uint8_t protocol = 0;

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
			callback_data->addr,
			callback_data->addr_len,
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

		if ((ret = rrr_array_new_message_from_array (
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
		RRR_SOCKET_CLIENT_ARRAY_CALLBACK_ARGS
) {
	struct ip_data *data = arg;

	(void)(private_data);

	int ret = 0;

	struct ip_read_array_callback_data callback_data = {
			data,
			array_final,
			read_session,
			addr,
			addr_len,
			{0}
	};

	if ((ret = rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			ip_array_callback_broker,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Error while writing entries to broker while reading in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	// All entries are allocated within message broker context within
	// ip_array_callback_broker, hence memory barrier is achieved.
	if ((ret = rrr_message_broker_write_entries_from_collection_unsafe (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			&callback_data.new_entries,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		goto out;
	}

	out:
	rrr_msg_holder_collection_clear(&callback_data.new_entries);
	return ret;
}

struct ip_accept_callback_data {
	struct ip_data *data;
	const struct sockaddr *addr;
	socklen_t addr_len;
};

static int ip_accept_callback_broker (struct rrr_msg_holder *entry, void *arg) {
	struct ip_accept_callback_data *callback_data = arg;
	struct ip_data *data = callback_data->data;

	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	if ((ret = rrr_msg_msg_new_with_data (
			&msg,
			MSG_TYPE_GET,
			MSG_CLASS_DATA,
			rrr_time_get_64(),
			data->accept_topic,
			data->accept_topic_length,
			NULL,
			0
	)) != 0) {
		RRR_MSG_0("Failed to create message in %s\n", __func__);
		goto out;
	}

	rrr_msg_holder_set_unlocked (
			entry,
			msg,
			MSG_TOTAL_SIZE(msg),
			callback_data->addr,
			callback_data->addr_len,
			RRR_IP_TCP
	);
	msg = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int ip_accept_callback (
		RRR_SOCKET_CLIENT_ACCEPT_CALLBACK_ARGS
) {
	struct ip_data *data = arg;

	(void)(private_data);

	int ret = 0;

	if (data->accept_topic != NULL) {
		struct ip_accept_callback_data callback_data = {
			data,
			addr,
			addr_len
		};

		if ((ret = rrr_message_broker_write_entry (
				INSTANCE_D_BROKER_ARGS(data->thread_data),
				NULL,
				0,
				0,
				NULL,
				ip_accept_callback_broker,
				&callback_data,
				INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
		)) != 0) {
			RRR_MSG_0("Error while writing entries to broker while reading in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
	}

	if (RRR_DEBUGLEVEL_2) {
		char buf[128];
		*buf = '\0';

		rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);

		RRR_DBG_2 ("ip instance %s accepted connection from %s\n",
				INSTANCE_D_NAME(data->thread_data), buf);
	}

	out:
	return ret;
}

static int ip_poll_callback (RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct ip_data *ip_data = thread_data->private_data;

	struct rrr_msg_msg *message = entry->message;

	rrr_send_loop_entry_prepare(ip_data->send_loop, entry);
	rrr_send_loop_push(ip_data->send_loop, entry);

	RRR_DBG_2 ("ip instance %s result from buffer timestamp %" PRIu64 " index %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), message->timestamp, entry->send_index);

	rrr_msg_holder_unlock(entry);

	ip_data->messages_count_polled++;

	return 0;
}

static int ip_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;

	return rrr_poll_do_poll_delete (amount, thread_data, ip_poll_callback);
}

struct ip_resolve_suggestion_callback_data {
	struct ip_data *ip_data;
	size_t address_count;
	struct sockaddr **addresses;
	socklen_t *address_lengths;
};

static int ip_resolve_suggestion_callback (
		const char *host,
		uint16_t port,
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
		RRR_DBG_7("ip instance %s resolve[%llu] %s:%u => %s\n",
				INSTANCE_D_NAME(callback_data->ip_data->thread_data),
				(long long unsigned int) callback_data->address_count,
				host,
				port,
				buf
		);
	}

	{
		struct sockaddr **addresses_new = rrr_reallocate(callback_data->addresses, sizeof(void *) * callback_data->address_count, sizeof(void *) * (callback_data->address_count + 1));
		if (addresses_new == NULL) {
			RRR_MSG_0("Failed to allocate memory in ip_resolve_suggestion_callback A\n");
			ret = 1;
			goto out;
		}
		callback_data->addresses = addresses_new;
	}

	{
		socklen_t *address_lengths_new = rrr_reallocate(callback_data->address_lengths, sizeof(socklen_t) * callback_data->address_count, sizeof(socklen_t) * (callback_data->address_count + 1));
		if (address_lengths_new == NULL) {
			RRR_MSG_0("Failed to allocate memory in ip_resolve_suggestion_callback B\n");
			ret = 1;
			goto out;
			
		}
		callback_data->address_lengths = address_lengths_new;
	}

	if ((callback_data->addresses[callback_data->address_count] = (void *) rrr_allocate(sizeof(struct sockaddr_storage))) == NULL) {
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
	uint16_t port;
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

	suggestion_callback_data.address_count = 0;
	suggestion_callback_data.addresses = NULL;
	suggestion_callback_data.address_lengths = NULL;

	out:
	for (size_t i = 0; i < suggestion_callback_data.address_count; i++) {
		rrr_free(suggestion_callback_data.addresses[i]);
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

	if (rrr_socket_graylist_exists(&ip_data->tcp_graylist, addr, addr_len)) {
		ret = RRR_SOCKET_NOT_READY;
		goto out;
	}

	rrr_socket_graylist_push (
			&ip_data->tcp_graylist,
			addr,
			addr_len,
			ip_data->close_grace_ms * 1000
	);

	if ((ret = rrr_ip_network_connect_tcp_ipv4_or_ipv6_raw_nonblock (
			fd,
			addr,
			addr_len
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

static void ip_msg_holder_incref_while_locked (void **private_data, void *arg) {
	struct rrr_msg_holder *entry = arg;
	rrr_msg_holder_incref_while_locked(entry);
	*private_data = entry;
}

static void ip_msg_holder_decref_void (void *arg) {
	struct rrr_msg_holder *entry = arg;
	rrr_msg_holder_decref(entry);
}

struct ip_resolve_push_sendto_callback_data {
	struct ip_data *ip_data;
	const void *send_data;
	rrr_biglength send_size;
	struct rrr_msg_holder *entry_orig;
};

static int ip_resolve_push_sendto_callback_test_fd (
		struct ip_data *ip_data,
		int fd,
		const char *dbg_ip,
		const char *dbg_family,
		const char *host,
		uint16_t port,
		const struct sockaddr *addr,
		socklen_t addr_len
) {
	int ret = 0;

	const char *dummy_data = "";

	// Test send to validate address
	if ((ret = (int) sendto(fd, dummy_data, 0, 0, addr, addr_len)) != 0) {
		RRR_DBG_7("ip instance %s resolve %s:%u => %s (sendto %s) failed: %s\n",
				INSTANCE_D_NAME(ip_data->thread_data),
				host,
				port,
				dbg_ip,
				dbg_family,
				rrr_strerror(errno)
		);
		// Try next suggestion
		goto out;
	}

	out:
	return ret;
}

static int ip_resolve_push_sendto_callback (
		const char *host,
		uint16_t port,
		const struct sockaddr *addr,
		socklen_t addr_len,
		void *arg
) {
	int ret = 0;

	struct ip_resolve_push_sendto_callback_data *callback_data = arg;

	int send_fd = -1;

	char buf[256];
	*buf = '\0';
	rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);

	// If no translation is needed, the original address is copied
	// rrr_ip_ipv4_mapped_ipv6_to_ipv4_if_needed(&addr, &addr_len, (const struct sockaddr *) &entry_orig->addr, entry_orig->addr_len);

	if ( callback_data->ip_data->udp_send_fd_ip6 > 0 &&
	     ip_resolve_push_sendto_callback_test_fd (
				callback_data->ip_data,
				callback_data->ip_data->udp_send_fd_ip6,
				buf,
				"ip6",
				host,
				port,
				addr,
				addr_len
	) == 0) {
		send_fd = callback_data->ip_data->udp_send_fd_ip6;
	}
	else if ( callback_data->ip_data->udp_send_fd_ip4 > 0 &&
	          ip_resolve_push_sendto_callback_test_fd (
				callback_data->ip_data,
				callback_data->ip_data->udp_send_fd_ip4,
				buf,
				"ip4",
				host,
				port,
				addr,
				addr_len
	) == 0) {
		send_fd = callback_data->ip_data->udp_send_fd_ip4;
	}
	else {
		RRR_DBG_7("ip instance %s resolve %s:%u => [address family %u] (sendto) failure\n",
				INSTANCE_D_NAME(callback_data->ip_data->thread_data),
				host,
				port,
				addr->sa_family
		);
		goto out;
	}

	RRR_DBG_7("ip instance %s resolve %s:%u => %s (sendto)\n",
			INSTANCE_D_NAME(callback_data->ip_data->thread_data),
			host,
			port,
			buf
	);

	rrr_length send_chunk_count = 0;
	if ((ret = rrr_socket_client_collection_sendto_push_const (
			&send_chunk_count,
			callback_data->ip_data->collection_udp,
			send_fd,
			addr,
			addr_len,
			callback_data->send_data,
			callback_data->send_size,
			ip_msg_holder_incref_while_locked,
			callback_data->entry_orig,
			ip_msg_holder_decref_void
	)) == 0) {
		// EOF breaks out from resolve iteration and indicates success
		ret = RRR_SOCKET_READ_EOF;
	}
	else {
		RRR_MSG_0("Failed to push send data in ip_resolve_sendto_callback of ip instance %s\n",
				INSTANCE_D_NAME(callback_data->ip_data->thread_data));
	}

	if (send_chunk_count > IP_SEND_CHUNK_COUNT_LIMIT) {
		RRR_MSG_0("Send chunk limit of %i reached (sendto default) in IP instance %s\n",
				IP_SEND_CHUNK_COUNT_LIMIT, INSTANCE_D_NAME(callback_data->ip_data->thread_data));
		ret = RRR_SOCKET_HARD_ERROR;
	}

	out:
	return ret;
}

static int ip_push_raw_default_target (
		struct ip_data *ip_data,
		struct rrr_msg_holder *entry_orig,
		const void *send_data,
		rrr_biglength send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	int ret = 0;

	if (ip_data->target_port == 0) {
		RRR_MSG_0("Warning: A message from a sender in ip instance %s had no address information and we have no default remote host set, dropping it\n",
				INSTANCE_D_NAME(thread_data));
		goto out;
	}

	if (ip_data->target_protocol == RRR_IP_TCP) {
		RRR_DBG_3("ip instance %s send using default target TCP [%s]\n", INSTANCE_D_NAME(thread_data), ip_data->target_host_and_port);

		struct ip_resolve_callback_data resolve_callback_data = {
			ip_data,
			ip_data->target_host,
			ip_data->target_port
		};

		rrr_length send_chunk_count = 0;
		ret = rrr_socket_client_collection_send_push_const_by_address_string_connect_as_needed (
				&send_chunk_count,
				ip_data->collection_tcp,
				ip_data->target_host_and_port,
				send_data,
				send_size,
				ip_msg_holder_incref_while_locked,
				entry_orig,
				ip_msg_holder_decref_void,
				ip_resolve_callback,
				&resolve_callback_data,
				ip_connect_raw_callback,
				ip_data
		);

		int send_chunk_count_limit_reached = (send_chunk_count > IP_SEND_CHUNK_COUNT_LIMIT);

		if (send_chunk_count_limit_reached) {
			RRR_DBG_3("Send chunk limit of %i reached (send) for default target in IP instance %s, closing connection when sending is completed\n",
					IP_SEND_CHUNK_COUNT_LIMIT, INSTANCE_D_NAME(ip_data->thread_data));
		}

		if (ip_data->do_multiple_per_connection == 0 || send_chunk_count_limit_reached) {
			rrr_socket_client_collection_close_when_send_complete_by_address_string (
					ip_data->collection_tcp,
					ip_data->target_host_and_port
			);
		}
	}
	else {
		RRR_DBG_3("ip instance %s send using default target UDP [%s]\n", INSTANCE_D_NAME(thread_data), ip_data->target_host_and_port);

		struct ip_resolve_push_sendto_callback_data resolve_callback_data = {
			ip_data,
			send_data,
			send_size,
			entry_orig
		};

		if ((ret = rrr_ip_network_resolve_ipv4_or_ipv6_with_callback (
				ip_data->target_port,
				ip_data->target_host,
				ip_resolve_push_sendto_callback,
				&resolve_callback_data
		)) == RRR_SOCKET_READ_EOF) {
			// OK, result found
			ret = 0;
		}
		else if (ret == 0) {
			// No address suggestions could be used
			RRR_MSG_0("Error while sending message to default remote %s:%u using UDP in ip instance %s, no resolve suggestions could be used\n",
					ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(ip_data->thread_data));
			ret = RRR_SOCKET_SOFT_ERROR;
		}
		else {
			RRR_MSG_0("Error while sending message to default remote %s:%u using UDP in ip instance %s\n",
					ip_data->target_host, ip_data->target_port, INSTANCE_D_NAME(ip_data->thread_data));
		}
	}

	out:
		return ret;
}

static int ip_push_raw (
		struct ip_data *ip_data,
		struct rrr_msg_holder *entry_orig,
		int protocol,
		const void *send_data,
		rrr_biglength send_size
) {
	struct rrr_instance_runtime_data *thread_data = ip_data->thread_data;

	int ret = 0;

	if (send_size == 0) {
		goto out;
	}

	// Configuration validation should produce an error if do_force_target is set
	// but no target_port/target_host
	if (ip_data->do_force_target == 1 || entry_orig->addr_len == 0) {
		//////////////////////////////////////////////////////
		// FORCED TARGET OR NO ADDRESS IN ENTRY, TCP OR UDP
		//////////////////////////////////////////////////////

		ret = ip_push_raw_default_target (
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

		if (RRR_DEBUGLEVEL_3) {
			char buf[256];
			rrr_ip_to_str(buf, sizeof(buf), (const struct sockaddr *) &entry_orig->addr, entry_orig->addr_len);
			RRR_DBG_3("ip instance %s send using address from entry TCP (%s)\n", INSTANCE_D_NAME(thread_data), buf);
		}

		rrr_length send_chunk_count = 0;
		ret = rrr_socket_client_collection_send_push_const_by_address_connect_as_needed (
				&send_chunk_count,
				ip_data->collection_tcp,
				(const struct sockaddr *) &entry_orig->addr,
				entry_orig->addr_len,
				send_data,
				send_size,
				ip_msg_holder_incref_while_locked,
				entry_orig,
				ip_msg_holder_decref_void,
				ip_connect_raw_callback,
				ip_data
		);

		int send_chunk_count_limit_reached = (send_chunk_count > IP_SEND_CHUNK_COUNT_LIMIT);

		if (send_chunk_count_limit_reached) {
			RRR_DBG_3("Send chunk limit of %i reached (send) for target in IP instance %s, closing connection when sending is completed\n",
					IP_SEND_CHUNK_COUNT_LIMIT, INSTANCE_D_NAME(ip_data->thread_data));
		}

		if (ip_data->do_multiple_per_connection == 0 || send_chunk_count_limit_reached) {
			rrr_socket_client_collection_close_when_send_complete_by_address (
					ip_data->collection_tcp,
					(const struct sockaddr *) &entry_orig->addr,
					entry_orig->addr_len
			);
		}
	}
	else {
		//////////////////////////////////////////////////////
		// ADDRESS FROM ENTRY, UDP
		//////////////////////////////////////////////////////

		if (RRR_DEBUGLEVEL_3) {
			char buf[256];
			rrr_ip_to_str(buf, sizeof(buf), (const struct sockaddr *) &entry_orig->addr, entry_orig->addr_len);
			RRR_DBG_3("ip instance %s send using address from entry UDP (%s)\n", INSTANCE_D_NAME(thread_data), buf);
		}

		int send_fd = -1;

		if (entry_orig->addr.ss_family == AF_INET) {
			send_fd = (ip_data->udp_send_fd_ip4 > 0 ? ip_data->udp_send_fd_ip4 : ip_data->udp_send_fd_ip6);
		}
		else {
			send_fd = (ip_data->udp_send_fd_ip6 > 0 ? ip_data->udp_send_fd_ip6 : ip_data->udp_send_fd_ip4);
		}

		rrr_length send_chunk_count = 0;
		ret = rrr_socket_client_collection_sendto_push_const (
				&send_chunk_count,
				ip_data->collection_udp,
				send_fd,
				(const struct sockaddr *) &entry_orig->addr,
				entry_orig->addr_len,
				send_data,
				send_size,
				ip_msg_holder_incref_while_locked,
				entry_orig,
				ip_msg_holder_decref_void
		);

		if (send_chunk_count > IP_SEND_CHUNK_COUNT_LIMIT) {
			RRR_MSG_0("Send chunk limit of %i reached (sendto address from entry) in IP instance %s\n",
					IP_SEND_CHUNK_COUNT_LIMIT, INSTANCE_D_NAME(ip_data->thread_data));
			ret = RRR_SOCKET_HARD_ERROR;
		}
	}

	if (ret != 0 && ret != RRR_SOCKET_NOT_READY) {
		RRR_MSG_0("Failed to push message to send queue in ip instance %s return was %i\n",
				INSTANCE_D_NAME(thread_data), ret
		);
		goto out;
	}

	//////////////////////////////////////////////////////
	// OUT
	//////////////////////////////////////////////////////

	out:
	return ret;
}

static int ip_push_message (
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
	rrr_biglength send_size = 0;
	
	struct rrr_array array_tmp = {0};
	struct rrr_msg_msg *message = entry->message;

	// We modify the data in the buffer here, no need to copy as the memory is always
	// freed after this function.
	if (ip_data->do_send_rrr_msg_msg != 0) {
		if (entry->data_length < (long int) sizeof(*message) - 1) {
			RRR_MSG_0("ip instance %s had send_rrr_msg_msg set but received a message which was too short (%llu<%llu), dropping it\n",
					INSTANCE_D_NAME(thread_data), (long long unsigned) entry->data_length, (long long unsigned) sizeof(*message));
			goto out;
		}

		rrr_length final_size = rrr_length_from_biglength_bug_const(entry->data_length);

		// Check for message already in network order (second send attempt)
		if (entry->endian_indicator != 0) {
			RRR_DBG_3 ("ip instance %s sends packet (new attempt) with rrr message timestamp from %" PRIu64 " size %" PRIrrrl "\n",
					INSTANCE_D_NAME(thread_data), rrr_be64toh(message->timestamp), final_size);
		}
		else {
			entry->data_length = final_size = MSG_TOTAL_SIZE(message);

			RRR_DBG_3 ("ip instance %s sends packet with rrr message timestamp from %" PRIu64 " size %" PRIrrrl "\n",
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
		if (rrr_array_message_append_to_array(&array_version_dummy, &array_tmp, message) != 0) {
			RRR_MSG_0("Could not convert array message to collection in ip instance %s\n", INSTANCE_D_NAME(thread_data));
			ret = RRR_SOCKET_HARD_ERROR;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(tmp_data);
		rrr_biglength target_size = 0;
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

		if (target_size > SSIZE_MAX) {
			RRR_MSG_0("Array message export size too long in ip instance %s\n (%llu > %lli)\n",
				INSTANCE_D_NAME(thread_data),
				(unsigned long long) target_size,
				(long long int) SSIZE_MAX
			);
			ret = RRR_SOCKET_SOFT_ERROR;
			goto out;
		}

		if (tag_count != 0 && found_tags != tag_count) {
			RRR_MSG_0("Array message to send in ip instance %s did not contain all tags specified in configuration, dropping it (%i tags missing)\n",
					INSTANCE_D_NAME(thread_data), tag_count - found_tags);
			goto out;
		}

		RRR_DBG_3 ("ip instance %s sends packet with array data from message with timestamp from %" PRIu64 " %i array tags size %" PRIrrrbl "\n",
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

		RRR_DBG_3 ("ip instance %s sends packet with raw data from message with timestamp from %" PRIu64 " %" PRIrrrbl " bytes\n",
				INSTANCE_D_NAME(thread_data), message->timestamp, send_size);
	}

	if ((ip_data->target_port != 0 && (ip_data->target_host == NULL || *(ip_data->target_host) == '\0')) ||
	    (ip_data->target_port == 0 && (ip_data->target_host != NULL && *(ip_data->target_host) != '\0'))
	) {
		RRR_BUG("Invalid target_port/target_host configuration in ip input_callback\n");
	}

	ret = ip_push_raw (
			ip_data,
			entry,
			entry->protocol,
			send_data,
			send_size
	);

	out:
		RRR_FREE_IF_NOT_NULL(tmp_data);
		rrr_array_clear(&array_tmp);
		return ret;
}

static int ip_send_loop_push_callback (
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct ip_data *ip_data = arg;
	return ip_push_message(ip_data, entry);
}

static int ip_send_loop_return_callback (
		struct rrr_msg_holder *entry,
		void *arg
) {
	struct ip_data *ip_data = arg;

	int ret = 0;

	if (entry->endian_indicator != 0) {
		if (rrr_msg_head_to_host_and_verify (
				entry->message,
				rrr_length_from_biglength_bug_const(entry->data_length)
		) != 0 || (
			rrr_msg_msg_to_host_and_verify(entry->message, entry->data_length) != 0
		)) {
			RRR_BUG("BUG: Message endian reversion failed in %s\n", __func__);
		}
		entry->endian_indicator = 0;
	}

	if ((ret = rrr_message_broker_incref_and_write_entry_unsafe (
			INSTANCE_D_BROKER_ARGS(ip_data->thread_data),
			entry,
			NULL,
			INSTANCE_D_CANCEL_CHECK_ARGS(ip_data->thread_data)
	)) != 0) {
		RRR_MSG_0("Error while adding message to buffer in ip instance %s\n",
				INSTANCE_D_NAME(ip_data->thread_data));
		ret = RRR_SEND_LOOP_HARD_ERROR;
		goto out;
	}

	out:
	return ret;
}

static void ip_send_loop_run_callback (
		void *arg
) {
	struct ip_data *ip_data = arg;

	if (rrr_send_loop_count(ip_data->send_loop) == 0 && ip_data->persistent_timeout_ms == 0) {
		rrr_socket_client_collection_close_outbound_when_send_complete(ip_data->collection_tcp);
	}
}

static int ip_start_udp (struct ip_data *data) {
	int ret = 0;

	struct rrr_ip_data ip_udp_6 = {0};
	struct rrr_ip_data ip_udp_4 = {0};

	ip_udp_6.port = data->source_udp_port;
	ip_udp_4.port = data->source_udp_port;

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

	data->udp_send_fd_ip4 = ip_udp_4.fd;
	data->udp_send_fd_ip6 = ip_udp_6.fd;

	if (ip_udp_6.fd != 0) {
		if ((ret = rrr_socket_client_collection_connected_fd_push(data->collection_udp, ip_udp_6.fd, RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT)) != 0) {
			RRR_MSG_0("Failed to push UDP IPv6 fd to collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		ip_udp_6.fd = 0;
	}

	if (ip_udp_4.fd != 0) {
		if ((ret = rrr_socket_client_collection_connected_fd_push(data->collection_udp, ip_udp_4.fd, RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_PERSISTENT)) != 0) {
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
		if ((ret = rrr_socket_client_collection_listen_fd_push(data->collection_tcp, ip_tcp_listen_6.fd)) != 0) {
			RRR_MSG_0("Failed to push TCP IPv6 fd to collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
			goto out;
		}
		ip_tcp_listen_6.fd = 0;
	}

	if (ip_tcp_listen_4.fd != 0) {
		if ((ret = rrr_socket_client_collection_listen_fd_push(data->collection_tcp, ip_tcp_listen_4.fd)) != 0) {
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

static int ip_entry_related_cmp (
		struct ip_data *ip_data ,
		const struct rrr_msg_holder *entry,
		const struct rrr_msg_holder *entry_related
) {
	if (ip_data->do_force_target == 1 ||
	    rrr_msg_holder_address_matches(entry, entry_related)
	) {
		return 0;
	}
	return 1;
}

static int ip_entry_related_cmp_callback (
		const struct rrr_msg_holder *entry,
		const struct rrr_msg_holder *entry_related,
		void *arg
) {
	struct ip_data *ip_data = arg;
	return ip_entry_related_cmp(ip_data, entry, entry_related);
}

struct chunk_send_smart_timeout_callback_data {
	struct ip_data *ip_data;
	const struct rrr_msg_holder *entry_orig;
};

static void ip_chunk_send_smart_timeout_callback (
		int *do_remove,
		const void *data,
		rrr_biglength data_size,
		rrr_biglength data_pos,
		void *chunk_private_data,
		void *callback_arg
) {
	struct chunk_send_smart_timeout_callback_data *callback_data = callback_arg;
	struct rrr_msg_holder *entry = chunk_private_data;

	(void)(data);
	(void)(data_size);
	(void)(data_pos);

	*do_remove = 0;

	rrr_msg_holder_lock(entry);
	if (ip_entry_related_cmp (callback_data->ip_data, callback_data->entry_orig, entry) == 0) {
		entry->send_time = rrr_time_get_64();
	}
	rrr_msg_holder_unlock(entry);
}

static void ip_chunk_send_notify_callback (RRR_SOCKET_CLIENT_SEND_NOTIFY_CALLBACK_ARGS) {
	struct ip_data *ip_data = callback_arg;
	struct rrr_msg_holder *entry = chunk_private_data;

	(void)(fd);
	(void)(data);
	(void)(data_size);
	(void)(data_pos);

	rrr_msg_holder_lock(entry);

	if (!was_sent) {
		rrr_send_loop_unshift(ip_data->send_loop, entry);
	}
	else if (ip_data->do_smart_timeout) {
		// TODO : Don't iterate everything with n^2 complexity

		struct chunk_send_smart_timeout_callback_data callback_data = {
			ip_data,
			entry
		};
		rrr_socket_client_collection_send_chunk_iterate (
				ip_data->collection_tcp,
				ip_chunk_send_smart_timeout_callback,
				&callback_data
		);
		rrr_socket_client_collection_send_chunk_iterate (
				ip_data->collection_udp,
				ip_chunk_send_smart_timeout_callback,
				&callback_data
		);

		rrr_send_loop_entry_touch_related(ip_data->send_loop, entry, ip_entry_related_cmp_callback, ip_data);
	}

	rrr_msg_holder_unlock(entry);
}

static void ip_fd_close_notify_callback (RRR_SOCKET_CLIENT_FD_CLOSE_CALLBACK_ARGS) {
	struct ip_data *ip_data = arg;

	(void)(fd);
	(void)(addr_string);

	if (create_type == RRR_SOCKET_CLIENT_COLLECTION_CREATE_TYPE_OUTBOUND && addr_len > 0) {
		if (RRR_DEBUGLEVEL_7) {
			char buf[256];
			rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);
			if (was_finalized) {
				RRR_DBG_7("fd %i connection to %s closed in ip instance %s, graylisting for %llu ms\n",
					fd, buf, INSTANCE_D_NAME(ip_data->thread_data), (long long unsigned int) ip_data->close_grace_ms);
			}
			else {
				RRR_DBG_7("fd %i connection to %s failed in ip instance %s, graylisting for %llu ms\n",
					fd, buf, INSTANCE_D_NAME(ip_data->thread_data), (long long unsigned int) ip_data->graylist_timeout_ms);
			}
		}

		rrr_socket_graylist_push (
				&ip_data->tcp_graylist,
				addr,
				addr_len,
				was_finalized ? ip_data->close_grace_ms * 1000LLU : ip_data->graylist_timeout_ms * 1000LLU
		);
	}
}

static void ip_send_chunk_periodic_callback (
		int *do_remove,
		const void *data,
		rrr_biglength data_size,
		rrr_biglength data_pos,
		void *chunk_private_data,
		void *callback_arg
) {
	struct ip_data *ip_data = callback_arg;
	struct rrr_msg_holder *entry = chunk_private_data;

	(void)(data);
	(void)(data_size);
	(void)(data_pos);

	rrr_msg_holder_lock(entry);
	rrr_send_loop_unshift_if_timed_out(do_remove, ip_data->send_loop, entry);
	rrr_msg_holder_unlock(entry);
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

	rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 2, "read_count", ip_data->messages_count_read);
	rrr_stats_instance_update_rate(INSTANCE_D_STATS(thread_data), 3, "polled_count", ip_data->messages_count_polled);

	ip_data->messages_count_read = 0;
	ip_data->messages_count_polled = 0;

	unsigned int delivery_entry_count = 0;
	int delivery_ratelimit_active = 0;

	if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
			&delivery_entry_count,
			&delivery_ratelimit_active,
			thread_data
	) != 0) {
		RRR_MSG_0("Error while setting ratelimit in ip instance %s\n",
				INSTANCE_D_NAME(thread_data));
		return RRR_EVENT_EXIT;
	}

	rrr_socket_client_collection_send_chunk_iterate (ip_data->collection_udp, ip_send_chunk_periodic_callback, ip_data);
	rrr_socket_client_collection_send_chunk_iterate (ip_data->collection_tcp, ip_send_chunk_periodic_callback, ip_data);

	return ret;
}

static void ip_array_parse_error_callback(RRR_SOCKET_CLIENT_ERROR_CALLBACK_ARGS) {
	struct ip_data *data = arg;

	(void)(read_session);
	(void)(private_data);

	char buf[256];
	*buf = '\0';
	rrr_ip_to_str(buf, sizeof(buf), addr, addr_len);
	RRR_MSG_0("ip instance %s failed to parse array data from %s%s\n",
			INSTANCE_D_NAME(data->thread_data),
			buf,
			(is_hard_err ? " (hard_error)": "")
	);
}

static void ip_event_setup (
		struct ip_data *data,
		struct rrr_socket_client_collection *collection,
		int socket_read_flags
) {
	if (data->definitions != NULL) {
		rrr_socket_client_collection_event_setup_array_tree (
			collection,
			ip_private_data_new,
			ip_private_data_destroy,
			data,
			socket_read_flags,
			NULL,
			NULL,
			data->definitions,
			data->do_sync_byte_by_byte,
			4096,
			0, /* No message max size */
			ip_array_callback,
			data,
			ip_array_parse_error_callback,
			data,
			ip_accept_callback,
			data
		);
	}
	else {
		rrr_socket_client_collection_event_setup_ignore (
			collection,
			ip_private_data_new,
			ip_private_data_destroy,
			data,
			socket_read_flags,
			NULL,
			NULL
		);
	}

	rrr_socket_client_collection_send_notify_setup (
		collection,
		ip_chunk_send_notify_callback,
		data
	);
	rrr_socket_client_collection_fd_close_notify_setup (
		collection,
		ip_fd_close_notify_callback,
		data
	);
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

	if (ip_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parsing failed for ip instance %s\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	{
		char tmp[256];
		snprintf(tmp, sizeof(tmp), "ip instance %s", INSTANCE_D_NAME(thread_data));
		tmp[sizeof(tmp) - 1] = '\0';
		if (rrr_send_loop_new (
				&data->send_loop,
				INSTANCE_D_EVENTS(thread_data),
				tmp,
				data->do_preserve_order,
				data->message_ttl_us,
				data->message_send_timeout_s * 1000 * 1000,
				data->timeout_action,
				ip_send_loop_push_callback,
				ip_send_loop_return_callback,
				ip_send_loop_run_callback,
				data
		)) {
			RRR_MSG_0("Failed to create send loop in ip instance %s", INSTANCE_D_NAME(thread_data));
			goto out_message;
		}
	}

	int has_senders = rrr_message_broker_senders_count(INSTANCE_D_BROKER_ARGS(thread_data)) > 0 ? 1 : 0;

	if (has_senders == 0 && data->definitions == NULL) {
		RRR_MSG_0("Error: ip instance %s has no senders defined and also has no array definition. Cannot do anything with this configuration.\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_socket_graylist_init(&data->tcp_graylist);

	if (rrr_socket_client_collection_new(&data->collection_tcp, INSTANCE_D_EVENTS(thread_data), INSTANCE_D_NAME(data->thread_data)) != 0) {
		RRR_MSG_0("Failed to create TDP client collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_message;
	}

	if (rrr_socket_client_collection_new(&data->collection_udp, INSTANCE_D_EVENTS(thread_data), INSTANCE_D_NAME(data->thread_data)) != 0) {
		RRR_MSG_0("Failed to create UDP client collection in ip instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out_message;
	}

	rrr_socket_client_collection_set_idle_timeout(data->collection_tcp, data->persistent_timeout_ms * 1000);
	rrr_socket_client_collection_set_idle_timeout(data->collection_udp, data->persistent_timeout_ms * 1000);

	// TODO : Use new read flags callback to distinguish read flags

	ip_event_setup (data, data->collection_tcp, RRR_SOCKET_READ_METHOD_RECV | RRR_SOCKET_READ_CHECK_POLLHUP | RRR_SOCKET_READ_CHECK_EOF | RRR_SOCKET_READ_FIRST_EOF_OK);
	ip_event_setup (data, data->collection_udp, RRR_SOCKET_READ_METHOD_RECVFROM);

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

