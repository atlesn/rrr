/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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
#include <sys/stat.h>

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/array.h"
#include "../lib/map.h"
#include "../lib/threads.h"
#include "../lib/poll_helper.h"
#include "../lib/instances.h"
#include "../lib/rrr_strerror.h"
#include "../lib/util/gnu.h"
#include "../lib/util/fs.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/instance_config.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/message_broker.h"
#include "../lib/event/event.h"
#include "../lib/raft/channel.h"
#ifdef RRR_WITH_JSONC
#  include "../lib/json/json.h"
#endif

#define RAFT_DEFAULT_DIRECTORY "/var/lib/rrr/raft"
#define RAFT_DEFAULT_PORT 9001

enum raft_req_type {
	RAFT_REQ_PUT,
	RAFT_REQ_PAT,
	RAFT_REQ_GET,
	RAFT_REQ_LEADERSHIP_TRANSFER
};

#define RAFT_REQ_TYPE_TO_STR(type)                                                   \
    ((type) == RAFT_REQ_PUT ? "PUT" :                                                \
    ((type) == RAFT_REQ_PAT ? "PAT" :                                                \
    ((type) == RAFT_REQ_GET ? "GET" :                                                \
    ((type) == RAFT_REQ_LEADERSHIP_TRANSFER ? "LEADERSHIP TRANSFER" : "UNKNOWN"))))

struct raft_request {
	uint32_t req_index;
	struct rrr_msg_msg *msg_orig;
	enum raft_req_type req_type;
};

struct raft_request_collection {
	struct raft_request *requests;
	size_t capacity;
};

static int raft_request_init (
		struct raft_request *request,
		uint32_t req_index,
		enum raft_req_type req_type,
		const struct rrr_msg_msg *msg_orig
) {
	int ret = 0;

	request->req_index = req_index;
	request->req_type = req_type;

	if (msg_orig != NULL && (request->msg_orig = rrr_msg_msg_duplicate(msg_orig)) == NULL) {
		RRR_MSG_0("Failed to duplicate message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static void raft_request_clear (
		struct raft_request *request
) {
	RRR_FREE_IF_NOT_NULL(request->msg_orig);
	*request = (struct raft_request) {0};
}

static struct raft_request raft_request_collection_consume (
		struct raft_request_collection *collection,
		uint32_t req_index
) {
	struct raft_request result;

	for (size_t i = 0; i < collection->capacity; i++) {
		if (collection->requests[i].req_index == req_index) {
			result = collection->requests[i];
			collection->requests[i] = (struct raft_request) {0};
			printf("== consume req %u type %s\n", req_index, RAFT_REQ_TYPE_TO_STR(result.req_type));
			return result;
		}
	}

	RRR_BUG("BUG: Request %u not found in %s\n", req_index, __func__);
}

static int raft_request_collection_push (
		struct raft_request_collection *collection,
		uint32_t req_index,
		enum raft_req_type req_type,
		const struct rrr_msg_msg *msg_orig
) {
	int ret = 0;

	printf("== push   req %u type %s cap %lu\n",
		req_index, RAFT_REQ_TYPE_TO_STR(req_type), collection->capacity);

	struct raft_request *target = NULL, *requests_new;
	size_t capacity_new;

	for (size_t i = 0; i < collection->capacity; i++) {
		if (collection->requests[i].req_index == 0) {
			target = &collection->requests[i];
			break;
		}
	}

	if (target)
		goto target_found;

	capacity_new = collection->capacity + 64;
	if ((requests_new = rrr_reallocate(collection->requests, capacity_new * sizeof(*requests_new))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}
	memset(requests_new + collection->capacity, '\0', sizeof(*requests_new) * (capacity_new - collection->capacity));

	target = requests_new + collection->capacity;
	collection->requests = requests_new;
	collection->capacity = capacity_new;

	target_found:
		if ((ret = raft_request_init(target, req_index, req_type, msg_orig)) != 0) {
			goto out;
		}
	out:
		return ret;
}

static void raft_request_collection_clear (
		struct raft_request_collection *collection
) {
	for (size_t i = 0; i < collection->capacity; i++) {
		raft_request_clear(&collection->requests[i]);
	}
	RRR_FREE_IF_NOT_NULL(collection->requests);
	*collection = (struct raft_request_collection) {0};
}

struct raft_data {
	struct rrr_instance_runtime_data *thread_data;

	struct rrr_map servers;
	rrr_setting_uint preferred_leader;
	int do_status_messages;

	struct rrr_raft_channel *channel;
	struct raft_request_collection requests;
	int is_leader;
	int leader_id;
	char leader_address[128];
	char *directory;
};

static void raft_data_init(struct raft_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void raft_data_cleanup(struct raft_data *data) {
	rrr_map_clear(&data->servers);
	if (data->channel != NULL)
		rrr_raft_channel_cleanup(data->channel);
	raft_request_collection_clear(&data->requests);
	RRR_FREE_IF_NOT_NULL(data->directory);
}

static int raft_poll_callback (RRR_POLL_CALLBACK_SIGNATURE) {
	struct rrr_instance_runtime_data *thread_data = arg;
	struct raft_data *data = thread_data->private_data;
	const struct rrr_msg_msg *message = entry->message;

	(void)(data);

	int ret = 0;

	uint32_t req_index;
	enum raft_req_type req_type;

	RRR_DBG_2("raft instance %s received a message with type %s, topic '%.*s' and timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(data->thread_data),
			MSG_TYPE_NAME(message),
			MSG_TOPIC_LENGTH(message),
			MSG_TOPIC_PTR(message),
			message->timestamp
	);

	switch (MSG_TYPE(message)) {
		case MSG_TYPE_PAT:
		case MSG_TYPE_MSG:
		case MSG_TYPE_PUT:
			if (!data->is_leader) {
				RRR_MSG_0("Warning: Received %s message (store command) in raft instance %s which might not be leader of the cluster.\n",
					MSG_TYPE_NAME(message), INSTANCE_D_NAME(thread_data));
			}
			break;
		default:
			break;
	};

	switch (MSG_TYPE(message)) {
		case MSG_TYPE_MSG:
		case MSG_TYPE_PUT: {
			if ((ret = rrr_raft_channel_request_put_native (
					&req_index,
					data->channel,
					message
			)) != 0) {
				RRR_MSG_0("Warning: Failed to put message in raft instance %s\n",
					INSTANCE_D_NAME(thread_data));
				goto out;
			}
			req_type = RAFT_REQ_PUT;
		} break;
		case MSG_TYPE_PAT: {
			if ((ret = rrr_raft_channel_request_patch_native (
					&req_index,
					data->channel,
					message
			)) != 0) {
				RRR_MSG_0("Warning: Failed to patch message in raft instance %s\n",
					INSTANCE_D_NAME(thread_data));
				goto out;
			}
			req_type = RAFT_REQ_PAT;
		} break;
		case MSG_TYPE_GET: {
			if ((ret = rrr_raft_channel_request_get (
					&req_index,
					data->channel,
					MSG_TOPIC_LENGTH(message) > 0 ? MSG_TOPIC_PTR(message) : NULL,
					MSG_TOPIC_LENGTH(message)
			)) != 0) {
				RRR_MSG_0("Warning: Failed to get message in raft instance %s\n",
					INSTANCE_D_NAME(thread_data));
				goto out;
			}
			req_type = RAFT_REQ_GET;
		} break;
		default: {
			RRR_MSG_0("Warning: Unknown type %s in message to raft instance %s, dropping it.\n",
				MSG_TYPE_NAME(message),
				INSTANCE_D_NAME(thread_data));
			goto out;
		} break;
	};

	// Message must be copied while the data is protected by entry lock
	if ((ret = raft_request_collection_push (
			&data->requests,
			req_index,
			req_type,
			message
	)) != 0) {
		goto out;
	}

	out:
	rrr_msg_holder_unlock(entry);
	return ret;
}

static int raft_event_broker_data_available (RRR_EVENT_FUNCTION_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(data);

	return rrr_poll_do_poll_delete (amount, thread_data, raft_poll_callback);
}

static int raft_parse_config (struct raft_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8("raft_directory", directory, RAFT_DEFAULT_DIRECTORY);

	if ((ret = rrr_instance_config_parse_comma_separated_associative_to_map (
			&data->servers,
			config,
			"raft_nodes",
			"->"
	)) != 0) {
		RRR_MSG_0("Failed to parse parameter raft_nodes of raft instance %s\n",
			config->name);
		goto out;
	}

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("raft_status_messages", do_status_messages, 0);

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("raft_preferred_leader", preferred_leader, 0);
	if (data->preferred_leader > INT32_MAX) {
		RRR_MSG_0("Field preferred_leader out of rang in raft instance %s, (%llu>%i)\n",
			config->name, (unsigned long long) data->preferred_leader, INT32_MAX);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

struct raft_message_broker_callback_data {
	struct raft_data *data;
	const struct rrr_array *array;
	const struct rrr_msg_msg *msg;
};

static int raft_message_broker_callback (
		struct rrr_msg_holder *new_entry,
		void *arg
) {
	struct raft_message_broker_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	// Caller must pass either message or array
	assert((void *) callback_data->msg != (void *) callback_data->array);

	if (callback_data->msg != NULL) {
		if ((msg = rrr_msg_msg_duplicate(callback_data->msg)) == NULL) {
			RRR_MSG_0("Warning: Failed to create result message in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}
	else {
		if ((ret = rrr_array_new_message_from_array (
				&msg,
				callback_data->array,
				rrr_time_get_64(),
				NULL,
				0
		)) != 0) {
			RRR_MSG_0("Warning: Failed to create array message in %s\n", __func__);
			goto out;
		}
	}

	rrr_msg_holder_set_unlocked (
			new_entry,
			msg,
			MSG_TOTAL_SIZE(msg),
			NULL,
			0,
			0
	);
	msg = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	rrr_msg_holder_unlock(new_entry);
	return ret;
}

static void raft_pong_callback (RRR_RAFT_PONG_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(data);
}

static void raft_ack_callback (RRR_RAFT_ACK_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	int ret_tmp = 0;
	struct rrr_array array_tmp = {0};
	struct raft_request request;
	const struct rrr_msg_msg *msg;
	struct rrr_msg_msg *msg_new = NULL;

	request = raft_request_collection_consume (&data->requests, req_index);
	msg = request.msg_orig;

	if (code != RRR_RAFT_OK) {
		RRR_MSG_0("Warning: A request failed in raft instance '%s', negative ACK with reason '%s' was received from the node.\n",
			INSTANCE_D_NAME(data->thread_data), rrr_raft_reason_to_str(code));
	}

	ret_tmp |= rrr_array_push_value_str_with_tag (
			&array_tmp,
			"raft_command",
			RAFT_REQ_TYPE_TO_STR(request.req_type)
	);
	ret_tmp |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			"raft_status",
			code == RRR_RAFT_OK
	);
	ret_tmp |= rrr_array_push_value_str_with_tag (
			&array_tmp,
			"raft_reason",
			rrr_raft_reason_to_str(code)
	);
	ret_tmp |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			"raft_server_id",
			server_id
	);
	ret_tmp |= rrr_array_push_value_i64_with_tag (
			&array_tmp,
			"raft_leader_id",
			data->leader_id
	);
	ret_tmp |= rrr_array_push_value_str_with_tag (
			&array_tmp,
			"raft_leader_address",
			data->leader_address
	);

	switch (request.req_type) {
		case RAFT_REQ_GET:
		case RAFT_REQ_PUT:
		case RAFT_REQ_PAT: {
			RRR_DBG_2("Result of command %s of message with topic %.*s in raft instance %s: %s\n",
				MSG_TYPE_NAME(msg),
				MSG_TOPIC_LENGTH(msg),
				MSG_TOPIC_PTR(msg),
				INSTANCE_D_NAME(data->thread_data),
				rrr_raft_reason_to_str(code)
			);

			ret_tmp |= rrr_array_push_value_str_with_tag_with_size (
				&array_tmp,
				"raft_topic",
				MSG_TOPIC_LENGTH(msg) > 0 ? MSG_TOPIC_PTR(msg) : "",
				MSG_TOPIC_LENGTH(msg)
			);
		} break;
		case RAFT_REQ_LEADERSHIP_TRANSFER: {
			RRR_DBG_1("Result of leadership transfer in raft instance %s: %s\n",
				INSTANCE_D_NAME(data->thread_data), rrr_raft_reason_to_str(code));

			ret_tmp |= rrr_array_push_value_str_with_tag (
				&array_tmp,
				"raft_topic",
				""
			);
		} break;
		default: {
			RRR_BUG("BUG: Unknown request type %i in %s\n", request.req_type, __func__);
		} break;
	};

	if (ret_tmp != 0) {
		RRR_MSG_0("Warning: Failed to add array values in %s\n", __func__);
		goto out;
	}

	struct raft_message_broker_callback_data callback_data = {
		data,
		&array_tmp,
		NULL
	};

	if (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			raft_message_broker_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) {
		RRR_MSG_0("Warning: Failed to write message to broker in %s\n", __func__);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg_new);
	raft_request_clear(&request);
	rrr_array_clear(&array_tmp);
}

static int raft_leadership_transfer (
		struct raft_data *data,
		int server_id
) {
	int ret = 0;

	uint32_t req_index;

	if ((ret = rrr_raft_channel_leadership_transfer (
			&req_index,
			data->channel,
			server_id
	)) != 0) {
		goto out;
	}

	if ((ret = raft_request_collection_push (
			&data->requests,
			req_index,
			RAFT_REQ_LEADERSHIP_TRANSFER,
			NULL
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

static void raft_opt_callback (RRR_RAFT_OPT_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(req_index);
	(void)(data);

	struct rrr_raft_server *server;

	strncpy(data->leader_address, leader_address, sizeof(data->leader_address));
	data->leader_address[sizeof(data->leader_address) - 1] = '\0';

	data->leader_id = leader_id;

	if (is_leader && data->preferred_leader > 0 && (int) data->preferred_leader != leader_id) {
		RRR_DBG_1("Raft instance %s id %i transferring leadership to %llu per configuration\n",
			INSTANCE_D_NAME(data->thread_data), server_id, (unsigned long long) data->preferred_leader);

		assert(data->preferred_leader <= INT32_MAX);
		if (raft_leadership_transfer(data, (int) data->preferred_leader) != 0) {
			RRR_MSG_0("Warning: Failed to transfer leadership to %llu in raft instance %s\n",
				(unsigned long long) data->preferred_leader,
				INSTANCE_D_NAME(data->thread_data)
			);
		}
	}

	if (is_leader) {
		RRR_DBG_1("Raft instance %s id %i is leader, cluster status for all nodes:\n",
			INSTANCE_D_NAME(data->thread_data), server_id);
		data->is_leader = 1;
	}
	else {
		RRR_DBG_1("Raft instance %s id %i is not leader, cluster status for all nodes:\n",
			INSTANCE_D_NAME(data->thread_data), server_id);
		data->is_leader = 0;
	}
	
	for (server = *servers; server->id > 0; server++) {
		RRR_DBG_1("- %s id %" PRIi64 " status %s catch up %s\n",
			server->address,
			server->id,
			RRR_RAFT_STATUS_TO_STR(server->status),
			RRR_RAFT_CATCH_UP_TO_STR(server->catch_up)
		);
	}
}

static void raft_msg_callback (RRR_RAFT_MSG_CALLBACK_ARGS) {
	struct raft_data *data = arg;

	(void)(server_id);
	(void)(req_index);

	RRR_DBG_2("Raft instance %s got a result with topic '%.*s' timestamp %" PRIu64 ", emitting message\n",
		INSTANCE_D_NAME(data->thread_data),
		MSG_TOPIC_LENGTH(*msg),
		MSG_TOPIC_PTR(*msg),
		(*msg)->timestamp
	);

	struct raft_message_broker_callback_data callback_data = {
		data,
		NULL,
		*msg
	};

	if (rrr_message_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			raft_message_broker_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) {
		RRR_MSG_0("Warning: Failed to write message to broker in %s\n", __func__);
		return;
	}
}

struct raft_patch_array_json_callback_data {
	struct rrr_array *array_data;
	const char *tag;
};

static int raft_patch_array_json_callback (const char *result, void *arg) {
	struct raft_patch_array_json_callback_data *callback_data = arg;
	struct rrr_array *array_data = callback_data->array_data;

	rrr_array_clear_by_tag(array_data, callback_data->tag);

	return rrr_array_push_value_str_with_tag(array_data, callback_data->tag, result);
}

static int raft_patch_array_callback (const struct rrr_type_value *value, void *arg) {
	struct rrr_array *array_data = arg;

	int ret = 0;

	struct rrr_type_value *value_new;
	char *str = NULL;

#ifdef RRR_WITH_JSONC
	if ((RRR_TYPE_IS_BLOB_EXCACT(value->definition->type) || RRR_TYPE_IS_STR(value->definition->type)) &&
	     value->element_count == 1 &&
	     rrr_array_has_tag(array_data, value->tag) &&
	     rrr_array_get_value_str_by_tag(&str, array_data, value->tag) == 0 &&
	     rrr_json_check_object(value->data, value->total_stored_length) == 0 &&
	     rrr_json_check_object(str, rrr_length_from_size_t_bug_const(strlen(str))) == 0
	) {
		RRR_DBG_3("Value '%s' contains JSON in raft patch, patching JSON object.\n",
			value->tag);

		struct raft_patch_array_json_callback_data callback_data = {
			array_data,
			value->tag
		};

		if ((ret = rrr_json_patch (
				str,
				rrr_length_from_size_t_bug_const(strlen(str)),
				value->data,
				value->total_stored_length,
				raft_patch_array_json_callback,
				&callback_data
		)) != 0) {
			goto out;
		}
	}
	else {
#else
	if (1) {
#endif
		rrr_array_clear_by_tag(array_data, value->tag);

#ifdef RRR_WITH_JSONC
		RRR_DBG_3("Value '%s' in raft patch is not a blob or string with a single value containing JSON while patching, replacing whole array value.\n",
			value->tag);
#else
		RRR_DBG_3("Replacing whole array value for '%s' while patching in raft.\n",
			value->tag);
#endif

		if ((ret = rrr_type_value_clone(&value_new, value, 1 /* With data */)) != 0) {
			goto out;
		}

		RRR_LL_APPEND(array_data, value_new);
	}

	out:
	RRR_FREE_IF_NOT_NULL(str);
	return ret;
}

static int raft_patch_callback (RRR_RAFT_PATCH_CB_ARGS) {
	int ret = 0;

	uint16_t version_dummy;
	struct rrr_array array_data = {0};

	// NOTE ! This callback is called from forked raft server context

	if (MSG_IS_ARRAY(msg_orig)) {
		if ((ret = rrr_array_message_append_to_array(&version_dummy, &array_data, msg_orig)) != 0) {
			goto out;
		}

		if ((ret = rrr_array_message_iterate_values (
				msg_patch,
				raft_patch_array_callback,
				&array_data
		)) != 0) {
			goto out;
		}

		if ((ret = rrr_array_new_message_from_array (
				msg_new,
				&array_data,
				0,
				MSG_TOPIC_PTR(msg_orig),
				MSG_TOPIC_LENGTH(msg_orig)
		)) != 0) {
			goto out;
		}
	}
	else {
		assert(0 && "Data patch not implemented\n");
	}

	(*msg_new)->msg_value = msg_orig->msg_value;
	(*msg_new)->timestamp = msg_orig->timestamp;
	(*msg_new)->type_and_class = msg_orig->type_and_class;

	out:
	rrr_array_clear(&array_data);
	return ret;
}

static int raft_fork (void *arg) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	int ret = 0;

	int socketpair[2] = {0}, i;
	unsigned long long id;
	char *end, *path;
	struct rrr_raft_server *servers = NULL;

	if ((ret = raft_parse_config(data, INSTANCE_D_CONFIG(thread_data))) != 0) {
		goto out_err;
	}

	if ((servers = rrr_allocate_zero(sizeof(*servers) * (RRR_LL_COUNT(&data->servers) + 1))) == NULL) {
		RRR_MSG_0("Failed to allocate servers structure in %s\n", __func__);
		ret = 1;
		goto out_err;
	}

	if ((ret = rrr_socketpair (AF_UNIX, SOCK_STREAM, 0, INSTANCE_D_NAME(thread_data), socketpair)) != 0) {
		RRR_MSG_0("Failed to create sockets in %s: %s\n",
			rrr_strerror(errno));
		goto out_err;
	}

	i = 0;
	RRR_MAP_ITERATE_BEGIN(&data->servers);
		id = strtoull(node_value, &end, 10);
		if (end == NULL || id < 1 || id > INT32_MAX || *end != '\0') {
			RRR_MSG_0("Invalid value '%s' for ID of server '%s' in configuration of raft instance %s. Ensure that ID is set after '->' separator.\n",
				node_value, node_tag, INSTANCE_D_NAME(thread_data));
			ret = 1;
			goto out_err;
		}
		if (strlen(node_tag) > sizeof(servers[0].address) - 1) {
			RRR_MSG_0("Server name '%s' too long in configuration of raft instance %s, may not exceed %lu characters.\n",
				node_tag, sizeof(servers[0].address) - 1);
			ret = 1;
			goto out_err;
		}

		servers[i].id = rrr_int_from_slength_bug_const(id);
		strcpy(servers[i].address, node_tag);

		i++;	
	RRR_MAP_ITERATE_END();

	if ((ret = rrr_util_fs_dir_ensure(data->directory)) != 0) {
		RRR_MSG_0("Failed to ensure server base directory %s in raft instance %s: %s\n",
			data->directory, INSTANCE_D_NAME(thread_data), rrr_strerror(errno));
		goto out;
	}

	if (rrr_asprintf(&path, "%s/%" PRIi64, data->directory, servers[0].id) <= 0) {
		RRR_MSG_0("Failed to create path in %s]\n", __func__);
		ret = 1;
		goto out_err;
	}

	if ((ret = rrr_util_fs_dir_ensure(path)) != 0) {
		RRR_MSG_0("Failed to ensure server directory %s in raft instance %s: %s\n",
			path, INSTANCE_D_NAME(thread_data), rrr_strerror(errno));
		goto out;
	}

	if ((ret = rrr_raft_channel_fork (
			&data->channel,
			INSTANCE_D_FORK(thread_data),
			INSTANCE_D_EVENTS(thread_data),
			INSTANCE_D_NAME(thread_data),
			socketpair,
			servers,
			0, /* Self index, assume it to be first in servers list */
			path,
			raft_pong_callback,
			raft_ack_callback,
			raft_opt_callback,
			raft_msg_callback,
			data,
			raft_patch_callback
	)) != 0) {
		RRR_MSG_0("Failed to create raft for in raft instance %s\n",
			INSTANCE_D_NAME(thread_data));
		goto out_err;
	}

	goto out;
	out_err:
		raft_data_cleanup(data);
	out:
		RRR_FREE_IF_NOT_NULL(servers);
		RRR_FREE_IF_NOT_NULL(path);
		if (socketpair[0] > 0)
			rrr_socket_close(socketpair[0]);
		if (socketpair[1] > 0)
			rrr_socket_close(socketpair[1]);
		return ret;
}

static int raft_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data;

	uint32_t req_index;

	if (rrr_raft_channel_request_opt(&req_index, data->channel) != 0) {
		RRR_MSG_0("Failed to send OPT request to raft node in raft instance %s\n",
			INSTANCE_D_NAME(thread_data));
		return RRR_EVENT_ERR;
	}

	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(thread);
}

static int raft_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	raft_data_init(data, thread_data);

	if (rrr_thread_start_condition_helper_fork(thread, raft_fork, thread) != 0) {
		RRR_MSG_0("Forking failed in raft instance %s\n", INSTANCE_D_NAME(thread_data));
		return 1;
	}

	RRR_DBG_1 ("raft thread data is %p\n", thread_data);

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("raft instance %s started thread\n",
			INSTANCE_D_NAME(thread_data));

	rrr_event_function_periodic_set (
			INSTANCE_D_EVENTS_H(thread_data),
			1 * 1000 * 1000, // 1 second
			raft_periodic
	);

	RRR_DBG_1 ("Thread raft %p exiting\n", thread);
	return 0;
}

static void raft_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct raft_data *data = thread_data->private_data = thread_data->private_memory;

	(void)(strike);

	raft_data_cleanup(data);

	rrr_event_receiver_reset(INSTANCE_D_EVENTS_H(thread_data));

	*deinit_complete = 1;
}

struct rrr_instance_event_functions event_functions = {
	raft_event_broker_data_available
};

static const char *module_name = "raft";

void load (struct rrr_instance_module_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_FLEXIBLE;
	data->event_functions = event_functions;
	data->init = raft_init;
	data->deinit = raft_deinit;
}

void unload (void) {
	RRR_DBG_1 ("Destroy raft module\n");
}

