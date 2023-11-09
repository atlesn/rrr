/*

Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "../log.h"
#include "../allocator.h"

#include "stats_message.h"

#include "../read.h"
#include "../read_constants.h"
#include "../util/rrr_endian.h"
#include "../helpers/string_builder.h"

int rrr_msg_stats_unpack (
		struct rrr_msg_stats *target,
		const struct rrr_msg_stats_packed *source,
		rrr_length expected_size
) {
	int ret = 0;

	if (expected_size < sizeof(*source) - sizeof(source->path_and_data)) {
		RRR_MSG_0("Received statistics message which was too short in rrr_msg_stats_unpack_callback\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (expected_size > sizeof(*source)) {
		RRR_MSG_0("Received statistics message which was too long in rrr_msg_stats_unpack_callback\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	uint16_t path_size = rrr_be16toh(source->path_size);
	uint32_t flags = rrr_be32toh(source->flags);
	uint8_t type = source->type;

	if ((flags & (unsigned int) ~(RRR_STATS_MESSAGE_FLAGS_ALL)) != 0) {
		RRR_MSG_0("Unknown flags %u in received statistics packet\n", flags);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	switch (type) {
		case RRR_STATS_MESSAGE_TYPE_KEEPALIVE:    break;
		case RRR_STATS_MESSAGE_TYPE_TEXT:         break;
		case RRR_STATS_MESSAGE_TYPE_BASE10_TEXT:  break;
		case RRR_STATS_MESSAGE_TYPE_DOUBLE_TEXT:  break;
		default:
			RRR_MSG_0("Unknown type %u in received statistics packet\n", type);
			ret = RRR_READ_SOFT_ERROR;
			goto out;
	};

	rrr_length actual_path_and_data_size = rrr_length_from_size_t_bug_const(expected_size - (sizeof(*source) - sizeof(source->path_and_data)));
	if (path_size > actual_path_and_data_size) {
		RRR_MSG_0("Path size in received statistics packet exceeds packet size\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	memset (target, '\0', sizeof(*target));

	target->flags = flags;
	target->type = type;
	target->timestamp = source->msg_value; // Already byte-swapped by socket framework

	rrr_length data_size = actual_path_and_data_size - path_size;
	if (data_size > 0) {
		memcpy(target->data, source->path_and_data + path_size, data_size);
		target->data_size = data_size;
	}

	if (path_size > 0) {
		if (source->path_and_data[path_size-1] != '\0') {
			RRR_MSG_0("Path was not zero-terminated in received statistics packet\n");
			ret = RRR_READ_SOFT_ERROR;
			goto out;
		}
		memcpy(target->path, source->path_and_data, path_size);
	}

	out:
	return ret;
}

void rrr_msg_stats_pack_and_flip (
		struct rrr_msg_stats_packed *target,
		rrr_length *total_size,
		const struct rrr_msg_stats *source
) {
	rrr_length path_size = rrr_length_inc_bug_const(rrr_length_from_size_t_bug_const(strlen(source->path)));
	rrr_length path_and_data_size = path_size + source->data_size;

	RRR_ASSERT(RRR_LENGTH_MAX > RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1,rrr_length_cannot_hold_stats_message_path);
	RRR_ASSERT(RRR_LENGTH_MAX > RRR_STATS_MESSAGE_DATA_MAX_SIZE,rrr_length_cannot_hold_stats_message_data);

	*total_size = sizeof(*target) - sizeof(target->path_and_data) + path_and_data_size;

	target->type = source->type;
	target->flags = rrr_htobe32(source->flags);
	target->path_size = rrr_htobe16((uint16_t) path_size);

	memcpy(target->path_and_data, source->path, path_size);
	memcpy(target->path_and_data + path_size, source->data, source->data_size);
}

int rrr_msg_stats_init (
		struct rrr_msg_stats *message,
		uint8_t type,
		uint32_t flags,
		const char *path_postfix,
		const void *data,
		uint32_t data_size
) {
	memset(message, '\0', sizeof(*message));

	if (strlen(path_postfix) > RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		RRR_MSG_0("Path postfix was too long in __rrr_msg_stats_init\n");
		return 1;
	}

	if (data_size > RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		RRR_MSG_0("Data was too long in __rrr_msg_stats_init\n");
		return 1;
	}

	strcpy(message->path, path_postfix);
	message->type = type;
	message->flags = flags;
	message->data_size = data_size;
	if (data_size > 0) {
		if (data == NULL) {
			RRR_BUG("data was NULL while data_size was >0 in rrr_msg_stats_init\n");
		}
		memcpy(message->data, data, data_size);
	}

	return 0;
}

int rrr_msg_stats_new_empty (
		struct rrr_msg_stats **message
) {
	int ret = 0;
	*message = NULL;

	struct rrr_msg_stats *new_message = rrr_allocate(sizeof(*new_message));
	if (new_message == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_msg_stats_new_empty");
		ret = 1;
		goto out;
	}

	*message = new_message;

	out:
	return ret;
}

int rrr_msg_stats_new (
		struct rrr_msg_stats **message,
		uint8_t type,
		uint32_t flags,
		const char *path_postfix,
		const void *data,
		uint32_t data_size
) {
	int ret = 0;
	*message = NULL;

	struct rrr_msg_stats *new_message;
	if (rrr_msg_stats_new_empty (&new_message) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_msg_stats_new");
		ret = 1;
		goto out;
	}

	if (rrr_msg_stats_init(new_message, type, flags, path_postfix, data, data_size) != 0) {
		RRR_MSG_0("Could not initialize message in rrr_msg_stats_new\n");
		ret = 1;
		goto out_free;
	}

	*message = new_message;
	goto out;

	out_free:
		rrr_free(new_message);
	out:
		return ret;
}

int rrr_msg_stats_new_log (
		struct rrr_msg_stats **message,
		const void *data,
		uint32_t data_size
) {
	return rrr_msg_stats_new (
			message,
			RRR_STATS_MESSAGE_TYPE_TEXT,
			RRR_STATS_MESSAGE_FLAGS_LOG,
			RRR_STATS_MESSAGE_PATH_GLOBAL_LOG_HOOK,
			data,
			data_size
	);
}

int rrr_msg_stats_init_event (
		struct rrr_msg_stats *message,
		const void *data,
		uint32_t data_size
) {
	return rrr_msg_stats_init (
			message,
			RRR_STATS_MESSAGE_TYPE_TEXT,
			RRR_STATS_MESSAGE_FLAGS_EVENT,
			RRR_STATS_MESSAGE_PATH_GLOBAL_EVENT_HOOK,
			data,
			data_size
	);
}

int rrr_msg_stats_init_rrr_msg_preface (
		struct rrr_msg_stats *message,
		const char *path_postfix,
		const char **hops,
		uint32_t hops_count
) {
	int ret = 0;

	char path[128];
	struct rrr_string_builder sb = {0};

	if (snprintf(path, sizeof(path), "%s/%s", RRR_STATS_MESSAGE_PATH_GLOBAL_MSG_HOOK, path_postfix) == sizeof(path)) {
		RRR_BUG("Path was too long in %s\n", __func__);
	}

	ret |= rrr_string_builder_append(&sb, "nexthops:");
	for (uint32_t i = 0; i < hops_count; i++) {
		ret |= rrr_string_builder_append(&sb, hops[i]);
		if (i < hops_count - 1) {
			ret |= rrr_string_builder_append(&sb, ",");
		}
	}

	if (ret != 0) {
		RRR_MSG_0("Could not append to string builder in %s\n", __func__);
		goto out;
	}

	if (sb.wpos >= RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		RRR_MSG_0("String builder was too long in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_msg_stats_init (
			message,
			RRR_STATS_MESSAGE_TYPE_TEXT,
			RRR_STATS_MESSAGE_FLAGS_RRR_MSG_PREFACE,
			path,
			sb.buf,
			sb.wpos
	)) != 0) {
		goto out;
	}

	out:
	rrr_string_builder_clear(&sb);
	return ret;
}

int rrr_msg_stats_set_path (
		struct rrr_msg_stats *message,
		const char *path
) {
	if (strlen(path) > RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		RRR_MSG_0("Path was too long in rrr_msg_stats_set_path\n");
		return 1;
	}
	strcpy(message->path, path);
	return 0;
}

int rrr_msg_stats_duplicate (
		struct rrr_msg_stats **target,
		const struct rrr_msg_stats *source
) {
	int ret = 0;
	*target = NULL;

	struct rrr_msg_stats *new_message;
	if (rrr_msg_stats_new_empty (&new_message) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_msg_stats_new");
		ret = 1;
		goto out;
	}

	memcpy(new_message, source, sizeof(*new_message));

	*target = new_message;

	out:
	return ret;
}

int rrr_msg_stats_destroy (
		struct rrr_msg_stats *message
) {
	rrr_free(message);
	return 0;
}

