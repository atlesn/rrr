/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#include "stats_message.h"

#include "../rrr_endian.h"
#include "../read.h"
#include "../read_constants.h"


int rrr_stats_message_unpack_callback (
		struct rrr_read_session *read_session,
		void *private_arg
) {
	struct rrr_stats_message_unpack_callback_data *data = private_arg;

	int ret = 0;

	struct rrr_stats_message_packed *source = (struct rrr_stats_message_packed *) read_session->rx_buf_ptr;

	if (read_session->rx_buf_wpos < 0) {
		RRR_BUG("negative wpos in rrr_stats_message_unpack_callback\n");
	}

	size_t received_size = read_session->rx_buf_wpos;

	if (received_size < sizeof(*source) - sizeof(source->path_and_data)) {
		RRR_MSG_0("Received statistics message which was too short in rrr_stats_message_unpack_callback\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (received_size > sizeof(*source)) {
		RRR_MSG_0("Received statistics message which was too long in rrr_stats_message_unpack_callback\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	uint16_t path_size = rrr_be16toh(source->path_size);
	uint32_t flags = rrr_be32toh(source->flags);
	uint8_t type = source->type;

	if ((flags & ~(RRR_STATS_MESSAGE_FLAGS_ALL)) != 0) {
		RRR_MSG_0("Unknown flags %u in received statistics packet\n", flags);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	switch (type) {
		case RRR_STATS_MESSAGE_TYPE_TEXT:			break;
		case RRR_STATS_MESSAGE_TYPE_BASE10_TEXT:	break;
		case RRR_STATS_MESSAGE_TYPE_DOUBLE_TEXT:	break;
		default:
			RRR_MSG_0("Unknown type %u in received statistics packet\n", type);
			ret = RRR_READ_SOFT_ERROR;
			goto out;
	};

	size_t actual_path_and_data_size = received_size - (sizeof(*source) - sizeof(source->path_and_data));
	if (path_size > actual_path_and_data_size) {
		RRR_MSG_0("Path size in received statistics packet exceeds packet size\n");
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	struct rrr_stats_message target;
	memset (&target, '\0', sizeof(target));

	target.flags = flags;
	target.type = type;
	target.timestamp = source->msg_value; // Already byte-swapped by socket framework

	size_t data_size = actual_path_and_data_size - path_size;
	if (data_size > 0) {
		memcpy(target.data, source->path_and_data + path_size, data_size);
		target.data_size = data_size;
	}

	if (path_size > 0) {
		if (source->path_and_data[path_size-1] != '\0') {
			RRR_MSG_0("Path was not zero-terminated in received statistics packet\n");
			ret = RRR_READ_SOFT_ERROR;
			goto out;
		}
		memcpy(target.path, source->path_and_data, path_size);
	}

	if ((ret = data->callback(&target, data->private_arg)) != 0) {
		RRR_MSG_0("Error from callback in rrr_stats_message_unpack_callback, return was %i\n", ret);
		goto out;
	}

	out:
	return ret;
}

void rrr_stats_message_pack_and_flip (
		struct rrr_stats_message_packed *target,
		size_t *total_size,
		const struct rrr_stats_message *source
) {
	uint16_t path_size = strlen(source->path) + 1;
	size_t path_and_data_size = path_size + source->data_size;

	if (path_and_data_size > RRR_STATS_MESSAGE_DATA_MAX_SIZE + RRR_STATS_MESSAGE_PATH_MAX_LENGTH + 1) {
		RRR_BUG("BUG: path + data too long in rrr_stats_message_pack_and_flip\n");
	}

	*total_size = sizeof(*target) - sizeof(target->path_and_data) + path_and_data_size;

	target->type = source->type;
	target->flags = rrr_htobe32(source->flags);
	target->path_size = rrr_htobe16(path_size);

	memcpy(target->path_and_data, source->path, path_size);
	memcpy(target->path_and_data + path_size, source->data, source->data_size);
}

int rrr_stats_message_init (
		struct rrr_stats_message *message,
		uint8_t type,
		uint32_t flags,
		const char *path_postfix,
		const void *data,
		uint32_t data_size
) {
	memset(message, '\0', sizeof(*message));

	if (strlen(path_postfix) > RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		RRR_MSG_0("Path postfix was too long in __rrr_stats_message_init\n");
		return 1;
	}

	if (data_size > RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		RRR_MSG_0("Data was too long in __rrr_stats_message_init\n");
		return 1;
	}

	strcpy(message->path, path_postfix);
	message->type = type;
	message->flags = flags;
	message->data_size = data_size;
	if (data_size > 0) {
		if (data == NULL) {
			RRR_BUG("data was NULL while data_size was >0 in rrr_stats_message_init\n");
		}
		memcpy(message->data, data, data_size);
	}

	return 0;
}

int rrr_stats_message_new_empty (
		struct rrr_stats_message **message
) {
	int ret = 0;
	*message = NULL;

	struct rrr_stats_message *new_message = malloc(sizeof(*new_message));
	if (new_message == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_stats_message_new_empty");
		ret = 1;
		goto out;
	}

	*message = new_message;

	out:
	return ret;
}

int rrr_stats_message_new (
		struct rrr_stats_message **message,
		uint8_t type,
		uint32_t flags,
		const char *path_postfix,
		const void *data,
		uint32_t data_size
) {
	int ret = 0;
	*message = NULL;

	// TODO : Support large messages?

	struct rrr_stats_message *new_message;
	if (rrr_stats_message_new_empty (&new_message) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_stats_message_new");
		ret = 1;
		goto out;
	}

	if (rrr_stats_message_init(new_message, type, flags, path_postfix, data, data_size) != 0) {
		RRR_MSG_0("Could not initialize message in rrr_stats_message_new\n");
		ret = 1;
		goto out_free;
	}

	*message = new_message;
	goto out;

	out_free:
		free(new_message);
	out:
		return ret;
}

int rrr_stats_message_set_path (
		struct rrr_stats_message *message,
		const char *path
) {
	if (strlen(path) > RRR_STATS_MESSAGE_PATH_MAX_LENGTH) {
		RRR_MSG_0("Path was too long in rrr_stats_message_set_path\n");
		return 1;
	}
	strcpy(message->path, path);
	return 0;
}

int rrr_stats_message_duplicate (
		struct rrr_stats_message **target,
		const struct rrr_stats_message *source
) {
	int ret = 0;
	*target = NULL;

	struct rrr_stats_message *new_message;
	if (rrr_stats_message_new_empty (&new_message) != 0) {
		RRR_MSG_0("Could not allocate memory in rrr_stats_message_new");
		ret = 1;
		goto out;
	}

	memcpy(new_message, source, sizeof(*new_message));

	*target = new_message;

	out:
	return ret;
}

int rrr_stats_message_destroy (
		struct rrr_stats_message *message
) {
	free(message);
	return 0;
}

