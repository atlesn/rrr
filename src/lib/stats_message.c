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

#include "../global.h"
#include "stats_message.h"

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
		VL_MSG_ERR("Path postfix was too long in __rrr_stats_message_init\n");
		return 1;
	}

	if (data_size > RRR_STATS_MESSAGE_DATA_MAX_SIZE) {
		VL_MSG_ERR("Data was too long in __rrr_stats_message_init\n");
		return 1;
	}

	message->type = type;
	message->flags = flags;
	message->data_size = data_size;
	memcpy(message->data, data, data_size);

	return 0;
}

int rrr_stats_message_new_empty (
		struct rrr_stats_message **message
) {
	int ret = 0;
	*message = NULL;

	struct rrr_stats_message *new_message = malloc(sizeof(*message));
	if (new_message == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_stats_message_new_empty");
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
		VL_MSG_ERR("Could not allocate memory in rrr_stats_message_new");
		ret = 1;
		goto out;
	}

	if (rrr_stats_message_init(new_message, type, flags, path_postfix, data, data_size) != 0) {
		VL_MSG_ERR("Could not initialize message in rrr_stats_message_new\n");
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

int rrr_stats_message_duplicate (
		struct rrr_stats_message **target,
		const struct rrr_stats_message *source
) {
	int ret = 0;
	*target = NULL;

	struct rrr_stats_message *new_message;
	if (rrr_stats_message_new_empty (&new_message) != 0) {
		VL_MSG_ERR("Could not allocate memory in rrr_stats_message_new");
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

