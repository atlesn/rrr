/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "ip_buffer_entry_util.h"

#include "log.h"
#include "mqtt/mqtt_topic.h"
#include "ip_buffer_entry.h"
#include "messages.h"

int rrr_ip_buffer_entry_util_message_topic_match (
		int *does_match,
		const struct rrr_ip_buffer_entry *entry,
		const struct rrr_mqtt_topic_token *filter_first_token
) {
	const struct rrr_message *message = entry->message;

	int ret = 0;

	*does_match = 0;

	struct rrr_mqtt_topic_token *entry_first_token = NULL;

	if ((rrr_slength) entry->data_length < (rrr_slength) sizeof(*message) || !MSG_IS_MSG(message) || MSG_TOPIC_LENGTH(message) == 0) {
		goto out;
	}

	if (rrr_mqtt_topic_validate_name_with_end (
			MSG_TOPIC_PTR(message),
			MSG_TOPIC_PTR(message) + MSG_TOPIC_LENGTH(message)
	) != 0) {
		RRR_MSG_0("Warning: Invalid syntax found in message while matching topic\n");
		ret = 0;
		goto out;
	}

	if (rrr_mqtt_topic_tokenize_with_end (
			&entry_first_token,
			MSG_TOPIC_PTR(message),
			MSG_TOPIC_PTR(message) + MSG_TOPIC_LENGTH(message)
	) != 0) {
		RRR_MSG_0("Tokenizing of topic failed in rrr_ip_buffer_entry_message_topic_match\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_mqtt_topic_match_tokens_recursively(filter_first_token, entry_first_token)) != RRR_MQTT_TOKEN_MATCH) {
		ret = 0;
		goto out;
	}

	*does_match = 1;

	out:
	rrr_mqtt_topic_token_destroy(entry_first_token);
	return ret;
}

void rrr_ip_buffer_entry_util_unlock (
		struct rrr_ip_buffer_entry *entry
) {
	rrr_ip_buffer_entry_unlock(entry);
}
