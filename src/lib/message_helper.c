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

#include <assert.h>

#include "message_helper.h"

#include "message_holder/message_holder_struct.h"
#include "messages/msg_msg.h"
#include "array.h"

int rrr_message_helper_topic_match (
		int *does_match,
		const struct rrr_msg_msg *msg,
		const struct rrr_mqtt_topic_token *token
) {
	int ret = 0;

	*does_match = 0;

	assert(RRR_MSG_IS_RRR_MESSAGE(msg));

	if (MSG_TOPIC_LENGTH(msg) > 0 && rrr_msg_msg_topic_match (
			does_match,
			msg,
			token
	) != 0) {
		RRR_MSG_0("Error while matching topic against topic filter\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_message_helper_has_array_tag (
		int *does_have,
		const struct rrr_msg_msg *msg,
		const char *tag
) {
	int ret = 0;

	*does_have = 0;

	assert(RRR_MSG_IS_RRR_MESSAGE(msg));

	*does_have = rrr_array_message_has_tag (msg, tag);

	return ret;
}

int rrr_message_helper_entry_topic_match (
		int *does_match,
		const struct rrr_msg_holder *entry,
		const struct rrr_mqtt_topic_token *token
) {
	const struct rrr_msg_msg *msg = entry->message;
	assert(entry->data_length >= MSG_MIN_SIZE(msg));
	return rrr_message_helper_topic_match(does_match, msg, token);
}

int rrr_message_helper_entry_has_array_tag (
		int *does_have,
		const struct rrr_msg_holder *entry,
		const char *tag
) {
	const struct rrr_msg_msg *msg = entry->message;
	assert(entry->data_length >= MSG_MIN_SIZE(msg));
	return rrr_message_helper_has_array_tag(does_have, msg, tag);
}
