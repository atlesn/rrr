/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include <stddef.h>

#include "discern_stack_helper.h"

#include "log.h"
#include "array.h"
#include "message_helper.h"
#include "allocator.h"
#include "messages/msg_msg_struct.h"
#include "mqtt/mqtt_topic.h"

int rrr_discern_stack_helper_topic_filter_resolve_cb (RRR_DISCERN_STACK_RESOLVE_TOPIC_FILTER_CB_ARGS) {
	struct rrr_discern_stack_helper_callback_data *callback_data = arg;
	const rrr_u16 topic_length = MSG_TOPIC_LENGTH(callback_data->msg);
	const char *topic = MSG_TOPIC_PTR(callback_data->msg);

	int ret = 0;

	*result = 0;

	if (topic_length == 0) {
		goto out;
	}

	if ((rrr_mqtt_topic_match_topic_and_linear_with_end (
			topic,
			topic + topic_length,
			topic_filter,
			topic_filter + topic_filter_size - 1
	)) == RRR_MQTT_TOKEN_MISMATCH) {
		goto out;
	}

	*result = 1;

	out:
	RRR_DBG_3("+ Topic filter %s is a %s\n", topic_filter, (*result ? "MATCH" : "MISMATCH"));
	return ret;
}

int rrr_discern_stack_helper_array_tag_resolve_cb (RRR_DISCERN_STACK_RESOLVE_ARRAY_TAG_CB_ARGS) {
	struct rrr_discern_stack_helper_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_array array = {0};

	if (!MSG_IS_ARRAY(callback_data->msg)) {
		*result = 0;
		goto not_array;
	}

	uint16_t version;
	if ((ret = rrr_array_message_append_to_array (
			&version,
			&array,
			callback_data->msg
	)) != 0) {
		goto out;
	}

	if (!callback_data->index_produced) {
		struct rrr_discern_stack_index_entry *entry;
		if ((entry = rrr_allocate(rrr_length_from_slength_bug_const(RRR_LL_COUNT(&array)) * sizeof(*entry))) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}

		rrr_length wpos = 0;
		RRR_LL_ITERATE_BEGIN(&array, struct rrr_type_value);
			if (!(node->tag_length > 0))
				RRR_LL_ITERATE_NEXT();
			entry[wpos++].id = RRR_DISCERN_STACK_FIRST_LAST_INDEX(node->tag, node->tag_length);
		RRR_LL_ITERATE_END();

		*new_index = entry;
		*new_index_size = wpos;

		callback_data->index_produced = 1;
	}

	*result = rrr_array_has_tag(&array, tag) != 0;

	not_array:

	RRR_DBG_3("+ Array tag check result for %s is %s\n",
			tag, (*result ? "HAS" : "HASN'T"));

	out:
	rrr_array_clear(&array);
	return ret;
}
