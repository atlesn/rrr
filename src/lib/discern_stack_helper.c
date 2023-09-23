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
#include "mqtt/mqtt_topic.h"

int rrr_discern_stack_helper_topic_filter_resolve_cb (RRR_DISCERN_STACK_RESOLVE_TOPIC_FILTER_CB_ARGS) {
	struct rrr_discern_stack_helper_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_mqtt_topic_token *token = NULL;

	if ((ret = rrr_mqtt_topic_tokenize(&token, topic_filter)) != 0) {
		RRR_MSG_0("Failed to tokenize topic in %s\n", __func__);
		goto out;
	}

	int result_tmp = 0;
	if ((ret = rrr_message_helper_topic_match(&result_tmp, callback_data->msg, token)) != 0) {
		RRR_MSG_0("Failed to match topic in %s\n", __func__);
		goto out;
	}
	*result = result_tmp != 0;

	RRR_DBG_3("+ Topic filter %s is a %s\n",
			topic_filter, (*result ? "MATCH" : "MISMATCH"));
	out:
	rrr_mqtt_topic_token_destroy(token);
	return ret;
}

int rrr_discern_stack_helper_array_tag_resolve_cb (RRR_DISCERN_STACK_RESOLVE_ARRAY_TAG_CB_ARGS) {
	struct rrr_discern_stack_helper_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_array array = {0};

	uint16_t version;
	if ((ret = rrr_array_message_append_to_array (
			&version,
			&array,
			callback_data->msg
	)) != 0) {
		goto out;
	}

	if (!callback_data->index_produced) {
		struct rrr_discern_stack_index_entry *entry, *entry_first;
		if ((entry = entry_first = rrr_allocate(rrr_length_from_slength_bug_const(RRR_LL_COUNT(&array)) * sizeof(*entry))) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}

		RRR_LL_ITERATE_BEGIN(&array, struct rrr_type_value);
			if (!(node->tag_length > 0))
				RRR_LL_ITERATE_NEXT();
			(entry++)->id = ((rrr_length) node->tag[0] << 16) | (rrr_length) (node->tag[node->tag_length - 1]);
		RRR_LL_ITERATE_END();

		*new_index = entry_first;
		*new_index_size = rrr_length_from_slength_bug_const(RRR_LL_COUNT(&array));

		callback_data->index_produced = 1;
	}

	*result = rrr_array_has_tag(&array, tag) != 0;

	RRR_DBG_3("+ Array tag check result for %s is %s\n",
			tag, (*result ? "HAS" : "HASN'T"));

	out:
	rrr_array_clear(&array);
	return ret;
}
