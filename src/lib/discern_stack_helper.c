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
#include "message_helper.h"
#include "mqtt/mqtt_topic.h"

int rrr_discern_stack_helper_topic_filter_resolve_cb (
		rrr_length *result,
		const char *topic_filter,
		void *arg
) {
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

int rrr_discern_stack_helper_array_tag_resolve_cb (
		rrr_length *result,
		const char *array_tag,
		void *arg
) {
	struct rrr_discern_stack_helper_callback_data *callback_data = arg;

	int ret = 0;

	int result_tmp = 0;
	if ((ret = rrr_message_helper_has_array_tag (
			&result_tmp,
			callback_data->msg,
			array_tag
	)) != 0) {
		goto out;
	}
	*result = result_tmp != 0;

	RRR_DBG_3("+ Array tag check result for %s is %s\n",
			array_tag, (*result ? "HAS" : "HASN'T"));

	out:
	return ret;
}
