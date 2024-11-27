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

#ifndef RRR_MESSAGE_HELPER_H
#define RRR_MESSAGE_HELPER_H

struct rrr_msg_msg;
struct rrr_msg_holder;
struct rrr_mqtt_topic_token;

int rrr_message_helper_topic_match (
		int *does_match,
		const struct rrr_msg_msg *msg,
		const struct rrr_mqtt_topic_token *token
);
int rrr_message_helper_has_array_tag (
		int *does_have,
		const struct rrr_msg_msg *msg,
		const char *tag
);
int rrr_message_helper_entry_topic_match (
		int *does_match,
		const struct rrr_msg_holder *entry,
		const struct rrr_mqtt_topic_token *token
);
int rrr_message_helper_entry_has_array_tag (
		int *does_have,
		const struct rrr_msg_holder *entry,
		const char *tag
);

#endif /* RRR_MESSAGE_HELPER_H */
