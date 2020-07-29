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

#ifndef RRR_IP_BUFFER_ENTRY_UTIL_H
#define RRR_IP_BUFFER_ENTRY_UTIL_H

struct rrr_ip_buffer_entry;
struct rrr_mqtt_topic_token;

int rrr_ip_buffer_entry_util_message_topic_match (
		int *does_match,
		const struct rrr_ip_buffer_entry *entry,
		const struct rrr_mqtt_topic_token *filter_first_token
);
void rrr_ip_buffer_entry_util_unlock (
		struct rrr_ip_buffer_entry *entry
);

#endif /* RRR_IP_BUFFER_ENTRY_UTIL_H */
