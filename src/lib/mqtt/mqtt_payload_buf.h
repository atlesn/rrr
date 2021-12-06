/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include "../rrr_types.h"

#ifndef RRR_MQTT_PAYLOAD_BUF_H
#define RRR_MQTT_PAYLOAD_BUF_H

#define RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE 64

#define RRR_MQTT_PAYLOAD_BUF_OK 0
#define RRR_MQTT_PAYLOAD_BUF_ERR 1

struct rrr_nullsafe_str;

struct rrr_mqtt_payload_buf_session {
	char *buf;
	char *wpos;
	char *wpos_max;
	rrr_length buf_size;
};

int rrr_mqtt_payload_buf_init (struct rrr_mqtt_payload_buf_session *session);
void rrr_mqtt_payload_buf_destroy (struct rrr_mqtt_payload_buf_session *session);
void rrr_mqtt_payload_buf_dump (struct rrr_mqtt_payload_buf_session *session);
int rrr_mqtt_payload_buf_ensure (struct rrr_mqtt_payload_buf_session *session, rrr_length size);
rrr_length rrr_mqtt_payload_buf_get_touched_size (struct rrr_mqtt_payload_buf_session *session);
char *rrr_mqtt_payload_buf_extract_buffer (struct rrr_mqtt_payload_buf_session *session);
int rrr_mqtt_payload_buf_put_nullsafe (
		struct rrr_mqtt_payload_buf_session *session,
		const struct rrr_nullsafe_str *str
);
int rrr_mqtt_payload_buf_put_raw (
		struct rrr_mqtt_payload_buf_session *session,
		const void *data,
		rrr_length size
);
int rrr_mqtt_payload_buf_put_raw_at_offset (
		struct rrr_mqtt_payload_buf_session *session,
		const void *data,
		rrr_length size,
		rrr_length offset
);
int rrr_mqtt_payload_buf_put_variable_int (
		struct rrr_mqtt_payload_buf_session *session,
		uint32_t value
);
static inline rrr_length rrr_mqtt_payload_buf_get_written_size (struct rrr_mqtt_payload_buf_session *session) {
	return rrr_length_from_ptr_sub_bug_const (session->wpos, session->buf);
}

#endif /* RRR_MQTT_PAYLOAD_BUF_H */
