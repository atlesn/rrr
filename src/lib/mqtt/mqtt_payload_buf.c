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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../log.h"

#include "mqtt_payload_buf.h"
#include "../macro_utils.h"

int rrr_mqtt_payload_buf_init (struct rrr_mqtt_payload_buf_session *session) {
	memset(session, '\0', sizeof(*session));
	session->buf = malloc(RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE);
	if (session->buf == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_payload_buf_init\n");
		return RRR_MQTT_PAYLOAD_BUF_ERR;
	}
	memset(session->buf, '\0', RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE);
	session->buf_size = RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE;
	session->wpos = session->buf;
	session->wpos_max = session->buf;
	return RRR_MQTT_PAYLOAD_BUF_OK;
}

 void rrr_mqtt_payload_buf_destroy (struct rrr_mqtt_payload_buf_session *session) {
	RRR_FREE_IF_NOT_NULL(session->buf);
}

void rrr_mqtt_payload_buf_dump (struct rrr_mqtt_payload_buf_session *session) {
	const char *pos = session->buf;
	const char *end = session->wpos_max;

	printf ("Dumping payload buffer wpos_max %p: ", (void*) (session->wpos_max - session->buf));
	while (pos < end) {
		uint8_t c = *pos;
		printf("0x");
		printf("%02x ", c);
		pos++;
	}
	printf("\n");
}

int rrr_mqtt_payload_buf_ensure (struct rrr_mqtt_payload_buf_session *session, ssize_t size) {
	if (size <= 0) {
		RRR_BUG("size was <= 0 in rrr_mqtt_payload_buf_ensure\n");
	}

	if (session->wpos + size <= session->buf + session->buf_size) {
		return RRR_MQTT_PAYLOAD_BUF_OK;
	}

	ssize_t old_wpos_max = session->wpos_max - session->buf;
	ssize_t old_wpos = session->wpos - session->buf;
	ssize_t new_size = (session->wpos + size) - session->buf;
	ssize_t size_diff = new_size - session->buf_size;

	if (size_diff <= 0) {
		RRR_BUG("size_diff was <= 0 in rrr_mqtt_payload_buf_ensure\n");
	}

	if (size_diff < RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE) {
		size_diff = RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE;
		new_size = size_diff + session->buf_size;
	}

	char *tmp = realloc(session->buf, new_size);
	if (tmp == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_mqtt_payload_buf_ensure\n");
		return RRR_MQTT_PAYLOAD_BUF_ERR;
	}
	memset(tmp + session->buf_size, '\0', size_diff);

	session->buf = tmp;
	session->buf_size = new_size;
	session->wpos = session->buf + old_wpos;
	session->wpos_max = session->buf + old_wpos_max;

	return RRR_MQTT_PAYLOAD_BUF_OK;
}

ssize_t rrr_mqtt_payload_buf_get_touched_size (struct rrr_mqtt_payload_buf_session *session) {
	return session->wpos_max - session->buf;
}

char *rrr_mqtt_payload_buf_extract_buffer (struct rrr_mqtt_payload_buf_session *session) {
	char *ret = session->buf;
	session->buf = NULL;
	return ret;
}

int rrr_mqtt_payload_buf_put_raw (
		struct rrr_mqtt_payload_buf_session *session,
		const void *data,
		ssize_t size
) {
	if (rrr_mqtt_payload_buf_ensure (session, size) != RRR_MQTT_PAYLOAD_BUF_OK) {
		return RRR_MQTT_PAYLOAD_BUF_ERR;
	}

	memcpy(session->wpos, data, size);
	session->wpos += size;

	if (session->wpos > session->wpos_max) {
		session->wpos_max = session->wpos;
	}

	return RRR_MQTT_PAYLOAD_BUF_OK;
}

int rrr_mqtt_payload_buf_put_raw_at_offset (
		struct rrr_mqtt_payload_buf_session *session,
		const void *data,
		ssize_t size,
		ssize_t offset
) {
	char *old_wpos = session->wpos;
	session->wpos = session->buf + offset;

	int ret = rrr_mqtt_payload_buf_put_raw (session, data, size);

	session->wpos = old_wpos;

	return ret;
}

int rrr_mqtt_payload_buf_put_variable_int (
		struct rrr_mqtt_payload_buf_session *session,
		uint32_t value
) {
	if (value > 0xfffffff) { // <-- Seven f's
		RRR_BUG("Value too large in rrr_mqtt_payload_buf_put_variable_int\n");
	}

	uint8_t chunks[4];

	ssize_t used_bytes = 0;
	for (int i = 0; i < 4; i--) {
		used_bytes++;

		chunks[i] = value & 0x7f;
		value >>= 7;
		if (value == 0) {
			break;
		}
		else {
			chunks[i] |= 1<<7;
		}
	}

	return rrr_mqtt_payload_buf_put_raw(session, chunks, used_bytes);
}

