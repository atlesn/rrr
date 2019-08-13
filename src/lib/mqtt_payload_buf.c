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

#include "../global.h"
#include "mqtt_payload_buf.h"

#define RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE 1024

int rrr_mqtt_payload_buf_init (struct rrr_mqtt_payload_buf_session *session) {
	memset(session, '\0', sizeof(*session));
	session->buf = malloc(RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE);
	if (session->buf == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_payload_buf_init\n");
		return RRR_MQTT_PAYLOAD_BUF_ERR;
	}
	session->buf_size = RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE;
	session->wpos = session->buf;
	session->end = session->buf + RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE;
	return RRR_MQTT_PAYLOAD_BUF_OK;
}

 void rrr_mqtt_payload_buf_destroy (struct rrr_mqtt_payload_buf_session *session) {
	RRR_FREE_IF_NOT_NULL(session->buf);
}

int rrr_mqtt_payload_buf_ensure (struct rrr_mqtt_payload_buf_session *session, ssize_t size) {
	if (session->wpos + size < session->end) {
		return RRR_MQTT_PAYLOAD_BUF_OK;
	}

	size = (size < RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE ? RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE : size);

	char *tmp = realloc(session->buf, session->buf_size + RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE);
	if (tmp == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_payload_buf_ensure\n");
		return RRR_MQTT_PAYLOAD_BUF_ERR;
	}

	ssize_t wpos = session->wpos - session->buf;
	ssize_t end = session->end - session->buf;

	session->buf = tmp;
	session->buf_size += RRR_MQTT_PAYLOAD_BUF_INCREMENT_SIZE;
	session->wpos = session->buf + wpos;
	session->end = session->buf + end;

	return RRR_MQTT_PAYLOAD_BUF_OK;
}

char *rrr_mqtt_payload_buf_extract_buffer (struct rrr_mqtt_payload_buf_session *session) {
	char *ret = session->buf;
	session->buf = NULL;
	return ret;
}

int rrr_mqtt_payload_buf_put_raw (struct rrr_mqtt_payload_buf_session *session, void *data, ssize_t size) {
	if (rrr_mqtt_payload_buf_ensure (session, size) != RRR_MQTT_PAYLOAD_BUF_OK) {
		return RRR_MQTT_PAYLOAD_BUF_ERR;
	}

	memcpy(session->wpos, data, size);
	session->wpos += size;

	return RRR_MQTT_PAYLOAD_BUF_OK;
}
