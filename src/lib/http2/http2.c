
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

#include <stdlib.h>
#include <string.h>
#include <nghttp2/nghttp2.h>

#include "../log.h"
#include "../util/base64.h"
#include "http2.h"

int rrr_http2_session_new_or_reset (
		struct rrr_http2_session **target
) {
	int ret = 0;

	struct rrr_http2_session *result = NULL;

	if (*target != NULL) {
		result = *target;
		goto reset;
	}

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_http2_session_new_or_reset\n");
		goto out;
	}

	reset:
	memset(result, '\0', sizeof(*result));

	*target = result;

	out:
	return ret;
}

void rrr_http2_session_destroy_if_not_null (
		struct rrr_http2_session **target
) {
	if (*target == NULL) {
		return;
	}

	free(*target);
	*target = NULL;
}

int rrr_http2_pack_upgrade_request_settings (
		char **target
) {
	*target = NULL;

	uint8_t payload[128];
	ssize_t payload_size = 0;

	nghttp2_settings_entry iv[2];

	iv[0].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
	iv[0].value = NGHTTP2_DEFAULT_HEADER_TABLE_SIZE;

	iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
	iv[1].value = NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE;

	if ((payload_size = nghttp2_pack_settings_payload (payload, sizeof(payload), iv, sizeof(iv) / sizeof(*iv))) <= 0) {
		RRR_MSG_0("Could not pack SETTINGS packet in rrr_http2_pack_upgrade_request_settings, return was %li\n", payload_size);
		return 1;
	}

	size_t result_length = 0;
	unsigned char *result = rrr_base64url_encode((unsigned char *) payload, payload_size, &result_length);

	if (result == NULL) {
		RRR_MSG_0("Base64url encoding failed in rrr_http2_pack_upgrade_request_settings\n");
		return 1;
	}

	*target = result;

	return 0;
}
