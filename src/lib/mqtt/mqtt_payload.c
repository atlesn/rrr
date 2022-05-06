/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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

#include "mqtt_payload.h"
#include "mqtt_usercount.h"
#include "../rrr_types.h"
#include "../allocator.h"

static void __rrr_mqtt_p_payload_destroy (void *arg) {
	struct rrr_mqtt_p_payload *payload = arg;
	RRR_FREE_IF_NOT_NULL(payload->packet_data);
	rrr_free(payload);
}

int rrr_mqtt_p_payload_set_data (
		struct rrr_mqtt_p_payload *target,
		const char *data,
		rrr_length size
) {
	int ret = 0;

	RRR_FREE_IF_NOT_NULL(target->packet_data);

	target->packet_data = rrr_allocate(size);
	if (target->packet_data == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memcpy(target->packet_data, data, size);
	target->size = size;
	target->payload_start = target->packet_data;

	out:
	return ret;
}

int rrr_mqtt_p_payload_new (
		struct rrr_mqtt_p_payload **target
) {
	int ret = 0;

	*target = NULL;

	struct rrr_mqtt_p_payload *result = rrr_allocate(sizeof(*result));

	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}
	memset(result, '\0', sizeof(*result));

	ret = rrr_mqtt_p_usercount_init (
			(struct rrr_mqtt_p_usercount *) result,
			__rrr_mqtt_p_payload_destroy
	);
	if (ret != 0) {
		RRR_MSG_0("Could not initialize refcount in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	*target = result;

	goto out;
	out_free:
		rrr_free(result);
	out:
		return ret;
}

int rrr_mqtt_p_payload_new_with_allocated_payload (
		struct rrr_mqtt_p_payload **target,
		char **packet_start,
		const char *payload_start,
		rrr_length payload_size
) {
	if (*target != NULL) {
		RRR_BUG("BUG: Target was not NULL in %s\n", __func__);
	}

	int ret = 0;

	struct rrr_mqtt_p_payload *result = NULL;

	ret = rrr_mqtt_p_payload_new (&result);
	if (ret != 0) {
		RRR_MSG_0("Could not create payload in %s\n", __func__);
		ret = 1;
		goto out;
	}

	result->packet_data = *packet_start;
	result->payload_start = payload_start;
	result->size = payload_size;

	*packet_start = NULL;

	*target = result;

	out:
	return ret;
}
