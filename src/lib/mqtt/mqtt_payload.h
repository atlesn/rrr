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

#ifndef RRR_MQTT_PAYLOAD_H
#define RRR_MQTT_PAYLOAD_H

#include "mqtt_usercount.h"
#include "../rrr_types.h"

struct rrr_mqtt_p_payload {
	RRR_MQTT_P_USERCOUNT_FIELDS;

	// Pointer to full packet, used only by free()
	char *packet_data;

	// Pointer to where payload starts
	const char *payload_start;
	rrr_length size;
};

int rrr_mqtt_p_payload_set_data (
		struct rrr_mqtt_p_payload *target,
		const char *data,
		rrr_length payload_size
);
int rrr_mqtt_p_payload_new (
		struct rrr_mqtt_p_payload **target
);
int rrr_mqtt_p_payload_new_with_allocated_payload (
		struct rrr_mqtt_p_payload **target,
		char **packet_start,
		const char *payload_start,
		rrr_length payload_size
);

#endif /* RRR_MQTT_PAYLOAD_H */
