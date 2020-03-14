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
#include <string.h>

#include "../global.h"
#include "mqtt_session.h"
#include "mqtt_property.h"

void rrr_mqtt_session_properties_destroy (
		struct rrr_mqtt_session_properties *target
) {
	rrr_mqtt_property_collection_destroy(&target->user_properties);
	rrr_mqtt_property_destroy(target->assigned_client_identifier);
	rrr_mqtt_property_destroy(target->reason_string);
	rrr_mqtt_property_destroy(target->response_information);
	rrr_mqtt_property_destroy(target->server_reference);
	rrr_mqtt_property_destroy(target->auth_method);
	rrr_mqtt_property_destroy(target->auth_data);
}


int rrr_mqtt_session_properties_clone (
		struct rrr_mqtt_session_properties *target,
		const struct rrr_mqtt_session_properties *source
) {
	int ret = 0;

	memcpy(target, source, sizeof(*target));

	memset(&target->user_properties, '\0', sizeof(target->user_properties));
	target->auth_method = NULL;
	target->auth_data = NULL;

	ret |= rrr_mqtt_property_collection_add_from_collection(&target->user_properties, &source->user_properties);
	ret |= rrr_mqtt_property_clone(&target->auth_method, source->auth_method);
	ret |= rrr_mqtt_property_clone(&target->auth_data, source->auth_data);

	if (ret != 0) {
		RRR_MSG_ERR("Could not clone properties in rrr_mqtt_session_properties_clone\n");
		goto out_destroy;
	}

	goto out;
	out_destroy:
		rrr_mqtt_session_properties_destroy(target);
	out:
		return ret;
}

void rrr_mqtt_session_collection_destroy (struct rrr_mqtt_session_collection *target) {
	(void)(target);
	// Nothing to do
}

int rrr_mqtt_session_collection_init (
		struct rrr_mqtt_session_collection *target,
		const struct rrr_mqtt_session_collection_methods *methods
) {
	int ret = 0;

	memset (target, '\0', sizeof(*target));

	target->methods = methods;

//	out:
	return ret;
}
