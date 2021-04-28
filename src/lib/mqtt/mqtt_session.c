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

#include "../log.h"
#include "../allocator.h"

#include "mqtt_session.h"
#include "mqtt_property.h"

void rrr_mqtt_session_properties_clear (
		struct rrr_mqtt_session_properties *target
) {
	rrr_mqtt_property_collection_clear(&target->user_properties);

	// The destroy function checks for NULL
	rrr_mqtt_property_destroy(target->assigned_client_identifier);
	rrr_mqtt_property_destroy(target->reason_string);
	rrr_mqtt_property_destroy(target->response_information);
	rrr_mqtt_property_destroy(target->server_reference);
	rrr_mqtt_property_destroy(target->auth_method);
	rrr_mqtt_property_destroy(target->auth_data);

	target->assigned_client_identifier = NULL;
	target->reason_string = NULL;
	target->response_information = NULL;
	target->server_reference = NULL;
	target->auth_method = NULL;
	target->auth_data = NULL;

	memset(target, '\0', sizeof(*target));
}

#define RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(name)			\
	do {if (source->name != NULL) {										\
		rrr_mqtt_property_destroy(target->name);						\
		ret |= rrr_mqtt_property_clone(&target->name, source->name);	\
	}} while(0)

#define RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(name)				\
		do {if (numbers_to_update == NULL || numbers_to_update->name != 0) {	\
			target->numbers.name = source->numbers.name;						\
		}} while(0)

int rrr_mqtt_session_properties_update (
		struct rrr_mqtt_session_properties *target,
		const struct rrr_mqtt_session_properties *source,
		const struct rrr_mqtt_session_properties_numbers *numbers_to_update
) {
	int ret = 0;

	ret |= rrr_mqtt_property_collection_add_from_collection(&target->user_properties, &source->user_properties);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(assigned_client_identifier);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(reason_string);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(response_information);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(server_reference);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(auth_method);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_IF_NOT_NULL(auth_data);

	if (ret != 0) {
		RRR_MSG_0("Could not update properties in rrr_mqtt_session_properties_update\n");
		goto out;
	}

	// If numbers_to_update is NULL, all are updated
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(session_expiry);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(receive_maximum);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(maximum_qos);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(retain_available);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(maximum_packet_size);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(wildcard_subscriptions_available);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(subscription_identifiers_availbable);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(shared_subscriptions_available);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(server_keep_alive);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(topic_alias_maximum);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(request_response_information);
	RRR_MQTT_SESSION_PROPERTIES_UPDATE_NUMBER_IF_DEFINED(request_problem_information);

	out:
	return ret;
}

int rrr_mqtt_session_properties_clone (
		struct rrr_mqtt_session_properties *target,
		const struct rrr_mqtt_session_properties *source
) {
	rrr_mqtt_session_properties_clear(target);
	return rrr_mqtt_session_properties_update(target, source, NULL);
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
