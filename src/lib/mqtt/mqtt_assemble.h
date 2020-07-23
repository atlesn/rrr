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

#ifndef RRR_MQTT_ASSEMBLE_H
#define RRR_MQTT_ASSEMBLE_H

#include <stdio.h>

#define RRR_MQTT_ASSEMBLE_OK 0
#define RRR_MQTT_ASSEMBLE_INTERNAL_ERR 1

#define RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION \
		char **target, ssize_t *size, struct rrr_mqtt_p *packet

struct rrr_mqtt_p;

int rrr_mqtt_assemble_connect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_connack (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_publish (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_def_puback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_subscribe (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_unsubscribe (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_suback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_unsuback (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_pingreq (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_pingresp (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_disconnect (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);
int rrr_mqtt_assemble_auth (RRR_MQTT_P_TYPE_ASSEMBLE_DEFINITION);

#endif /* RRR_MQTT_ASSEMBLE_H */
