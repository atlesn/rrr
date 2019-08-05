/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#include "mqtt_packet.h"
#include "mqtt_common.h"

static int rrr_mqtt_p_handler_connect (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_publish (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_puback (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubrec (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubrel (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pubcomp (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_subscribe (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_unsubscribe (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_pingreq (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_disconnect (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;
}
static int rrr_mqtt_p_handler_auth (RRR_MQTT_PACKET_TYPE_HANDLER_DEFINITION) {
	int ret = 0;
	return ret;

}

static const struct rrr_mqtt_p_type_properties type_properties[] = {
	{1, 0, NULL},
	{1, 0, rrr_mqtt_p_handler_connect},
	{1, 0, NULL},
	{0, 0, rrr_mqtt_p_handler_publish},
	{1, 0, rrr_mqtt_p_handler_puback},
	{1, 0, rrr_mqtt_p_handler_pubrec},
	{1, 2, rrr_mqtt_p_handler_pubrel},
	{1, 0, rrr_mqtt_p_handler_pubcomp},
	{1, 2, rrr_mqtt_p_handler_subscribe},
	{1, 0, NULL},
	{1, 2, rrr_mqtt_p_handler_unsubscribe},
	{1, 0, NULL},
	{1, 0, rrr_mqtt_p_handler_pingreq},
	{1, 0, NULL},
	{1, 0, rrr_mqtt_p_handler_disconnect},
	{1, 0, rrr_mqtt_p_handler_auth}
};
