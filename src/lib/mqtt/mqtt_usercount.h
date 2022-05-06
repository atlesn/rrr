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

#ifndef RRR_MQTT_USERCOUNT_H
#define RRR_MQTT_USERCOUNT_H

#define RRR_MQTT_P_USERCOUNT_FIELDS \
	int users;                  \
	void (*destroy)(void *arg)

struct rrr_mqtt_p_usercount {
	RRR_MQTT_P_USERCOUNT_FIELDS;
};

#define RRR_MQTT_P_INCREF(p) \
	rrr_mqtt_p_usercount_incref((struct rrr_mqtt_p_usercount *) (p))

#define RRR_MQTT_P_DECREF(p) \
	rrr_mqtt_p_usercount_decref((struct rrr_mqtt_p_usercount *) (p))

#define RRR_MQTT_P_DECREF_IF_NOT_NULL(p)    \
	if ((p) != NULL)                    \
		RRR_MQTT_P_DECREF(p)

#define RRR_MQTT_P_USERCOUNT(p) \
	rrr_mqtt_p_usercount_get_refcount((struct rrr_mqtt_p_usercount *) (p))

int rrr_mqtt_p_usercount_init (
		struct rrr_mqtt_p_usercount *usercount,
		void (*destroy)(void *arg)
);
void rrr_mqtt_p_usercount_incref (
		struct rrr_mqtt_p_usercount *usercount
);
static inline void rrr_mqtt_p_usercount_incref_void (void *usercount) {
	rrr_mqtt_p_usercount_incref(usercount);
}
void rrr_mqtt_p_usercount_decref (
		struct rrr_mqtt_p_usercount *usercount
);
static inline void rrr_mqtt_p_usercount_decref_void (void *usercount) {
	rrr_mqtt_p_usercount_decref(usercount);
}
int rrr_mqtt_p_usercount_get_refcount (
		struct rrr_mqtt_p_usercount *usercount
);

#endif /* RRR_MQTT_USERCOUNT_H */
