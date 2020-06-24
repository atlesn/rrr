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

#ifndef RRR_MQTT_ACL_H
#define RRR_MQTT_ACL_H

#include "../linked_list.h"

#define RRR_MQTT_ACL_ACTION_DENY	0
#define RRR_MQTT_ACL_ACTION_RO		1
#define RRR_MQTT_ACL_ACTION_RW		2
#define RRR_MQTT_ACL_ACTION_DEFAULT	RRR_MQTT_ACL_ACTION_DENY

#define RRR_MQTT_ACL_RESULT_ALLOW		0
#define RRR_MQTT_ACL_RESULT_ERR			1
#define RRR_MQTT_ACL_RESULT_DENY		2
#define RRR_MQTT_ACL_RESULT_DISCONNECT	3

struct rrr_mqtt_topic_token;

struct rrr_mqtt_acl_user_entry {
	RRR_LL_NODE(struct rrr_mqtt_acl_user_entry);
	char *username;
	int action;
};

struct rrr_mqtt_acl_entry {
	RRR_LL_HEAD(struct rrr_mqtt_acl_user_entry);
	RRR_LL_NODE(struct rrr_mqtt_acl_entry);
	int default_action;
	int default_action_is_set;
	struct rrr_mqtt_topic_token *first_token;
	char *topic_orig;
};

struct rrr_mqtt_acl {
	RRR_LL_HEAD(struct rrr_mqtt_acl_entry);
};

void rrr_mqtt_acl_entry_collection_clear (
		struct rrr_mqtt_acl *collection
);
int rrr_mqtt_acl_entry_collection_populate_from_file (
		struct rrr_mqtt_acl *collection,
		const char *filename
);
int rrr_mqtt_acl_entry_collection_push_allow_all (
		struct rrr_mqtt_acl *collection
);
int rrr_mqtt_acl_check_access (
		const struct rrr_mqtt_acl *collection,
		const struct rrr_mqtt_topic_token *first_token,
		int requested_access_level,
		const char *username,
		int (*match_function) (
				const struct rrr_mqtt_topic_token *a,
				const struct rrr_mqtt_topic_token *b
		)
);

#endif /* RRR_MQTT_ACL_H */
