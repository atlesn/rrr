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

#ifndef RRR_MQTT_SUBSCRIPTION_H
#define RRR_MQTT_SUBSCRIPTION_H

#include <stdio.h>

#include "../util/linked_list.h"

#define RRR_MQTT_SUBSCRIPTION_OK				0
#define RRR_MQTT_SUBSCRIPTION_MATCH				0
#define RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR	1
#define RRR_MQTT_SUBSCRIPTION_REPLACED			3
#define RRR_MQTT_SUBSCRIPTION_MISMATCH			4

#define RRR_MQTT_SUBSCRIPTION_ITERATE_OK				0
#define RRR_MQTT_SUBSCRIPTION_ITERATE_INTERNAL_ERROR	(1<<0)
#define RRR_MQTT_SUBSCRIPTION_ITERATE_DESTROY			(1<<1)
#define RRR_MQTT_SUBSCRIPTION_ITERATE_STOP				(1<<2)

#define RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_QOS(flags)			((flags & (1<<0|1<<1)))
#define RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_NL(flags)			((flags & (1<<2)) >> 2)
#define RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_RAP(flags)			((flags & (1<<3)) >> 3)
#define RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_RETAIN(flags)		((flags & (1<<4|1<<5)) >> 4)
#define RRR_MQTT_SUBSCRIPTION_GET_FLAG_RAW_RESERVED(flags)		((flags & (1<<6|1<<7)) >> 6)

struct rrr_mqtt_p_publish;
struct rrr_mqtt_topic_token;

struct rrr_mqtt_subscription {
	RRR_LL_NODE(struct rrr_mqtt_subscription);

	char *topic_filter;
	struct rrr_mqtt_topic_token *token_tree;

	uint8_t retain_handling;
	uint8_t rap;
	uint8_t nl;
	uint8_t qos_or_reason_v5;
};

struct rrr_mqtt_subscription_collection {
	RRR_LL_HEAD(struct rrr_mqtt_subscription);
};

int rrr_mqtt_subscription_destroy (
		struct rrr_mqtt_subscription *subscription
);
int rrr_mqtt_subscription_new (
		struct rrr_mqtt_subscription **target,
		const char *topic_filter,
		uint8_t retain_handling,
		uint8_t rap,
		uint8_t nl,
		uint8_t qos
);
int rrr_mqtt_subscription_clone (
		struct rrr_mqtt_subscription **target,
		const struct rrr_mqtt_subscription *source
);
void rrr_mqtt_subscription_replace_and_destroy (
		struct rrr_mqtt_subscription *target,
		struct rrr_mqtt_subscription *source
);
int rrr_mqtt_subscription_collection_match_publish_callback (
		const struct rrr_mqtt_subscription_collection *subscriptions,
		const struct rrr_mqtt_p_publish *publish,
		int (*match_callback)(const struct rrr_mqtt_p_publish *publish, const struct rrr_mqtt_subscription *subscription, void *arg),
		void *callback_arg,
		int *match_count_final
);
int rrr_mqtt_subscription_collection_match_publish (
		const struct rrr_mqtt_subscription_collection *subscriptions,
		const struct rrr_mqtt_p_publish *publish
);
int rrr_mqtt_subscription_collection_count (
		const struct rrr_mqtt_subscription_collection *target
);
void rrr_mqtt_subscription_collection_dump (
		const struct rrr_mqtt_subscription_collection *subscriptions
);
void rrr_mqtt_subscription_collection_clear (
		struct rrr_mqtt_subscription_collection *target
);
void rrr_mqtt_subscription_collection_destroy (
		struct rrr_mqtt_subscription_collection *target
);
int rrr_mqtt_subscription_collection_new (
		struct rrr_mqtt_subscription_collection **target
);
int rrr_mqtt_subscription_collection_clone (
		struct rrr_mqtt_subscription_collection **target,
		const struct rrr_mqtt_subscription_collection *source
);
int rrr_mqtt_subscription_collection_iterate (
		struct rrr_mqtt_subscription_collection *collection,
		int (*callback)(struct rrr_mqtt_subscription *sub, void *arg),
		void *callback_arg
);
const struct rrr_mqtt_subscription *rrr_mqtt_subscription_collection_get_subscription_by_idx (
		const struct rrr_mqtt_subscription_collection *target,
		ssize_t idx
);
const struct rrr_mqtt_subscription *rrr_mqtt_subscription_collection_get_subscription_by_idx_const (
		const struct rrr_mqtt_subscription_collection *target,
		ssize_t idx
);
int rrr_mqtt_subscription_collection_remove_topic (
		int *did_remove,
		struct rrr_mqtt_subscription_collection *target,
		const char *topic
);
int rrr_mqtt_subscription_collection_push_unique (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription **subscription
);
int rrr_mqtt_subscription_collection_push_unique_str (
		struct rrr_mqtt_subscription_collection *target,
		const char *topic,
		uint8_t retain_handling,
		uint8_t rap,
		uint8_t nl,
		uint8_t qos
);
int rrr_mqtt_subscription_collection_append_unique (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription **subscription
);
int rrr_mqtt_subscription_collection_append_unique_take_from_collection (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription_collection *source,
		int include_invalid_entries
);
int rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
		struct rrr_mqtt_subscription_collection *target,
		const struct rrr_mqtt_subscription_collection *source,
		int include_invalid_entries
);
int rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription_collection *source,
		int *removed_count
);

#endif /* RRR_MQTT_SUBSCRIPTION_H */
