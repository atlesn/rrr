/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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
#include <inttypes.h>

#include "../log.h"
#include "../allocator.h"

#include "mqtt_subscription.h"
#include "mqtt_packet.h"
#include "mqtt_topic.h"

#include "../util/linked_list.h"
#include "../util/macro_utils.h"

#define RRR_MQTT_SUBSCRIPTION_COLLECTION_MAX 65536

// On new data fields, remember to also update rrr_mqtt_subscription_replace_and_destroy
int rrr_mqtt_subscription_destroy (
		struct rrr_mqtt_subscription *subscription
) {
	if (subscription == NULL) {
		return 0;
	}
	rrr_mqtt_topic_token_destroy(subscription->token_tree);
	RRR_FREE_IF_NOT_NULL(subscription->topic_filter);
	RRR_FREE_IF_NOT_NULL(subscription);
	return 0;
}

int rrr_mqtt_subscription_new (
		struct rrr_mqtt_subscription **target,
		const char *topic_filter,
		uint8_t retain_handling,
		uint8_t rap,
		uint8_t nl,
		uint8_t qos
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*target = NULL;

	if (nl > 0 || rap > 0 || retain_handling > 2) {
		RRR_BUG("Invalid flags in %s\n", __func__);
	}

	if (rrr_mqtt_topic_filter_validate_name(topic_filter) != 0) {
		RRR_BUG("Invalid topic filter passed to %s. Caller should check for this.\n", __func__);
	}

	struct rrr_mqtt_subscription *sub = rrr_allocate(sizeof(*sub));
	if (sub == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(sub, '\0', sizeof(*sub));

	// Callers must check for this
	if (topic_filter == NULL || *topic_filter == '\0') {
		RRR_BUG("Topic filter was NULL or zero length in %s\n", __func__);
	}


	else {
		sub->topic_filter = rrr_allocate(strlen(topic_filter) + 1);
		if (sub == NULL) {
			RRR_MSG_0("Could not allocate memory for topic filter in %s\n", __func__);
			ret = 1;
			goto out_free_subscription;
		}
		strcpy(sub->topic_filter, topic_filter);

		ret = rrr_mqtt_topic_tokenize(&sub->token_tree, sub->topic_filter);
		if (ret != 0) {
			RRR_MSG_0("Error while creating token tree in %s\n", __func__);
			ret = 1;
			goto out_free_topic_filter;
		}

		sub->qos_or_reason_v5 = qos;
	}

	sub->retain_handling = retain_handling;
	sub->rap = rap;
	sub->nl = nl;

	*target = sub;

	goto out;

	out_free_topic_filter:
		rrr_free(sub->topic_filter);
	out_free_subscription:
		rrr_free(sub);
	out:
		return ret;
}

int rrr_mqtt_subscription_clone (
		struct rrr_mqtt_subscription **target,
		const struct rrr_mqtt_subscription *source
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*target = NULL;

	struct rrr_mqtt_subscription *sub = NULL;
	if ((ret = rrr_mqtt_subscription_new (
			&sub,
			source->topic_filter,
			source->retain_handling,
			source->rap,
			source->nl,
			source->qos_or_reason_v5
	)) != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not clone subscription in %s return was %i\n", __func__, ret);
		goto out;
	}

	*target = sub;

	out:
	return ret;
}

static void __rrr_mqtt_subscription_move_data_and_zero_source (
		struct rrr_mqtt_subscription *target,
		struct rrr_mqtt_subscription *source
) {
	RRR_FREE_IF_NOT_NULL(target->topic_filter);
	rrr_mqtt_topic_token_destroy(target->token_tree);
	memcpy(target, source, sizeof(*target));
	memset(source, '\0', sizeof(*source));
}

static void __rrr_mqtt_subscription_replace_and_destroy (
		struct rrr_mqtt_subscription *target,
		struct rrr_mqtt_subscription **source
) {
	if ((*source)->ptr_next != NULL) {
		RRR_BUG("source->ptr_next was not NULL, part of a collection in %s\n", __func__);
	}
	/*
	 * 1. Free the original dynamically allocated data in target
	 * 2. Save the linked list pointers temporarily
	 * 3. Shallow-copy all data from source to target
	 * 4. Re-write linked list data with data from point 2
	 * 5. Zero all data in source
	 * 6. Free source
	 */
	RRR_LL_REPLACE_NODE (
			target,
			*source,
			struct rrr_mqtt_subscription,
			__rrr_mqtt_subscription_move_data_and_zero_source(target, *source)
	);

	rrr_mqtt_subscription_destroy(*source);
	*source = NULL;
}

static int __rrr_mqtt_subscription_match_publish (
		const struct rrr_mqtt_subscription *subscription,
		const struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_TOKEN_MISMATCH;

	const char *topic_name = publish->topic;

	if (rrr_mqtt_topic_validate_name(topic_name) != 0) {
		RRR_BUG("Topic name of packet was not valid in %s, should be checked at parsing\n", __func__);
	}

	ret = rrr_mqtt_topic_match_tokens_recursively(subscription->token_tree, publish->token_tree_);

	return ret;
}

// Callback is called once per matching subscription
int rrr_mqtt_subscription_collection_match_publish_with_callback (
		const struct rrr_mqtt_subscription_collection *subscriptions,
		const struct rrr_mqtt_p_publish *publish,
		int (*match_callback) (
				const struct rrr_mqtt_p_publish *publish,
				const struct rrr_mqtt_subscription *subscription,
				void *callback_arg
		),
		void *callback_arg,
		rrr_length *match_count_final
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*match_count_final = 0;

	RRR_LL_ITERATE_BEGIN(subscriptions, const struct rrr_mqtt_subscription);
		ret = __rrr_mqtt_subscription_match_publish(node, publish);
		if (ret == RRR_MQTT_TOKEN_MATCH) {
			ret = match_callback(publish, node, callback_arg);
			if (ret != 0) {
				RRR_MSG_0("Error from match_callback in %s: %i\n",
						__func__, ret);
				ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
				RRR_LL_ITERATE_LAST();
			}
			rrr_length_inc_bug(match_count_final);
		}
		else if (ret != RRR_MQTT_TOKEN_MISMATCH) {
			RRR_MSG_0("Error in %s, return was %i\n", __func__, ret);
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			RRR_LL_ITERATE_LAST();
		}
		else {
			ret = RRR_MQTT_SUBSCRIPTION_OK;
		}
	RRR_LL_ITERATE_END();

	return ret;
}

int rrr_mqtt_subscription_collection_match_publish (
		const struct rrr_mqtt_subscription_collection *subscriptions,
		const struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_TOKEN_MISMATCH;

	RRR_LL_ITERATE_BEGIN(subscriptions, const struct rrr_mqtt_subscription);
		ret = __rrr_mqtt_subscription_match_publish(node, publish);
		if (ret == RRR_MQTT_TOKEN_MATCH) {
			RRR_LL_ITERATE_LAST();
		}
		else if (ret != RRR_MQTT_TOKEN_MISMATCH) {
			RRR_MSG_0("Error from matcher in %s, return was %i\n", __func__, ret);
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return ret;
}

rrr_length rrr_mqtt_subscription_collection_count (
		const struct rrr_mqtt_subscription_collection *target
) {
	return rrr_length_from_slength_bug_const (RRR_LL_COUNT(target));
}

void rrr_mqtt_subscription_collection_dump (
		const struct rrr_mqtt_subscription_collection *subscriptions
) {
	int i = 0;
	RRR_MSG_2("=== DUMPING SUBSCRIPTIONS IN COLLECTION %p ===\n", subscriptions);
	RRR_LL_ITERATE_BEGIN(subscriptions, const struct rrr_mqtt_subscription);
		i++;
		RRR_MSG_2("%i: %s\n", i, node->topic_filter);
	RRR_LL_ITERATE_END();
	RRR_MSG_2("===\n");
}

void rrr_mqtt_subscription_collection_clear (
		struct rrr_mqtt_subscription_collection *target
) {
	RRR_LL_DESTROY(target, struct rrr_mqtt_subscription, rrr_mqtt_subscription_destroy(node));
}

void rrr_mqtt_subscription_collection_destroy (
		struct rrr_mqtt_subscription_collection *target
) {
	if (target == NULL) {
		return;
	}
	rrr_mqtt_subscription_collection_clear(target);
	rrr_free(target);
}

int rrr_mqtt_subscription_collection_new (
		struct rrr_mqtt_subscription_collection **target
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*target = NULL;

	struct rrr_mqtt_subscription_collection *res = rrr_allocate(sizeof(*res));
	if (res == NULL) {
		RRR_MSG_0("Could not allocate subscription in %s\n", __func__);
		return RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
	}

	memset(res, '\0', sizeof(*res));

	*target = res;

	return ret;
}

static int __rrr_mqtt_subscription_collection_append_unchecked_clone (
		struct rrr_mqtt_subscription_collection *target,
		const struct rrr_mqtt_subscription *old
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	struct rrr_mqtt_subscription *new = NULL;

	if ((ret = rrr_mqtt_subscription_clone(&new, old)) != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not clone subscription in %s\n", __func__);
		goto out;
	}

	RRR_LL_APPEND(target, new);

	out:
	return ret;
}

int rrr_mqtt_subscription_collection_clone (
		struct rrr_mqtt_subscription_collection **target,
		const struct rrr_mqtt_subscription_collection *source
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*target = NULL;

	struct rrr_mqtt_subscription_collection *res = NULL;

	ret = rrr_mqtt_subscription_collection_new(&res);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error while cloning subscriptions in %s\n", __func__);
		goto out;
	}

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_mqtt_subscription);
		if ((ret = __rrr_mqtt_subscription_collection_append_unchecked_clone (
				res,
				node
		)) != RRR_MQTT_SUBSCRIPTION_OK) {
			RRR_MSG_0("Error while appending subscriptions while cloning in %s\n", __func__);
			goto out_destroy_collection;
		}
	RRR_LL_ITERATE_END();

	*target = res;

	goto out;
	out_destroy_collection:
		rrr_mqtt_subscription_collection_destroy(res);
	out:
		return ret;
}

int rrr_mqtt_subscription_collection_check_full (
		const struct rrr_mqtt_subscription_collection *collection
) {
	if (RRR_LL_COUNT(collection) >= RRR_MQTT_SUBSCRIPTION_COLLECTION_MAX) {
		return RRR_MQTT_SUBSCRIPTION_REFUSED;
	}
	return RRR_MQTT_SUBSCRIPTION_OK;
}

int rrr_mqtt_subscription_collection_iterate (
		struct rrr_mqtt_subscription_collection *collection,
		int (*callback)(struct rrr_mqtt_subscription *sub, void *arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_mqtt_subscription);
		// Only internal error propagates
		int ret_tmp = callback(node, callback_arg);
		if ((ret_tmp & RRR_MQTT_SUBSCRIPTION_ITERATE_INTERNAL_ERROR) != 0) {
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			RRR_LL_ITERATE_BREAK();
		}
		if ((ret_tmp & RRR_MQTT_SUBSCRIPTION_ITERATE_DESTROY) != 0) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		if ((ret_tmp & RRR_MQTT_SUBSCRIPTION_ITERATE_STOP) != 0) {
			RRR_LL_ITERATE_BREAK();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, rrr_mqtt_subscription_destroy(node));

	return ret;
}

struct push_unique_callback_data {
	struct rrr_mqtt_subscription **subscription;
};

static int __rrr_mqtt_subscription_collection_push_unique_callback (
		struct rrr_mqtt_subscription *subscription,
		void *arg
) {
	struct push_unique_callback_data *callback_data = arg;

	int ret = RRR_MQTT_SUBSCRIPTION_ITERATE_OK;

	if (strcmp(subscription->topic_filter, (*callback_data->subscription)->topic_filter) == 0) {
		__rrr_mqtt_subscription_replace_and_destroy(subscription, callback_data->subscription);
		ret |= RRR_MQTT_SUBSCRIPTION_ITERATE_STOP;
	}

	return ret;
}

// NOTE : Check for REPLACED and REFUSED return value when calling.
// NOTE : Should set subscription to NULL and take ownership or
//        destroy, but might not set NULL if there are errors.
//        Caller must check for this and free if needed, usually
//        just always call the destroy function afterwards.
int rrr_mqtt_subscription_collection_add_unique (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription **subscription,
		int put_at_end
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	if (RRR_LL_IS_EMPTY(target)) {
		RRR_LL_APPEND(target, *subscription);
		*subscription = NULL;
		goto out;
	}

	struct push_unique_callback_data callback_data = {
			subscription
	};

	ret = rrr_mqtt_subscription_collection_iterate (
			target,
			__rrr_mqtt_subscription_collection_push_unique_callback,
			&callback_data
	);

	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error from iterator when pushing unique MQTT subscription to collection\n");
		ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
		goto out;
	}

	if (*(callback_data.subscription) == NULL) {
		ret = RRR_MQTT_SUBSCRIPTION_REPLACED;
	}
	else {
		if ((ret = rrr_mqtt_subscription_collection_check_full (target)) != 0) {
			// Refused, collection full
			goto out;
		}
		if (put_at_end == 1) {
			RRR_LL_APPEND(target, *subscription);
		}
		else {
			RRR_LL_UNSHIFT(target, *subscription);
		}
		*subscription = NULL;
	}

	out:
	return ret;
}

const struct rrr_mqtt_subscription *rrr_mqtt_subscription_collection_get_subscription_by_idx (
		const struct rrr_mqtt_subscription_collection *target,
		rrr_length idx
) {
	if ((rrr_slength) idx > target->node_count - 1) {
		RRR_BUG("Index out of range in %s\n", __func__);
	}

	int i = 0;
	RRR_LL_ITERATE_BEGIN(target,const struct rrr_mqtt_subscription);
		if (i == (rrr_slength) idx) {
			return node;
		}
		i++;
	RRR_LL_ITERATE_END();

	return NULL;
}

const struct rrr_mqtt_subscription *rrr_mqtt_subscription_collection_get_subscription_by_idx_const (
		const struct rrr_mqtt_subscription_collection *target,
		rrr_length idx
) {
	if ((rrr_slength) idx > target->node_count - 1) {
		RRR_BUG("Index out of range in %s\n", __func__);
	}

	int i = 0;
	RRR_LL_ITERATE_BEGIN(target,const struct rrr_mqtt_subscription);
		if (i == (rrr_slength) idx) {
			return node;
		}
		i++;
	RRR_LL_ITERATE_END();

	return NULL;
}

int rrr_mqtt_subscription_collection_remove_topic (
		int *did_remove,
		struct rrr_mqtt_subscription_collection *target,
		const char *topic
) {
	*did_remove = 0;

	int did_destroy = 0;
	RRR_LL_ITERATE_BEGIN(target,struct rrr_mqtt_subscription);
		if (strcmp(node->topic_filter, topic) == 0) {
			RRR_LL_ITERATE_SET_DESTROY();
			did_destroy++;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(target,rrr_mqtt_subscription_destroy(node));

	if (did_destroy > 1) {
		RRR_BUG("More than 1 subscription matched in %s\n", __func__);
	}

	*did_remove = did_destroy;

	return 0;
}

int rrr_mqtt_subscription_collection_push_unique_str (
		struct rrr_mqtt_subscription_collection *target,
		const char *topic,
		uint8_t retain_handling,
		uint8_t rap,
		uint8_t nl,
		uint8_t qos
) {
	int ret = 0;
	struct rrr_mqtt_subscription *subscription = NULL;

	if (rrr_mqtt_subscription_new(&subscription, topic, retain_handling, rap, nl, qos) != 0) {
		RRR_MSG_0("Could not create subscription in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (subscription->qos_or_reason_v5 != qos) {
		if (subscription->qos_or_reason_v5 == RRR_MQTT_P_5_REASON_TOPIC_FILTER_INVALID) {
			RRR_MSG_0("Topic filter '%s' was invalid while pushing to subscription collection\n",
					topic);
			ret = 1;
			goto out;
		}
		else {
			RRR_BUG("Unknown reason %u from rrr_mqtt_subscription_new in %s\n",
					subscription->qos_or_reason_v5, __func__);
		}
	}

	if ((ret = rrr_mqtt_subscription_collection_add_unique (target, &subscription, 0)) != RRR_MQTT_SUBSCRIPTION_OK) {
		if (ret == RRR_MQTT_SUBSCRIPTION_REPLACED) {
			ret = RRR_MQTT_SUBSCRIPTION_OK;
		}
		else if (ret == RRR_MQTT_SUBSCRIPTION_REFUSED) {
			goto out;
		}
		else {
			RRR_MSG_0("Could not add subscription to collection in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	subscription = NULL;

	out:
	// Destroy function checks for NULL
	rrr_mqtt_subscription_destroy(subscription);
	return ret;
}

int rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
		struct rrr_mqtt_subscription_collection *target,
		const struct rrr_mqtt_subscription_collection *source,
		int include_invalid_entries,
		int (*new_subscrition_callback)(const struct rrr_mqtt_subscription *subscription, void *arg),
		void *new_subscrition_callback_arg
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	RRR_LL_ITERATE_BEGIN(source, const struct rrr_mqtt_subscription);
		if (include_invalid_entries == 0 && node->qos_or_reason_v5 > 2) {
			RRR_LL_ITERATE_NEXT();
		}

		struct rrr_mqtt_subscription *subscription_tmp = NULL;
		if (rrr_mqtt_subscription_clone(&subscription_tmp, node) != 0) {
			RRR_MSG_0("Failed to clone subscription in %s\n", __func__);
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			goto out;
		}

		ret = rrr_mqtt_subscription_collection_add_unique(target, &subscription_tmp, 1);
		rrr_mqtt_subscription_destroy(subscription_tmp); // Destroy function checks for NULL

		if ((ret & RRR_MQTT_SUBSCRIPTION_REPLACED) == 0) {
			if (new_subscrition_callback != NULL) {
				ret = new_subscrition_callback(node, new_subscrition_callback_arg);
			}
		}
		else {
			ret &= ~(RRR_MQTT_SUBSCRIPTION_REPLACED);
		}

		if (ret != 0) {
			RRR_MSG_0("Internal error in %s return was %i\n", __func__, ret);
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			goto out;
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}

int rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription_collection *source,
		rrr_length *removed_count
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*removed_count = 0;

	RRR_LL_ITERATE_BEGIN(source, struct rrr_mqtt_subscription);
		int did_remove = 0;

		if (node->qos_or_reason_v5 != RRR_MQTT_P_5_REASON_OK) {
			RRR_MSG_0("MQTT not removing topic '%s' due to reason %u set\n",
					node->topic_filter,
					node->qos_or_reason_v5
			);
			RRR_LL_ITERATE_NEXT();
		}

		if (rrr_mqtt_subscription_collection_remove_topic (
				&did_remove,
				target,
				node->topic_filter
		)) {
			RRR_MSG_0("Error while removing topic in %s\n", __func__);
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			node->qos_or_reason_v5 = RRR_MQTT_P_5_REASON_UNSPECIFIED_ERROR;
			goto out;
		}

		if (did_remove == 0) {
			node->qos_or_reason_v5 = RRR_MQTT_P_5_REASON_NO_SUBSCRIPTION_EXISTED;
		}
		else {
			node->qos_or_reason_v5 = RRR_MQTT_P_5_REASON_OK;
			rrr_length_inc_bug(removed_count);
		}
	RRR_LL_ITERATE_END();

	out:
	return ret;
}
