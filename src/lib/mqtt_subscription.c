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
#include <inttypes.h>

#include "../global.h"
#include "mqtt_subscription.h"

void rrr_mqtt_subscription_destroy (
		struct rrr_mqtt_subscription *subscription
) {
	if (subscription == NULL) {
		return;
	}
	RRR_FREE_IF_NOT_NULL(subscription->topic_filter);
	RRR_FREE_IF_NOT_NULL(subscription);
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

	if (topic_filter == NULL || *topic_filter == '\0') {
		VL_MSG_ERR("Zero-length or NULL topic filter in rrr_mqtt_subscription_new\n");
		ret = RRR_MQTT_SUBSCRIPTION_MALFORMED;
		goto out;
	}

	struct rrr_mqtt_subscription *sub = malloc(sizeof(*sub));
	if (sub == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_subscription_new_subscription A\n");
		ret = 1;
		goto out;
	}

	sub->topic_filter = malloc(strlen(topic_filter) + 1);
	if (sub == NULL) {
		VL_MSG_ERR("Could not allocate memory in rrr_mqtt_subscription_new_subscriptionB\n");
		ret = 1;
		goto out_free_subscription;
	}

	strcpy(sub->topic_filter, topic_filter);

	sub->retain_handling = retain_handling;
	sub->rap = rap;
	sub->nl = nl;
	sub->qos_or_reason_v5 = qos;

	*target = sub;

	goto out;

	out_free_subscription:
	free(sub);

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
	if ((ret = rrr_mqtt_subscription_new(
			&sub,
			source->topic_filter,
			source->retain_handling,
			source->rap,
			source->nl,
			source->qos_or_reason_v5
	)) != RRR_MQTT_SUBSCRIPTION_OK) {
		VL_MSG_ERR("Could not clone subscription in rrr_mqtt_subscription_clone\n");
		goto out;
	}

	*target = sub;

	out:
	return ret;
}

void rrr_mqtt_subscription_replace_and_destroy (
		struct rrr_mqtt_subscription *target,
		struct rrr_mqtt_subscription *source
) {
	if (source->next != NULL) {
		VL_BUG("source->next was not NULL, part of a collection in rrr_mqtt_subscription_replace_and_destroy\n");
	}

	RRR_FREE_IF_NOT_NULL(target->topic_filter);

	struct rrr_mqtt_subscription *next_preserve = target->next;
	memcpy(target, source, sizeof(*target));
	target->next = next_preserve;

	source->topic_filter = NULL;
	rrr_mqtt_subscription_destroy(source);
}

void rrr_mqtt_subscription_collection_destroy (
		struct rrr_mqtt_subscription_collection *target
) {
	struct rrr_mqtt_subscription *cur = target->first;
	while (cur) {
		struct rrr_mqtt_subscription *next = cur->next;
		RRR_FREE_IF_NOT_NULL(cur->topic_filter);
		RRR_FREE_IF_NOT_NULL(cur);
		cur = next;
	}

	free(target);
}

int rrr_mqtt_subscription_collection_new (
		struct rrr_mqtt_subscription_collection **target
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	*target = NULL;

	struct rrr_mqtt_subscription_collection *res = malloc(sizeof(*res));
	if (res == NULL) {
		VL_MSG_ERR("Could not allocate subscription in rrr_mqtt_subscription_collection_new\n");
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
		VL_MSG_ERR("Could not clone subscription in __rrr_mqtt_subscription_collection_append_raw_clone\n");
		goto out;
	}

	if (target->last != NULL) {
		target->last->next = new;
	}
	else {
		target->first = new;
	}

	target->last = new;
	new->next = NULL;

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
		VL_MSG_ERR("Error while cloning subscriptions in rrr_mqtt_subscription_collection_clone\n");
		goto out;
	}

	const struct rrr_mqtt_subscription *cur = source->first;
	while (cur != NULL) {
		if ((ret = __rrr_mqtt_subscription_collection_append_unchecked_clone (
				res,
				cur
		)) != RRR_MQTT_SUBSCRIPTION_OK) {
			VL_MSG_ERR("Error while appending subscriptions while cloning in rrr_mqtt_subscription_collection_clone\n");
			goto out_destroy_collection;
		}
		cur = cur->next;
	}

	*target = res;

	goto out;
	out_destroy_collection:
		rrr_mqtt_subscription_collection_destroy(res);
	out:
		return ret;
}

int rrr_mqtt_subscription_collection_iterate (
		struct rrr_mqtt_subscription_collection *collection,
		int (*callback)(struct rrr_mqtt_subscription *sub, void *arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	struct rrr_mqtt_subscription *cur = collection->first;
	struct rrr_mqtt_subscription *prev = NULL;

	while (cur) {
		struct rrr_mqtt_subscription *next = cur->next;

		int ret_tmp = callback(cur, callback_arg);
		if ((ret_tmp & RRR_MQTT_SUBSCRIPTION_ITERATE_INTERNAL_ERROR) != 0) {
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			break;
		}
		if ((ret_tmp & RRR_MQTT_SUBSCRIPTION_ITERATE_DESTROY) != 0) {
			if (prev == NULL) {
				collection->first = next;
			}
			else {
				prev->next = next;
			}

			rrr_mqtt_subscription_destroy(cur);
			cur = NULL;
		}
		if ((ret_tmp & RRR_MQTT_SUBSCRIPTION_ITERATE_STOP) != 0) {
			break;
		}

		prev = cur;
		cur = next;
	}

	return ret;
}

struct push_unique_callback_data {
	struct rrr_mqtt_subscription *subscription;
	int did_replace;
};

static int __rrr_mqtt_subscription_collection_push_unique_callback (
		struct rrr_mqtt_subscription *subscription,
		void *arg
) {
	struct push_unique_callback_data *callback_data = arg;

	int ret = RRR_MQTT_SUBSCRIPTION_ITERATE_OK;

	if (strcmp(subscription->topic_filter, callback_data->subscription->topic_filter) == 0) {
		rrr_mqtt_subscription_replace_and_destroy(subscription, callback_data->subscription);

		callback_data->subscription = subscription;
		callback_data->did_replace = 1;

		ret |= RRR_MQTT_SUBSCRIPTION_ITERATE_STOP;
	}

	return ret;
}

static int __rrr_mqtt_subscription_collection_add_unique (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription **subscription,
		int put_at_end
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	if (target->first == NULL) {
		(*subscription)->next = NULL;
		target->first = *subscription;
		target->last = *subscription;
		goto out;
	}

	struct push_unique_callback_data callback_data = {
			*subscription, 0
	};

	ret = rrr_mqtt_subscription_collection_iterate (
			target,
			__rrr_mqtt_subscription_collection_push_unique_callback,
			&callback_data
	);

	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		VL_MSG_ERR("Error from iterator when pushing unique MQTT subscription to collection\n");
		ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
		goto out;
	}

	if (callback_data.did_replace == 1) {
		ret = RRR_MQTT_SUBSCRIPTION_REPLACED;
		*subscription = callback_data.subscription;
	}
	else {
		if (put_at_end == 1) {
			target->last->next = *subscription;
			target->last = *subscription;
			(*subscription)->next = NULL;
		}
		else {
			(*subscription)->next = target->first;
			target->first = *subscription;
		}
	}

	out:
	return ret;
}

int rrr_mqtt_subscription_collection_push_unique (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription **subscription
) {
	return __rrr_mqtt_subscription_collection_add_unique (target, subscription, 0);
}

int rrr_mqtt_subscription_collection_append_unique (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription **subscription
) {
	return __rrr_mqtt_subscription_collection_add_unique (target, subscription, 1);
}

int rrr_mqtt_subscription_collection_append_unique_take_from_collection (
		struct rrr_mqtt_subscription_collection *target,
		struct rrr_mqtt_subscription_collection *source
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	struct rrr_mqtt_subscription *cur = source->first;

	// NOTE : append_unique will steal all the pointers from the source
	//        which means the list cannot be used afterwards
	while (cur != NULL) {
		struct rrr_mqtt_subscription *next = cur->next;

		ret = rrr_mqtt_subscription_collection_append_unique(target, &cur) & ~RRR_MQTT_SUBSCRIPTION_REPLACED;

		if (ret != 0) {
			VL_MSG_ERR("Internal error in rrr_mqtt_subscription_collection_take_from_collection_unique\n");
			ret = RRR_MQTT_SUBSCRIPTION_INTERNAL_ERROR;
			break;
		}

		cur = next;
	}

	source->first = NULL;
	source->last = NULL;

	return ret;
}

int rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
		struct rrr_mqtt_subscription_collection *target,
		const struct rrr_mqtt_subscription_collection *source
) {
	int ret = RRR_MQTT_SUBSCRIPTION_OK;

	struct rrr_mqtt_subscription_collection *new_source = NULL;

	if ((ret = rrr_mqtt_subscription_collection_clone(&new_source, source)) != 0) {
		VL_MSG_ERR("Could not clone collection in rrr_mqtt_subscription_collection_copy_from_collection_unique\n");
		goto out;
	}

	if ((ret = rrr_mqtt_subscription_collection_append_unique_take_from_collection (
			target,
			new_source
	)) != RRR_MQTT_SUBSCRIPTION_OK) {
		VL_MSG_ERR("Could not append to collection in rrr_mqtt_subscription_collection_copy_from_collection_unique\n");
		goto out;
	}

	if (new_source->first != NULL) {
		VL_BUG("new source was not empty in rrr_mqtt_subscription_collection_append_unique_copy_from_collection\n");
	}

	out:
	if (new_source != NULL) {
		rrr_mqtt_subscription_collection_destroy(new_source);
	}
	return ret;

}
