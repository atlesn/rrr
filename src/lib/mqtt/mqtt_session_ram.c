/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "../allocator.h"

#include "mqtt_session_ram.h"
#include "mqtt_session.h"
#include "mqtt_packet.h"
#include "mqtt_subscription.h"
#include "mqtt_common.h"
#include "mqtt_id_pool.h"

#include "../util/rrr_time.h"
#include "../util/linked_list.h"
#include "../util/macro_utils.h"
#include "../util/posix.h"
#include "../fifo.h"

#define RRR_MQTT_SESSION_RAM_MAINTAIN_INTERVAL_MS             250
#define RRR_MQTT_SESSION_RAM_PUBLISH_GRACE_QUEUE_INTERVAL_MS  250
#define RRR_MQTT_SESSION_RAM_HARD_TIMEOUT_MS                  (RRR_MQTT_COMMON_TICK_INTERVAL_S * 1000 * 2)

struct rrr_mqtt_session_collection_ram_data;

struct rrr_mqtt_session_ram {
	// MUST be first
	struct rrr_mqtt_session session;

	RRR_LL_NODE(struct rrr_mqtt_session_ram);

	struct rrr_mqtt_session_collection_ram_data *ram_data;

	int users;

	struct rrr_mqtt_p_queue to_remote_buffer;
	struct rrr_mqtt_p_queue to_remote_delayed_buffer;
	struct rrr_mqtt_p_queue from_remote_buffer;
	struct rrr_mqtt_p_queue publish_grace_buffer;
	struct rrr_mqtt_id_pool id_pool;

	// Iteration of garce queue only done as often as publish grace time
	uint64_t prev_publish_grace_queue_iteration;

	char *client_id_;
	struct rrr_mqtt_session_properties session_properties;
	uint64_t retry_interval_usec;
	uint64_t expire_time;
	uint64_t heartbeat_time;
	uint32_t max_in_flight;
	uint32_t complete_publish_grace_time_s;
	struct rrr_mqtt_subscription_collection *subscriptions;
	struct rrr_mqtt_p_publish *will_publish;
};

#define RRR_MQTT_SESSION_RAM_DELIVERY_METHOD_ARGS \
    struct rrr_mqtt_session_ram *ram_session,     \
    struct rrr_mqtt_p_publish *publish

#define RRR_MQTT_SESSION_RAM_PRETRANSMIT_METHOD_ARGS \
    int *drop,                                       \
    struct rrr_mqtt_p_publish *publish

struct rrr_mqtt_session_collection_ram_data {
	RRR_MQTT_SESSION_COLLECTION_HEAD;
	RRR_LL_HEAD(struct rrr_mqtt_session_ram);

	void (*publish_notify_callback)(RRR_MQTT_SESSION_PUBLISH_NOTIFY_ARGS);
	void *common_callback_arg;

	// Deliver PUBLISH locally (and check against subscriptions) or forward to other sessions
	int (*delivery_method)(RRR_MQTT_SESSION_RAM_DELIVERY_METHOD_ARGS);

	// Checks and modifications to perform before transmitting publish (broker handles expiry)
	int (*pretransmit_method)(RRR_MQTT_SESSION_RAM_PRETRANSMIT_METHOD_ARGS);

	// Packets in this queue are retained and will be published upon new subscriptions matching
	// topics.
	struct rrr_mqtt_p_queue retain_buffer;

	// Packets in this queue are stored until read from. Used by client program.
	struct rrr_mqtt_p_queue publish_local_buffer;

	// Should be updated using provided functions to avoid difficult to find bugs
	struct rrr_mqtt_session_collection_stats stats;
};

#define SESSION_RAM_INCREF_OR_RETURN() \
	do { \
		struct rrr_mqtt_session_collection_ram_data *ram_data = (struct rrr_mqtt_session_collection_ram_data *)(collection); \
		struct rrr_mqtt_session_ram *ram_session = __rrr_mqtt_session_collection_ram_session_find_and_incref(ram_data, (*session_to_find)); \
		if (ram_session == NULL) { \
			*session_to_find = NULL; \
			return RRR_MQTT_SESSION_DELETED; \
		}

#define SESSION_RAM_DECREF() \
		__rrr_mqtt_session_ram_decref ((ram_session)); \
	} while (0)

struct rrr_mqtt_session_ram_fifo_write_callback_data {
	struct rrr_mqtt_p *packet;
	uint64_t order;
	int do_order;
	uint64_t *stats_counter;
};

static int __rrr_mqtt_session_ram_fifo_write_callback (RRR_FIFO_WRITE_CALLBACK_ARGS) {
	struct rrr_mqtt_session_ram_fifo_write_callback_data *callback_data = arg;

	*data = (char *) callback_data->packet;
	*size = sizeof(*callback_data->packet);
	*order = callback_data->order;

	callback_data->packet = NULL;
	(*callback_data->stats_counter)++;

	if (callback_data->do_order) {
		return RRR_FIFO_WRITE_ORDERED;
	}

	return RRR_FIFO_OK;
}

static int __rrr_mqtt_session_ram_fifo_write (
		struct rrr_fifo *buffer,
		struct rrr_mqtt_p *packet,
		uint64_t order,
		int do_order,
		uint64_t *stats_counter
) {
	struct rrr_mqtt_session_ram_fifo_write_callback_data callback_data = {
		packet,
		order,
		do_order,
		stats_counter
	};

	return rrr_fifo_write (buffer, __rrr_mqtt_session_ram_fifo_write_callback, &callback_data);
}

static int __rrr_mqtt_session_ram_fifo_write_ordered (
		struct rrr_fifo *buffer,
		struct rrr_mqtt_p *packet,
		uint64_t order
) {
	uint64_t dummy_stats = 0;
	return __rrr_mqtt_session_ram_fifo_write (buffer, packet, order, 1, &dummy_stats);
}

static int __rrr_mqtt_session_ram_fifo_write_simple (
		struct rrr_fifo *buffer,
		struct rrr_mqtt_p *packet
) {
	uint64_t dummy_stats = 0;
	return __rrr_mqtt_session_ram_fifo_write (buffer, packet, 0, 0, &dummy_stats);
}

static int __rrr_mqtt_session_ram_fifo_write_with_stats (
		struct rrr_fifo *buffer,
		struct rrr_mqtt_p *packet,
		uint64_t *stats_counter
) {
	return __rrr_mqtt_session_ram_fifo_write (buffer, packet, 0, 0, stats_counter);
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_create (struct rrr_mqtt_session_collection_ram_data *data) {
	data->stats.active++;
	data->stats.total_created++;
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_delete (struct rrr_mqtt_session_collection_ram_data *data) {
	data->stats.active--;
	data->stats.total_deleted++;
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_forwarded (struct rrr_mqtt_session_collection_ram_data *data, unsigned int num) {
	data->stats.total_publish_forwarded_out += num;
}

static inline void __rrr_mqtt_session_collection_ram_stats_notify_not_forwarded (struct rrr_mqtt_session_collection_ram_data *data) {
	data->stats.total_publish_not_forwarded++;
}

static int __rrr_mqtt_session_collection_ram_get_stats (
		struct rrr_mqtt_session_collection_stats *target,
		struct rrr_mqtt_session_collection *collection
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *)(collection);

	*target = data->stats;

	return 0;
}

struct mqtt_session_ram_retain_buffer_insert_callback_data {
	struct rrr_mqtt_p_publish *publish;
	int is_zero_byte_payload;
};

static int __rrr_mqtt_session_ram_retain_buffer_write_callback (
		RRR_FIFO_WRITE_CALLBACK_ARGS
) {
	int ret = RRR_FIFO_OK;

	// Remember that data is double pointer **data

	struct mqtt_session_ram_retain_buffer_insert_callback_data *callback_data = arg;

	if (callback_data->publish == NULL) {
		// We always get called again after iteration, but if we already replaced
		// another entry, don't do anything
		ret = RRR_FIFO_WRITE_DROP;
		goto out;
	}

	if (*data == NULL) {
		if (callback_data->is_zero_byte_payload) {
			RRR_DBG_3("Note: MQTT broker received zero-byte RETAIN PUBLISH with topic '%s', but no topics matched\n",
					callback_data->publish->topic);
			ret = RRR_FIFO_WRITE_DROP;
			goto out;
		}
		RRR_DBG_3("MQTT broker new RETAIN PUBLISH with topic '%s' expiry interval is %" PRIu32 "\n",
				callback_data->publish->topic, callback_data->publish->message_expiry_interval);
		// No topic has matched, add entry to buffer. We are in fifo write context
		goto out_do_write;
	}
	else {
		// We are in fifo search and replace context
		struct rrr_mqtt_p_publish *publish_in_buffer = (struct rrr_mqtt_p_publish *) *data;

		int topic_matches = 0;

		topic_matches = (strcmp(publish_in_buffer->topic, callback_data->publish->topic) == 0 ? 1 : 0);

		if (topic_matches) {
			// A payload length of 0 instructs us to delete old entry only
			if (callback_data->is_zero_byte_payload) {
				RRR_DBG_3("MQTT broker deleting RETAIN PUBLISH with topic '%s'\n",
						callback_data->publish->topic);

				// Stop debug/error message in last write iteration
				callback_data->publish = NULL;

				ret = RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE|RRR_FIFO_SEARCH_STOP;
				goto out;
			}
			else {
				RRR_DBG_3("MQTT broker replacing RETAIN PUBLISH with topic '%s' expiry interval is %" PRIu32 "\n",
						callback_data->publish->topic, callback_data->publish->message_expiry_interval);
				ret = RRR_FIFO_SEARCH_REPLACE|RRR_FIFO_SEARCH_FREE|RRR_FIFO_SEARCH_STOP;
				goto out_do_write;
			}
		}
	}

	goto out;
	out_do_write:
		*data = (char *) callback_data->publish;
		*size = sizeof(struct rrr_mqtt_p);
		*order = 0;

		callback_data->publish = NULL;

	out:
		return ret;
}

struct receive_forwarded_publish_data {
	struct rrr_mqtt_session_ram *session;
};

static int __rrr_mqtt_session_ram_receive_forwarded_publish_match_callback (
		const struct rrr_mqtt_p_publish *publish,
		const struct rrr_mqtt_subscription *subscription,
		void *arg
) {
	struct receive_forwarded_publish_data *callback_data = arg;
	struct rrr_mqtt_session_ram *session = callback_data->session;

	int ret = RRR_MQTT_SESSION_OK;

	struct rrr_mqtt_p_publish *new_publish = NULL;

	if ( session->session_properties.numbers.maximum_packet_size != 0 &&
	     publish->received_size > (int64_t) session->session_properties.numbers.maximum_packet_size
	) {
		RRR_MSG_0("Not forwarding matching PUBLISH to client, packet size exceeds set maximum packet size%" PRIrrrl ">%u\n",
				publish->received_size, session->session_properties.numbers.maximum_packet_size);
		ret = RRR_MQTT_SESSION_OK;
		goto out;
	}

	if ((new_publish = rrr_mqtt_p_clone_publish (
			publish, 1, 0, 0 // Preserve only type flags, but DUP and Retain flags are always overwritten elsewhere
	)) == NULL) {
		RRR_MSG_0("Could not clone PUBLISH packet in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}

	// Always clear retain flag per specification
	RRR_MQTT_P_PUBLISH_SET_FLAG_RETAIN(new_publish, 0);

	// Always clear dup flag per speficiation
	RRR_MQTT_P_PUBLISH_SET_FLAG_DUP(new_publish, 0);
	new_publish->dup = 0;

	// We don't set the new packet ID yet in case the client is not currently connected
	// and many packets would exhaust the 16-bit ID field. It is set when iterating the
	// send queue and the zero ID is found.
	new_publish->packet_identifier = 0;

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(new_publish) > subscription->qos_or_reason_v5) {
		// Downgrade QOS
		RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(new_publish, subscription->qos_or_reason_v5);
	}

	RRR_DBG_2("  => Forward PUBLISH topic '%s' qos %u to client %s\n",
			publish->topic,
			RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish),
			session->client_id_
	);

	new_publish->is_outbound = 1;

	if (__rrr_mqtt_session_ram_fifo_write_simple (
			&session->to_remote_buffer.buffer,
			(struct rrr_mqtt_p *) new_publish
	) != 0) {
		RRR_MSG_0("Could not write to to_remote_queue in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(new_publish);
	return ret;
}

static int __rrr_mqtt_session_ram_receive_forwarded_publish (
		struct rrr_mqtt_session_ram *ram_session,
		const struct rrr_mqtt_p_publish *publish,
		rrr_length *match_count
) {
	int ret = RRR_MQTT_SESSION_OK;

	struct receive_forwarded_publish_data callback_data = { ram_session };

	// Note : We always send one PUBLISH per matching subscription and do
	//        not check for overlaps. Other brokers might treat this different
	//        and only send one PUBLISH. The different methods comply with
	//        the standards (both V3.1.1 and V5), but the method here is the
	//        least complex to implement.

	if ((ret = rrr_mqtt_subscription_collection_match_publish_with_callback (
			ram_session->subscriptions,
			publish,
			__rrr_mqtt_session_ram_receive_forwarded_publish_match_callback,
			&callback_data,
			match_count
	)) != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error while matching publish packet against subscriptions in %s, return was %i\n",
				__func__, ret);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	return ret;
}

static int __rrr_mqtt_session_collection_ram_forward_publish_to_clients (
		struct rrr_mqtt_session_collection_ram_data *ram_data,
		const struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_FIFO_OK;

	rrr_length total_match_count = 0;

	RRR_LL_ITERATE_BEGIN(ram_data, struct rrr_mqtt_session_ram);
		rrr_length match_count = 0;
		int ret_tmp = __rrr_mqtt_session_ram_receive_forwarded_publish(node, publish, &match_count);
		total_match_count += match_count;

		if (ret_tmp != RRR_MQTT_SESSION_OK) {
			RRR_MSG_0("Error while receiving forwarded publish message, return was %i\n", ret);
			ret |= RRR_FIFO_GLOBAL_ERR;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	if (total_match_count == 0) {
		__rrr_mqtt_session_collection_ram_stats_notify_not_forwarded(ram_data);
	}
	else {
		__rrr_mqtt_session_collection_ram_stats_notify_forwarded(ram_data, total_match_count);
	}

	return ret;
}

static int __rrr_mqtt_session_collection_ram_delivery_forward_final (
		struct rrr_mqtt_session_collection_ram_data *ram_data,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(publish) != 0) {
		int is_zero_byte_payload = 0;

		// Zero-byte payload publishes will remove matching topics
		// from retain queue and not forwarded

		if (publish->payload == NULL) {
			is_zero_byte_payload = 1;
		}
		else {
			if (publish->payload->length == 0) {
				is_zero_byte_payload = 1;
			}
		}

		struct mqtt_session_ram_retain_buffer_insert_callback_data callback_data = {
			publish,
			is_zero_byte_payload
		};

		if (rrr_fifo_search_and_replace (
				&ram_data->retain_buffer.buffer,
				__rrr_mqtt_session_ram_retain_buffer_write_callback,
				&callback_data,
				1  // <-- Call callback again for potential write operation after looping
		) != 0) {
			RRR_MSG_0("Could not write to retain queue in %s\n", __func__);
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}
	}

	if ((ret = __rrr_mqtt_session_collection_ram_forward_publish_to_clients (
			ram_data,
			publish
	)) != 0) {
		goto out;
	}

	// Notify application. It should after this call forward maintain function.
	ram_data->publish_notify_callback(ram_data->common_callback_arg);

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_check_publish_expired (
		struct rrr_mqtt_p_publish *publish
) {
	if ( publish->message_expiry_interval != 0 &&
	     publish->create_time + (uint64_t) publish->message_expiry_interval * 1000 * 1000 < rrr_time_get_64()
	) {
		return 1;
	}

	return 0;
}

static int __rrr_mqtt_session_ram_update_publish_expiry_interval_properties ( 
		struct rrr_mqtt_p_publish *publish
) {
	int ret = 0;

	if (publish->message_expiry_interval == 0) {
		goto out;
	}

	const uint32_t old_interval = publish->message_expiry_interval;
	const uint32_t diff_s = (uint32_t) ((rrr_time_get_64() - publish->create_time) / 1000 / 1000);
	const uint32_t new_interval = diff_s >= old_interval ? 1 : old_interval - diff_s;

	rrr_mqtt_property_collection_clear_by_id (&publish->properties, RRR_MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL);
	if (rrr_mqtt_property_collection_add_uint32 (
			&publish->properties,
			RRR_MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL,
			new_interval
	) != 0) {
		RRR_MSG_0("Could not set session expiry for PUBLISH packet in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_DBG_3("%s %p id %u expiry interval updated from %" PRIu32 " to %" PRIu32 "\n",
			RRR_MQTT_P_GET_TYPE_NAME(publish),
			publish,
			RRR_MQTT_P_GET_IDENTIFIER(publish),
			old_interval,
			new_interval
	);

	out:
	return ret;
}

// Used by broker
static int __rrr_mqtt_session_ram_delivery_forward (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_publish *publish
) {
	RRR_DBG_2(">=   Forward PUBLISH topic '%s' qos %u retain %u from client %s\n",
			publish->topic,
			RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish),
			RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(publish),
			ram_session->client_id_
	);

	return __rrr_mqtt_session_collection_ram_delivery_forward_final (
			ram_session->ram_data,
			publish
	);
}

// Used by broker
static int __rrr_mqtt_session_ram_pretransmit_forward (
		int *drop,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = 0;

	*drop = 0;

	if (publish->message_expiry_interval == 0) {
		goto out;
	}

	if (__rrr_mqtt_session_ram_check_publish_expired (publish)) {
		RRR_DBG_3("Expired PUBLISH with topic '%s' during pretransmit, deleting.\n", publish->topic);
		*drop = 1;
		goto out;
	}

	// Only update the properties which is sent to the client. Preserve
	// the original value in case it needs to be checked for expiration.
	if (!publish->message_expiry_interval_properties_updated && (ret = __rrr_mqtt_session_ram_update_publish_expiry_interval_properties (
			publish
	)) != 0) {
		goto out;
	}

	publish->message_expiry_interval_properties_updated = 1;

	out:
	return ret;
}

// Used by client
static int __rrr_mqtt_session_ram_delivery_local (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if ((ret = rrr_mqtt_subscription_collection_match_publish (
			ram_session->subscriptions,
			publish
	)) != RRR_MQTT_SUBSCRIPTION_MATCH) {
		if (ret != RRR_MQTT_SUBSCRIPTION_MISMATCH) {
			RRR_MSG_0("Error while checking PUBLISH against subscriptions in %s\n", __func__);
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}
		ret = RRR_MQTT_SESSION_OK;
		goto out; // No match
	}

	if (__rrr_mqtt_session_ram_fifo_write_with_stats (
			&ram_session->ram_data->publish_local_buffer.buffer,
			(struct rrr_mqtt_p *) publish,
			&ram_session->ram_data->stats.total_publish_delivered
	) != 0) {
		RRR_MSG_0("Could not write to publish local queue in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	// Notify application. It should after this clear local delivery buffer.
	ram_session->ram_data->publish_notify_callback(ram_session->ram_data->common_callback_arg);

	out:
	return ret;
}

// Used by client
static int __rrr_mqtt_session_ram_pretransmit_local (
		int *drop,
		struct rrr_mqtt_p_publish *publish
) {
	(void)(publish);

	*drop = 0;

	// Nothing to do

	return 0;
}

static int __rrr_mqtt_session_collection_ram_create_and_add_session (
		struct rrr_mqtt_session_ram **target,
		struct rrr_mqtt_session_collection_ram_data *data,
		const char *client_id
) {
	struct rrr_mqtt_session_ram *result = NULL;
	int ret = RRR_MQTT_SESSION_OK;

	*target = NULL;

	result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}
	memset(result, '\0', sizeof(*result));

	if (client_id != NULL && *client_id != '\0') {
		if ((result->client_id_ = rrr_strdup(client_id)) == NULL) {
			RRR_MSG_0("Could not allocate memory for client ID in %s\n", __func__);
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out_free_result;
		}
	}

	if ((ret = rrr_mqtt_subscription_collection_new(&result->subscriptions)) != 0) {
		RRR_MSG_0("Could not create subscription collection in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_free_client_id;
	}

	if (rrr_mqtt_id_pool_init(&result->id_pool) != 0) {
		RRR_MSG_0("Could not initialize ID pool in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out_destroy_subscriptions;
	}

	rrr_fifo_init_custom_refcount(&result->to_remote_buffer.buffer, rrr_mqtt_p_standardized_incref, rrr_mqtt_p_standardized_decref);
	rrr_fifo_init_custom_refcount(&result->to_remote_delayed_buffer.buffer, rrr_mqtt_p_standardized_incref, rrr_mqtt_p_standardized_decref);
	rrr_fifo_init_custom_refcount(&result->from_remote_buffer.buffer, rrr_mqtt_p_standardized_incref, rrr_mqtt_p_standardized_decref);
	rrr_fifo_init_custom_refcount(&result->publish_grace_buffer.buffer, rrr_mqtt_p_standardized_incref, rrr_mqtt_p_standardized_decref);

	result->users = 1;
	result->ram_data = data;
	result->heartbeat_time = rrr_time_get_64();

	RRR_LL_UNSHIFT(data,result);

	*target = result;

	goto out;

/*	out_destroy_id_pool:
		rrr_mqtt_id_pool_destroy(&result->id_pool);*/
	out_destroy_subscriptions:
		rrr_mqtt_subscription_collection_destroy(result->subscriptions);
	out_free_client_id:
		RRR_FREE_IF_NOT_NULL(result->client_id_);
	out_free_result:
		RRR_FREE_IF_NOT_NULL(result->client_id_);
		RRR_FREE_IF_NOT_NULL(result);
	out:
		return ret;
}

struct session_collection_ram_iterate_retain_callback_data {
	const struct rrr_mqtt_subscription_collection *subscriptions;
	int (*match_callback) (
			const struct rrr_mqtt_p_publish *publish,
			const struct rrr_mqtt_subscription *subscription,
			void *callback_arg
	);
	void *match_callback_arg;
};

static int __rrr_mqtt_session_collection_ram_iterate_retain_callback (
		RRR_FIFO_READ_CALLBACK_ARGS
) {
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct session_collection_ram_iterate_retain_callback_data *callback_data = arg;

	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) data;

	if (publish->payload == NULL) {
		RRR_BUG("BUG: Publish with NULL payload in %s\n", __func__);
	}

	if (__rrr_mqtt_session_ram_check_publish_expired(publish)) {
		RRR_DBG_3("Found expired RETAIN PUBLISH with topic '%s', deleting. Expiry interval is %" PRIu32 " current age is %" PRIu64 ".\n",
			publish->topic,
			publish->message_expiry_interval,
			(rrr_time_get_64() - publish->create_time) / 1000 / 1000
		);
		ret = RRR_FIFO_SEARCH_GIVE|RRR_FIFO_SEARCH_FREE;
		goto out;
	}

	rrr_length match_count_dummy = 0;

	if ((ret = rrr_mqtt_subscription_collection_match_publish_with_callback (
			callback_data->subscriptions,
			publish,
			callback_data->match_callback,
			callback_data->match_callback_arg,
			&match_count_dummy
	)) != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Error %i while checking subscriptions against publish in %s\n",ret, __func__);
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_collection_ram_iterate_retain (
		struct rrr_mqtt_session_collection_ram_data *data,
		const struct rrr_mqtt_subscription_collection *subscriptions,
		int (*match_callback) (
				const struct rrr_mqtt_p_publish *publish,
				const struct rrr_mqtt_subscription *subscription,
				void *callback_arg
		),
		void *match_callback_arg
) {
	// NULL subscriptions is allowed
	struct session_collection_ram_iterate_retain_callback_data callback_data = {
			subscriptions,
			match_callback,
			match_callback_arg
	};

	return rrr_fifo_search (
			&data->retain_buffer.buffer,
			__rrr_mqtt_session_collection_ram_iterate_retain_callback,
			&callback_data
	);
}

static int __rrr_mqtt_session_ram_packet_id_release (struct rrr_mqtt_p *packet) {
	RRR_MQTT_P_CLEAR_POOL_ID(packet);
	return 0;
}

static int __rrr_mqtt_session_ram_packet_id_release_callback (RRR_FIFO_CLEAR_CALLBACK_ARGS) {
	struct rrr_mqtt_p *packet = *((struct rrr_mqtt_p **) data);

	(void)(size);
	(void)(callback_data);

	return (__rrr_mqtt_session_ram_packet_id_release(packet) == 0 ? RRR_FIFO_OK : RRR_FIFO_GLOBAL_ERR);
}

static int __rrr_mqtt_session_ram_decref (
		struct rrr_mqtt_session_ram *session
) {
	if (--(session->users) >= 1) {
		return 0;
	}
	if (session->users < 0) {
		RRR_BUG("users was < 0 in %s\n", __func__);
	}

	rrr_fifo_clear_with_callback(&session->to_remote_buffer.buffer, __rrr_mqtt_session_ram_packet_id_release_callback, NULL);
	rrr_fifo_clear_with_callback(&session->to_remote_delayed_buffer.buffer, __rrr_mqtt_session_ram_packet_id_release_callback, NULL);
	rrr_fifo_clear_with_callback(&session->from_remote_buffer.buffer, __rrr_mqtt_session_ram_packet_id_release_callback, NULL);
	rrr_fifo_clear_with_callback(&session->publish_grace_buffer.buffer, __rrr_mqtt_session_ram_packet_id_release_callback, NULL);

	RRR_FREE_IF_NOT_NULL(session->client_id_);

	rrr_mqtt_subscription_collection_destroy(session->subscriptions);
	rrr_mqtt_session_properties_clear(&session->session_properties);
	rrr_mqtt_id_pool_destroy(&session->id_pool);

	RRR_MQTT_P_DECREF_IF_NOT_NULL(session->will_publish);
	session->will_publish = NULL;

	rrr_free(session);

	return 0;
}

static void __rrr_mqtt_session_ram_incref (struct rrr_mqtt_session_ram *session) {
	session->users++;
}

static void __rrr_mqtt_session_collection_remove (
		struct rrr_mqtt_session_collection_ram_data *data,
		struct rrr_mqtt_session_ram *session
) {
	RRR_LL_REMOVE_NODE_IF_EXISTS (
			data,
			struct rrr_mqtt_session_ram,
			session,
			__rrr_mqtt_session_ram_decref(node)
	);

	if (session != NULL) {
		RRR_BUG("Session not found in %s\n", __func__);
	}
}

static struct rrr_mqtt_session_ram *__rrr_mqtt_session_collection_ram_find_session (
		struct rrr_mqtt_session_collection_ram_data *data,
		const char *client_id
) {
	struct rrr_mqtt_session_ram *result = NULL;

	RRR_LL_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		if (client_id == NULL) {
			if (node->client_id_ == NULL || *(node->client_id_) == '\0') {
				result = node;
			}
		}
		else if (strcmp(node->client_id_, client_id) == 0) {
			if (result != NULL) {
				RRR_BUG("Found two equal client ids in %s\n", __func__);
			}
			result = node;
		}
	RRR_LL_ITERATE_END();

	return result;
}

static int __rrr_mqtt_session_collection_ram_get_session (
		struct rrr_mqtt_session **target,
		struct rrr_mqtt_session_collection *sessions,
		const char *client_id,
		short *session_was_present,
		short no_creation
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	int ret = RRR_MQTT_SESSION_OK;

	*target = NULL;
	*session_was_present = 0;

	struct rrr_mqtt_session_ram *result = NULL;

	result = __rrr_mqtt_session_collection_ram_find_session (data, client_id);

	if (result != NULL) {
		*session_was_present = 1;
	}
	else if (no_creation == 0) {
		if ((ret = __rrr_mqtt_session_collection_ram_create_and_add_session (
				&result,
				data,
				client_id
		)) != RRR_MQTT_SESSION_OK) {
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}

		__rrr_mqtt_session_collection_ram_stats_notify_create(data);
	}

	if (result != NULL) {
		RRR_DBG_2("Got a session, session present was %i and no creation was %i\n",
				*session_was_present, no_creation);
	}

	*target = (struct rrr_mqtt_session *) result;

	out:
	return ret;
}

static void __rrr_mqtt_session_collection_ram_register_callbacks (
		struct rrr_mqtt_session_collection *sessions,
		void (*publish_notify_callback)(RRR_MQTT_SESSION_PUBLISH_NOTIFY_ARGS),
		void *arg
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	data->publish_notify_callback = publish_notify_callback;
	data->common_callback_arg = arg;
}

static struct rrr_mqtt_session_ram *__rrr_mqtt_session_collection_ram_session_find_and_incref (
		struct rrr_mqtt_session_collection_ram_data *data,
		struct rrr_mqtt_session *session
) {
	if (session == NULL) {
		return NULL;
	}

	struct rrr_mqtt_session_ram *found = NULL;

	RRR_LL_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		if ((void*) node == (void*) session) {
			__rrr_mqtt_session_ram_incref(node);
			found = node;
			RRR_LL_ITERATE_LAST();
		}
	RRR_LL_ITERATE_END();

	return found;
}

static void __rrr_mqtt_session_ram_packet_reset_id (
		struct rrr_mqtt_p *packet
) {
	packet->packet_identifier = 0;
	packet->dup = 0;
}

static int __rrr_mqtt_session_ram_release_packet_id (
		void *arg1,
		void *arg2,
		uint16_t packet_id
) {
	struct rrr_mqtt_session_collection *collection = arg1;
	struct rrr_mqtt_session *session = arg2;
	struct rrr_mqtt_session **session_to_find = &session;

	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	rrr_mqtt_id_pool_release_id(&ram_session->id_pool, packet_id);

	SESSION_RAM_DECREF();

	return ret;
}

static void __rrr_mqtt_session_ram_will_publish_unregister (
		struct rrr_mqtt_session_ram *ram_session
) {
	if (ram_session->will_publish != NULL) {
		RRR_MQTT_P_DECREF_IF_NOT_NULL(ram_session->will_publish);
		ram_session->will_publish = NULL;
	}
}

static int __rrr_mqtt_session_ram_will_publish_maintain (
		struct rrr_mqtt_session_collection_ram_data *ram_data,
		struct rrr_mqtt_session_ram *ram_session,
		short force_publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (ram_session->will_publish == NULL || ram_session->will_publish->planned_expiry_time == 0) {
		goto out;
	}

	struct rrr_mqtt_p_publish *publish = ram_session->will_publish;

	if (force_publish || publish->planned_expiry_time <= rrr_time_get_64()) {
		RRR_DBG_2("|==> WILL PUBLISH for client %s with topic '%s' retain %u, publishing now in MQTT broker.\n",
				ram_session->client_id_, publish->topic, RRR_MQTT_P_PUBLISH_GET_FLAG_RETAIN(publish));

		ret = __rrr_mqtt_session_collection_ram_delivery_forward_final (
				ram_data,
				publish
		);

		// Always unregister the will
		__rrr_mqtt_session_ram_will_publish_unregister(ram_session);

		if (ret != 0) {
			RRR_MSG_0("Warning: Error while delivering will PUBLISH after expired delay interval in %s return was %i\n", __func__, ret);
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_will_publish_notify_disconnect (
		struct rrr_mqtt_session_collection_ram_data *ram_data,
		struct rrr_mqtt_session_ram *ram_session,
		uint8_t reason_v5,
		short session_deleted
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (ram_session->will_publish == NULL) {
		goto out;
	}

	// Initialize. Delay interval is stored in seconds, multiply by 10^6.
	ram_session->will_publish->planned_expiry_time = rrr_time_get_64() + (ram_session->will_publish->will_delay_interval * 1000 * 1000);

	// Clear any WILL message unless explicitly told by client to publish it.
	// In version 3.1, the will PUBLISH is always cleared (reason_v5 will
	// always be 0 as there is no reason field in V3.1 DISCONNECT)
	if (reason_v5 == RRR_MQTT_P_5_REASON_DISCONNECT_WITH_WILL) {
		RRR_DBG_3("Normal disconnect from client '%s' with reason DISCONNECT_WITH_WILL, not clearing will message\n", ram_session->client_id_);
	}
	else if (reason_v5 == 0) {
		RRR_DBG_3("Clearing will message for client '%s' upon receival of normal disconnect in MQTT broker\n", ram_session->client_id_);
		__rrr_mqtt_session_ram_will_publish_unregister(ram_session);
	}

	if ((ret = __rrr_mqtt_session_ram_will_publish_maintain (
			ram_data,
			ram_session,
			session_deleted /* If session is deleted, ignore any delay interval */
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}

struct iterate_local_delivery_callback_data {
	void (*callback)(struct rrr_mqtt_p_publish *publish, void *arg);
	void *callback_arg;
};

static int __rrr_mqtt_session_collection_iterate_and_clear_local_delivery_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_MQTT_SESSION_OK;

	(void)(size);

	struct iterate_local_delivery_callback_data *iterate_callback_data = arg;
	struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) data;

	if (RRR_MQTT_P_GET_TYPE(publish) != RRR_MQTT_P_TYPE_PUBLISH) {
		RRR_BUG("Packet was not publish in %s\n", __func__);
	}

	iterate_callback_data->callback (
			publish,
			iterate_callback_data->callback_arg
	);

	return ret | RRR_FIFO_SEARCH_FREE;
}


static int __rrr_mqtt_session_collection_ram_iterate_and_clear_local_delivery (
		struct rrr_mqtt_session_collection *sessions,
		void (*callback)(struct rrr_mqtt_p_publish *publish, void *arg),
		void *callback_arg
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	int ret = RRR_MQTT_SESSION_OK;

	struct iterate_local_delivery_callback_data iterate_callback_data = {
			callback,
			callback_arg
	};

	RRR_MQTT_COMMON_CALL_FIFO_CHECK_RETURN_TO_SESSION_ERRORS_GENERAL(
			rrr_fifo_read_clear_forward_all (
					&data->publish_local_buffer.buffer,
					__rrr_mqtt_session_collection_iterate_and_clear_local_delivery_callback,
					&iterate_callback_data
			),
			goto out,
			" while iterating local delivery queue"
	);

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_iterate_publish_grace_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	 struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;

	(void)(size);

	int *counter = arg;

	int ret = RRR_FIFO_OK;

	if (packet->planned_expiry_time == 0) {
		RRR_BUG("BUG: Planned expiry not set in %s\n", __func__);
	}
	else if (packet->planned_expiry_time < rrr_time_get_64()) {
		RRR_DBG_3("%s %p id %u grace time is complete, deleting from buffer.\n",
			RRR_MQTT_P_GET_TYPE_NAME(packet),
			packet,
			RRR_MQTT_P_GET_IDENTIFIER(packet)
		);
		(*counter)++;
		ret = RRR_FIFO_SEARCH_GIVE | RRR_FIFO_SEARCH_FREE;
	}
	else {
		// If we encounter a packet which has not expired, it's unlikely that the rest
		// of the packets are expired.
		ret = RRR_FIFO_SEARCH_STOP;
	}

	return ret;
}
			
static int __rrr_mqtt_session_collection_ram_maintain_expire (
		struct rrr_mqtt_session_collection *sessions
) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	int ret = RRR_MQTT_SESSION_OK;

	const uint64_t time_now = rrr_time_get_64();

	// CHECK FOR EXPIRED SESSIONS AND LOOP ACK NOTIFY QUEUES
	RRR_LL_ITERATE_BEGIN(data, struct rrr_mqtt_session_ram);
		short do_expire = 0;

		if (node->prev_publish_grace_queue_iteration + RRR_MQTT_SESSION_RAM_PUBLISH_GRACE_QUEUE_INTERVAL_MS * 1000 < time_now) {
			node->prev_publish_grace_queue_iteration = time_now;

			int counter_dummy = 0;
			if (rrr_fifo_search (
					&node->publish_grace_buffer.buffer,
					__rrr_mqtt_session_ram_iterate_publish_grace_callback,
					&counter_dummy
			) != 0) {
				RRR_MSG_0("Error while iterating publish grace queue in %s\n", __func__);
				ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
				goto out;
			}
		}

		if (node->expire_time == 0 && node->heartbeat_time + RRR_MQTT_SESSION_RAM_HARD_TIMEOUT_MS * 1000 < time_now) {
			RRR_DBG_1("Session heartbeat timeout for client %s (forced timeout after %u ms as no session expiry is set)\n",
					(node->client_id_ != NULL ? node->client_id_ : "(no ID)"), RRR_MQTT_SESSION_RAM_HARD_TIMEOUT_MS);
			do_expire = 1;
		}

		// Expiration time set upon disconnect notification, and set to 0 again
		// in session init function
		if (node->expire_time != 0 && time_now >= node->expire_time) {
			RRR_DBG_1("Session expired for client %s (expiry interval was %" PRIu32 ")\n",
					(node->client_id_ != NULL ? node->client_id_ : "(no ID)"), node->session_properties.numbers.session_expiry);
			do_expire = 1;
		}

		if (do_expire) {
			RRR_LL_ITERATE_SET_DESTROY();
		}

		if ((ret = __rrr_mqtt_session_ram_will_publish_maintain (
				data,
				node,
				do_expire /* Ignore delay interval when session has expired */
		)) != 0) {
			goto out;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY (
			data,
			__rrr_mqtt_session_ram_decref(node)
	);

	out:
	return ret;
}

static void __rrr_mqtt_session_collection_ram_destroy (struct rrr_mqtt_session_collection *sessions) {
	struct rrr_mqtt_session_collection_ram_data *data = (struct rrr_mqtt_session_collection_ram_data *) sessions;

	rrr_fifo_destroy(&data->retain_buffer.buffer);
	rrr_fifo_destroy(&data->publish_local_buffer.buffer);

	RRR_LL_DESTROY (
			data,
			struct rrr_mqtt_session_ram,
			__rrr_mqtt_session_ram_decref(node)
	);

	rrr_mqtt_session_collection_destroy(sessions);

	rrr_free(sessions);
}

struct preserve_publish_list {
	RRR_LL_HEAD(struct rrr_mqtt_p);
	int error_in_callback;
};

static int __rrr_mqtt_session_ram_clean_preserve_publish_and_release_id_callback (RRR_FIFO_CLEAR_CALLBACK_ARGS) {
	struct rrr_mqtt_p *packet = *((struct rrr_mqtt_p **) data);
	struct rrr_mqtt_p_publish *publish = *((struct rrr_mqtt_p_publish **) data);
	struct preserve_publish_list *preserve_data = callback_data;

	// Upon errors, the generated linked list must be cleared by caller

	(void)(size);

	// We need to check for all possible complete states, just like when housekeeping
	// the queue. Complete packets are not preserved.
	if (	RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH &&
			packet->planned_expiry_time == 0 &&
			(
					(RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 1 && publish->qos_packets.puback == NULL) ||
					(RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 2 && publish->qos_packets.pubcomp == NULL)
			)
	) {
		// In case anybody else holds reference to the packet, we clone it. The payload
		// is not cloned, but it is INCREF'ed by the clone function.
		struct rrr_mqtt_p_publish *publish_new = rrr_mqtt_p_clone_publish (
				(struct rrr_mqtt_p_publish *) packet,
				1, 1, 1 // Preserve everything
		);
		if (publish_new == NULL) {
			RRR_MSG_0("Could not clone PUBLISH in %s\n", __func__);
			preserve_data->error_in_callback = 1;
			goto out;
		}

		if (rrr_mqtt_p_standardized_get_refcount(publish_new) != 1) {
			RRR_BUG("Usercount was not 1 in %s\n", __func__);
		}

		RRR_LL_APPEND(preserve_data, (struct rrr_mqtt_p *) publish_new);
	}

	if (__rrr_mqtt_session_ram_packet_id_release(packet) != 0) {
		RRR_BUG("Error while releasing packet ID in %s\n", __func__);
	}

	out:

	// We are not allowed to return anything but zero
	return RRR_FIFO_OK;
}

static int __rrr_mqtt_session_ram_clean_final (struct rrr_mqtt_session_ram *ram_session) {
	int ret = 0;

	struct preserve_publish_list preserve_data = {0};

	// We preserve the outbound PUBLISH packets
	// by re-queing them after the list is emptied (QOS0 are deleted, QOS1-2 are preserved).
	rrr_fifo_clear_with_callback (
			&ram_session->to_remote_buffer.buffer,
			__rrr_mqtt_session_ram_clean_preserve_publish_and_release_id_callback,
			&preserve_data
	);

	if (preserve_data.error_in_callback != 0) {
		RRR_MSG_0("Error from callback while clearing to_remote-buffer and preserving PUBLISH white cleaning ram session\n");
		ret = 1;
		goto out;
	}

	if (RRR_LL_COUNT(&preserve_data) > 0) {
		RRR_DBG_1("Preserved %i outbound PUBLISH when cleaning session. IDs will be reset.\n",
				RRR_LL_COUNT(&preserve_data));
	}

	// Add PUBLISH-packets to preserve back to buffer. The list is finally cleared further down.
	RRR_LL_ITERATE_BEGIN(&preserve_data, struct rrr_mqtt_p);
		__rrr_mqtt_session_ram_packet_reset_id(node);

		RRR_DBG_3("Preserved PUBLISH topic '%s' qos %u client %s\n",
				((struct rrr_mqtt_p_publish *) node)->topic,
				RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(node),
				ram_session->client_id_
		);

		if (__rrr_mqtt_session_ram_fifo_write_simple (
				&ram_session->to_remote_buffer.buffer,
				node
		) != 0) {
			RRR_MSG_0("Could not write to to_remote_queue in %s\n", __func__);
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	RRR_LL_ITERATE_END();

	rrr_fifo_clear_with_callback (
			&ram_session->from_remote_buffer.buffer,
			__rrr_mqtt_session_ram_packet_id_release_callback,
			NULL
	);

	rrr_fifo_clear_with_callback (
			&ram_session->publish_grace_buffer.buffer,
			__rrr_mqtt_session_ram_packet_id_release_callback,
			NULL
	);

	out:
	RRR_LL_DESTROY(&preserve_data, struct rrr_mqtt_p, rrr_mqtt_p_standardized_decref(node));
	rrr_mqtt_subscription_collection_clear(ram_session->subscriptions);
	rrr_mqtt_id_pool_clear(&ram_session->id_pool);

	return ret;
}

static int __rrr_mqtt_session_ram_init (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		const struct rrr_mqtt_session_properties *session_properties,
		uint64_t retry_interval_usec,
		uint32_t max_in_flight,
		uint32_t complete_publish_grace_time_s,
		short clean_session
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	// The clone function clears the target first
	if ((ret = rrr_mqtt_session_properties_clone (
			&ram_session->session_properties,
			session_properties
	)) != 0) {
		RRR_MSG_0("Could not clone properties in %s\n", __func__);
		goto out;
	}

	ram_session->retry_interval_usec = retry_interval_usec;
	ram_session->max_in_flight = max_in_flight;
	ram_session->expire_time = 0;
	ram_session->complete_publish_grace_time_s = complete_publish_grace_time_s;

	if (clean_session) {
		__rrr_mqtt_session_ram_clean_final(ram_session);
	}

	RRR_DBG_2("Initialize ram session, expiry interval is %" PRIu32 " have will publish %p\n",
			ram_session->session_properties.numbers.session_expiry,
			ram_session->will_publish
	);

	out:
	SESSION_RAM_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_clean (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	__rrr_mqtt_session_ram_clean_final(ram_session);

	SESSION_RAM_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_update_client_identifier (
		struct rrr_mqtt_session_ram *session,
		short is_v5
) {
	int ret = 0;

	char *assigned_identifier_tmp = NULL;

	if (session->session_properties.assigned_client_identifier != NULL) {
		// Only V5 CONNACK has properties

		if (rrr_mqtt_property_get_blob_as_str (
				&assigned_identifier_tmp,
				session->session_properties.assigned_client_identifier
		) != 0) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}

		if (session->client_id_ != NULL && *(session->client_id_) != '\0') {
			RRR_MSG_1("Warning: Received an assigned client ID in CONNACK as a response to a CONNECT with set client identifier, server should not do this.\n");
			if (strcmp(assigned_identifier_tmp, session->client_id_) != 0) {
				RRR_MSG_0("Server responded with assigned client identifier '%s' while '%s' was used in CONNECT, closing connection\n",
						assigned_identifier_tmp, session->client_id_);
				ret = RRR_MQTT_SESSION_ERROR;
				goto out;
			}
		}

		RRR_DBG_1("MQTT client session %p: Server assigned client identifier %s in V5 CONNACK\n",
				session, assigned_identifier_tmp);

		RRR_FREE_IF_NOT_NULL(session->client_id_);
		session->client_id_ = assigned_identifier_tmp;
		assigned_identifier_tmp = NULL;
	}
	else {
		if (is_v5) {
			if (session->client_id_ == NULL || *(session->client_id_) == '\0') {
				RRR_MSG_0("Received V5 CONNACK without assigned client identifier property in response to CONNECT with empty client identifier, this is a protocol error.\n");
				ret = RRR_MQTT_SESSION_ERROR;
				goto out;
			}
		}
		else {
			RRR_DBG_1("MQTT client session %p: Server assigned a client ID but we don't know what it is when using V3. Use V5 to make the server reveal the ID used.\n", session);
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(assigned_identifier_tmp);
	return ret;
}

static int __rrr_mqtt_session_ram_update_properties (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		const struct rrr_mqtt_session_properties *session_properties,
		const struct rrr_mqtt_session_properties_numbers *numbers_to_update,
		short is_v5
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	if ((ret = rrr_mqtt_session_properties_update (
			&ram_session->session_properties,
			session_properties,
			numbers_to_update
	)) != 0) {
		RRR_MSG_0("Could not clone properties in %s\n", __func__);
		goto out;
	}

	if ((ret = __rrr_mqtt_session_ram_update_client_identifier (
			ram_session,
			is_v5
	)) != 0) {
		goto out;
	}

	out:
	SESSION_RAM_DECREF();
	return ret;
}

// Get session properties. Target is cleaned up before used.
static int __rrr_mqtt_session_ram_get_properties (
		struct rrr_mqtt_session_properties *target,
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	// The clone function clears the target first
	if ((ret = rrr_mqtt_session_properties_clone (
			target,
			&ram_session->session_properties
	)) != 0) {
		RRR_MSG_0("Could not clone properties in %s\n", __func__);
		goto out;
	}

	out:
	SESSION_RAM_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_heartbeat (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	ram_session->heartbeat_time = rrr_time_get_64();

	SESSION_RAM_DECREF();

	return ret;
}

struct ram_process_ack_callback_data {
	struct rrr_mqtt_p *ack_packet;
	unsigned int *found;
	int is_outbound;
	struct rrr_mqtt_session_ram *ram_session;
};

static int __rrr_mqtt_session_ram_process_ack_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct ram_process_ack_callback_data *ack_callback_data = arg;
	struct rrr_mqtt_session_ram *ram_session = ack_callback_data->ram_session;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;
	struct rrr_mqtt_p *ack_packet = ack_callback_data->ack_packet;

	if (packet == ack_packet) {
		RRR_BUG("An ACK packet existed bare in a queue without being part of the original packet in %s\n", __func__);
	}

	// INCREF first because the packet we are processing possibly already is
	// held by the PUBLISH packet with user count 1, and we DECREF this pointer
	// if a QoS packet field is already filled
	RRR_MQTT_P_INCREF(ack_packet);

	if (( RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBACK ||
	      RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREC ||
	      RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREL ||
	      RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBCOMP
	)) {
		// Ignore ACK packets waiting to be sent to remote for the first time. The packet IDs
		// of these packets are both from the remote generated series and from the locally generated
		// series, and they might therefore collide.
		goto out;
	}

	if (RRR_MQTT_P_GET_IDENTIFIER(packet) != RRR_MQTT_P_GET_IDENTIFIER(ack_packet)) {
		goto out;
	}

	if (ack_callback_data->is_outbound == packet->is_outbound) {
		if (( RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBACK ||
		      RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC ||
		      RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREL ||
		      RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBCOMP
		) && RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_PUBLISH) {
			RRR_BUG("Expected packet of type %s while traversing buffer for complementary of %s," \
					"but %s was found with matching packet ID %u\n",
					RRR_MQTT_P_GET_TYPE_NAME_RAW(RRR_MQTT_P_TYPE_PUBLISH),
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
			);
		}
		else if ( RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_SUBACK &&
		          RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_SUBSCRIBE
		) {
			RRR_BUG("Expected packet of type %s while traversing buffer for complementary of %s," \
					"but %s was found with matching packet ID %u\n",
					RRR_MQTT_P_GET_TYPE_NAME_RAW(RRR_MQTT_P_TYPE_SUBACK),
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
			);
		}
		else if ( RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_UNSUBACK &&
		          RRR_MQTT_P_GET_TYPE(packet) != RRR_MQTT_P_TYPE_UNSUBSCRIBE
		) {
			RRR_BUG("Expected packet of type %s while traversing buffer for complementary of %s," \
					"but %s was found with matching packet ID %u\n",
					RRR_MQTT_P_GET_TYPE_NAME_RAW(RRR_MQTT_P_TYPE_UNSUBACK),
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
			);
		}
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;

		if ((RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBACK ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC) &&
			RRR_MQTT_P_GET_REASON_V5(ack_packet) != RRR_MQTT_P_5_REASON_OK
		) {
			const struct rrr_mqtt_p_reason *reason = rrr_mqtt_p_reason_get_v5 (RRR_MQTT_P_GET_REASON_V5(ack_packet));
			if (reason == NULL) {
				RRR_MSG_0("Unknown reason %u in PUBACK or PUBREC in %s\n", RRR_MQTT_P_GET_REASON_V5(ack_packet), __func__);
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			RRR_MSG_1("Note: PUBLISH with topic '%s' was rejected by broker with reason '%s'\n",
					publish->topic, reason->description);
		}

		if ((RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBCOMP ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC ||
			RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREL) && (
					RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) != 2
			)
		) {
			RRR_MSG_0("Received %s for PUBLISH packet id %u which was not QoS2 in %s\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet), RRR_MQTT_P_GET_IDENTIFIER(ack_packet), __func__);
			ret = RRR_FIFO_CALLBACK_ERR;
			goto out;
		}

		ret = RRR_FIFO_SEARCH_STOP;

		if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBACK) {
			if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) != 1) {
				RRR_MSG_0("Duplicate PUBACK for PUBLISH packet which was not QoS1 id %u in %s\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet), __func__);
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			if (publish->qos_packets.puback != NULL) {
				RRR_DBG_1("Received duplicate PUBACK for PUBLISH id %u direction %s\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet),
						publish->is_outbound ? "outbound" : "inbound"
				);
				RRR_MQTT_P_DECREF(publish->qos_packets.puback);
				publish->qos_packets.puback = NULL;
			}
			else if (publish->is_outbound == 0) {
				if ((ret = ram_session->ram_data->delivery_method(ram_session, publish)) != RRR_MQTT_SESSION_OK) {
					RRR_MSG_0("Error while delivering PUBLISH in %s return was %i\n", __func__, ret);
					ret = RRR_FIFO_GLOBAL_ERR;
					goto out;
				}
			}
			// Noisy
			RRR_DBG_3 ("Bind PUBACK id %u to PUBLISH\n", ack_packet->packet_identifier);
			publish->qos_packets.puback = (struct rrr_mqtt_p_puback *) ack_packet;
			ack_packet = NULL;
		}
		else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBCOMP) {
			if (publish->qos_packets.pubcomp != NULL) {
				RRR_DBG_1("Duplicate PUBCOMP for PUBLISH id %u direction %s\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet),
						publish->is_outbound ? "outbound" : "inbound"
				);
				RRR_MQTT_P_DECREF(publish->qos_packets.pubcomp);
				publish->qos_packets.pubcomp = NULL;
			}
			if (publish->qos_packets.pubrel == NULL || publish->qos_packets.pubrec == NULL) {
				RRR_MSG_0("Received premature PUBCOMP for PUBLISH id %u, PUBREC and PUBREL not complete yet\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			publish->qos_packets.pubcomp = (struct rrr_mqtt_p_pubcomp *) ack_packet;
			ack_packet = NULL;
		}
		else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREC) {
			if (publish->qos_packets.pubrec != NULL) {
				RRR_DBG_1("Received duplicate PUBREC for PUBLISH with id %u\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				RRR_MQTT_P_DECREF(publish->qos_packets.pubrec);
				publish->qos_packets.pubrec = NULL;
			}
			publish->qos_packets.pubrec = (struct rrr_mqtt_p_pubrec *) ack_packet;
			ack_packet = NULL;
		}
		else if (RRR_MQTT_P_GET_TYPE(ack_packet) == RRR_MQTT_P_TYPE_PUBREL) {
			if (publish->qos_packets.pubrec == NULL) {
				RRR_MSG_0("Received premature PUBREL for PUBLISH id %u, PUBREC not yet complete\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			if (publish->qos_packets.pubrel != NULL) {
				RRR_DBG_1("Received duplicate PUBREL for PUBLISH with id %u\n",
						RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
				RRR_MQTT_P_DECREF(publish->qos_packets.pubrel);
				publish->qos_packets.pubrel = NULL;
				// NOTE !!!! DO NOT RELEASE QOS2 PACKET AGAIN !!!!
			}
			else if (publish->is_outbound == 0) {
				if (ram_session->ram_data->delivery_method(ram_session, publish) != RRR_MQTT_SESSION_OK) {
					RRR_MSG_0("Error while delivering PUBLISH in %s\n", __func__);
					ret = RRR_FIFO_GLOBAL_ERR;
					goto out;
				}
			}
			publish->qos_packets.pubrel = (struct rrr_mqtt_p_pubrel *) ack_packet;
			ack_packet = NULL;
		}
		else {
			RRR_MSG_0("Received unknown ACK packet type %s for PUBLISH with id %u\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet), RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
			ret = RRR_FIFO_CALLBACK_ERR;
			goto out;
		}
	}
	else if (
		RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
		RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		if (	(	RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE &&
				 	RRR_MQTT_P_GET_TYPE(ack_packet) != RRR_MQTT_P_TYPE_SUBACK
				) ||
				(	RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE &&
					RRR_MQTT_P_GET_TYPE(ack_packet) != RRR_MQTT_P_TYPE_UNSUBACK
				)
		) {
			RRR_MSG_0("Received unknown ACK packet type %s for %s with id %u\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet)
			);
			ret = RRR_FIFO_CALLBACK_ERR;
			goto out;
		}

		struct rrr_mqtt_p_suback_unsuback *sub_usuback = (struct rrr_mqtt_p_suback_unsuback *) ack_packet;
		struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) packet;
		if (sub_usub->sub_usuback != NULL) {
			RRR_DBG_1("Received duplicate %s for %s with id %u\n",
					RRR_MQTT_P_GET_TYPE_NAME(ack_packet),
					RRR_MQTT_P_GET_TYPE_NAME(packet),
					RRR_MQTT_P_GET_IDENTIFIER(ack_packet));
			if (sub_usuback->dup == 0) {
				RRR_MSG_0("Duplicate %s did not have DUP flag set\n", RRR_MQTT_P_GET_TYPE_NAME(ack_packet));
				ret = RRR_FIFO_CALLBACK_ERR;
				goto out;
			}
			RRR_MQTT_P_DECREF(sub_usub->sub_usuback);
			sub_usub->sub_usuback = NULL;
		}

		sub_usuback->orig_sub_usub = sub_usub;
		sub_usub->sub_usuback = sub_usuback;
		ack_packet = NULL;
	}
	else {
		RRR_BUG("Unknown packet type %s in %s\n", RRR_MQTT_P_GET_TYPE_NAME(packet), __func__);
	}

	(*ack_callback_data->found)++;

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(ack_packet);
	return ret;
}

static int __rrr_mqtt_session_ram_process_iterate_ack (
		unsigned int *match_count,
		int is_outbound,
		struct rrr_mqtt_p *packet,
		struct rrr_mqtt_session_ram *ram_session
) {
	int ret = RRR_MQTT_SESSION_OK;

	// The match count is always updated for the
	// caller to assess, also upon errors.
	*match_count = 0;

	struct ram_process_ack_callback_data callback_data = {
			packet,
			match_count,
			is_outbound, // For bugchecks
			ram_session
	};

	if ((ret = rrr_fifo_read (
			(is_outbound ? &ram_session->to_remote_buffer.buffer : &ram_session->from_remote_buffer.buffer),
			__rrr_mqtt_session_ram_process_ack_callback,
			&callback_data
	)) != 0) {
		if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
			RRR_MSG_0("Internal error while searching send buffer in %s\n", __func__);
			ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			goto out;
		}
		RRR_MSG_0("Soft error while searching send buffer in %s return was %i\n", __func__, ret);
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_add_subscriptions (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_subscribe *subscribe,
		int (*new_subscription_callback)(const struct rrr_mqtt_subscription *subscription, void *callback_data),
		void *new_subscription_callback_data
) {
	int ret = RRR_MQTT_SESSION_OK;

	if ((ret = rrr_mqtt_subscription_collection_append_unique_copy_from_collection (
			ram_session->subscriptions,
			subscribe->subscriptions,
			0, // <-- Don't include subscriptions with errors (QoS > 2)
			new_subscription_callback,
			new_subscription_callback_data
	)) != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not add subscriptions to session in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	if (RRR_DEBUGLEVEL_2) {
		rrr_mqtt_subscription_collection_dump(ram_session->subscriptions);
	}

	return ret;
}

static int __rrr_mqtt_session_ram_remove_subscriptions (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_unsubscribe *unsubscribe
) {
	int ret = RRR_MQTT_SESSION_OK;

	rrr_length removed_count = 0;

	ret = rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
			ram_session->subscriptions,
			unsubscribe->subscriptions,
			&removed_count
	);
	if (ret != RRR_MQTT_SUBSCRIPTION_OK) {
		RRR_MSG_0("Could not remove subscriptions from session in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}

	if (RRR_DEBUGLEVEL_2) {
		rrr_mqtt_subscription_collection_dump(ram_session->subscriptions);
	}

	const rrr_length count = rrr_mqtt_subscription_collection_count(unsubscribe->subscriptions);

	if (rrr_mqtt_subscription_collection_count(unsubscribe->subscriptions) != removed_count) {
		RRR_MSG_0("MQTT %" PRIrrrl " of %" PRIrrrl " subscriptions were not removed from the session as requested\n",
				count - removed_count,
				count
		);
	}

	return ret;
}

static int __rrr_mqtt_session_ram_receive_suback (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_suback *suback
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (suback->orig_subscribe == NULL) {
		RRR_BUG("orig_subscribe not set for SUBACK in %s\n", __func__);
	}

	const rrr_length orig_count = rrr_mqtt_subscription_collection_count(suback->orig_subscribe->subscriptions);
	const rrr_length new_count = suback->acknowledgements_size;

	if (orig_count != new_count) {
		RRR_MSG_0("Topic count in received SUBACK did not match the original SUBSCRIBE, broker error\n");
		return 1;
	}

	for (rrr_length i = 0; i < new_count; i++) {
		const struct rrr_mqtt_subscription *subscription;
		subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx_const (
				suback->orig_subscribe->subscriptions,
				i
		);

		if (suback->acknowledgements[i] <= 2) {
			continue;
		}

		int did_remove = 0;
		if (rrr_mqtt_subscription_collection_remove_topic (
				&did_remove,
				ram_session->subscriptions,
				subscription->topic_filter
		) != 0) {
			RRR_MSG_0("Error while removing subscription from collection in %s\n", __func__);
			return 1;
		}

		if (did_remove == 1) {
			RRR_DBG_1("Removed topic '%s' from session subscription collection as it was rejected by the broker\n",
					subscription->topic_filter);
		}
		else {
			RRR_MSG_0("Tried to remove non-existent topic '%s' from collection in %s\n", __func__,
					subscription->topic_filter);
			return 1;
		}

	}

	if (ret != 0) {
		RRR_MSG_0("Error while iterating subscriptions in %s\n", __func__);
		ret = RRR_MQTT_SESSION_ERROR;
	}

	return ret;
}


static int __rrr_mqtt_session_ram_receive_unsuback (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_unsuback *unsuback
) {
	int ret = RRR_MQTT_SESSION_OK;

	rrr_length removed_count = 0;

	if (unsuback->orig_unsubscribe == NULL) {
		RRR_BUG("orig_unsubscribe not set for UNSUBACK in %s\n", __func__);
	}

	// Needs to be copied due to const
	struct rrr_mqtt_subscription_collection *orig_collection = NULL;
	if (rrr_mqtt_subscription_collection_clone(&orig_collection, unsuback->orig_unsubscribe->subscriptions) != 0) {
		RRR_MSG_0("Could not clone subscription collection in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
		goto out;
	}

	const rrr_length orig_count = rrr_mqtt_subscription_collection_count(orig_collection);
	const rrr_length new_count = unsuback->acknowledgements_size;

	if (RRR_MQTT_P_IS_V5(unsuback) && orig_count != new_count) {
		RRR_MSG_0("Topic count in received SUBACK did not match the original SUBSCRIBE, broker error\n");
		ret = RRR_MQTT_SESSION_ERROR;
		goto out;
	}

	if (RRR_MQTT_P_IS_V5(unsuback)) {
		for (rrr_length i = 0; i < unsuback->acknowledgements_size; i++) {
			const struct rrr_mqtt_subscription *subscription;
			subscription = rrr_mqtt_subscription_collection_get_subscription_by_idx_const (
					orig_collection,
					i
			);

			if (unsuback->acknowledgements[i] == RRR_MQTT_P_5_REASON_OK) {
				int did_remove = 0;
				if (rrr_mqtt_subscription_collection_remove_topic (
						&did_remove,
						ram_session->subscriptions,
						subscription->topic_filter
				) != 0) {
					RRR_MSG_0("Error while removing subscription from collection in %s\n", __func__);
					ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
					goto out;
				}

				if (did_remove != 1) {
					RRR_MSG_0("Tried to remove non-existent topic '%s' from collection in %s\n", __func__,
							subscription->topic_filter);
					ret = RRR_MQTT_SESSION_ERROR;
					goto out;
				}

				rrr_length_inc_bug(&removed_count);
			}
			else {
				RRR_DBG_1("MQTT unsubscription of topic '%s' failed as it was rejected by the broker with reason %u\n",
						subscription->topic_filter, unsuback->acknowledgements[i]);
			}
		}
	}
	else {
		// For version 3.1 we just have to assume that all subscriptions were removed at broker
		// as no success messages are returned in the ACK
		ret = rrr_mqtt_subscription_collection_remove_topics_matching_and_set_reason (
				ram_session->subscriptions,
				orig_collection,
				&removed_count
		);

		if (ret != 0) {
			goto out;
		}
	}

	if (RRR_DEBUGLEVEL_2) {
		rrr_mqtt_subscription_collection_dump(ram_session->subscriptions);
	}

	if (rrr_mqtt_subscription_collection_count(orig_collection) != removed_count) {
		RRR_MSG_0("Warning: Removed subscription count upon UNSUBACK did not match topic count in %s\n", __func__);
	}

	out:
	if (orig_collection != NULL) {
		rrr_mqtt_subscription_collection_destroy(orig_collection);
	}
	return ret;
}

static int __rrr_mqtt_session_ram_process_ack (
		unsigned int *match_count,
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p *packet,
		int packet_was_outbound,
		int allow_missing_publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (!RRR_MQTT_P_IS_ACK(packet)) {
		RRR_BUG("Received non-ACK packet in %s\n", __func__);
	}

	RRR_DBG_3("Process ACK packet %p id %u type %s in queue direction %s\n",
			packet,
			RRR_MQTT_P_GET_IDENTIFIER(packet),
			RRR_MQTT_P_GET_TYPE_NAME(packet),
			packet_was_outbound ? "outbound" : "inbound"
	);

	if ((ret = __rrr_mqtt_session_ram_process_iterate_ack (
			match_count,
			packet_was_outbound,
			packet,
			ram_session
	)) != 0) {
		RRR_MSG_0("Error while iterating send queue in %s\n", __func__);
		goto out;
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PINGRESP) {
		// Everything goes
	}
	else if (*match_count > 1) {
		RRR_BUG("Two packets with the same identifier %u matched while processing in %s\n",
				RRR_MQTT_P_GET_IDENTIFIER(packet), __func__);
	}
	else if (*match_count == 0) {
		RRR_DBG_1("No packet with identifier %u matched while processing ACK packet of type %s, maybe we have forgotten about a QoS2 handshake which the remote still remembers\n",
				RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

		if (packet_was_outbound == 0 && RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREL) {
			// Duplicate PUBREL packet. New PUBCOMP is to be sent, this is OK.
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBCOMP) {
			// Duplicate PUBCOMP packet is OK
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK) {
			// Duplicate SUBACK packet is OK
		}
		else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK) {
			// Duplicate UNSUBACK packet is OK
		}
		else if (allow_missing_publish == 0) {
			RRR_MSG_0("Packet identifier %u missing for ACK of type %s for packet which originated from us, this is a session error\n",
					RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));
			ret = RRR_MQTT_SESSION_ERROR;
		}
		goto out;
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK) {
		if (packet_was_outbound == 0) {
			RRR_BUG("packet_was_outbound was zero for SUBACK in %s\n", __func__);
		}
		if (__rrr_mqtt_session_ram_receive_suback(ram_session, (struct rrr_mqtt_p_suback *) packet) != 0) {
			RRR_MSG_0("Error while handling SUBACK packet in %s\n", __func__);
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK) {
		if (packet_was_outbound == 0) {
			RRR_BUG("packet_was_outbound was zero for UNSUBACK in %s\n", __func__);
		}
		if (__rrr_mqtt_session_ram_receive_unsuback(ram_session, (struct rrr_mqtt_p_unsuback *) packet) != 0) {
			RRR_MSG_0("Error while handling UNSUBACK packet in %s\n", __func__);
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	}

	out:
	return ret;
}

struct find_qos2_publish_data {
	struct rrr_mqtt_p_publish *publish;
	struct rrr_mqtt_p_publish *publish_in_buffer;
	uint16_t prev_packet_id;
};

static int __rrr_mqtt_session_ram_find_qos2_publish_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	int ret = RRR_FIFO_OK;

	(void)(size);

	struct find_qos2_publish_data *qos2_publish_data = arg;
	struct rrr_mqtt_p_publish *publish_in_buffer = (struct rrr_mqtt_p_publish *) data;
	struct rrr_mqtt_p_publish *publish_received = qos2_publish_data->publish;

	if (qos2_publish_data->prev_packet_id == publish_in_buffer->packet_identifier) {
		RRR_BUG("Two equal packet IDs in buffer __rrr_mqtt_session_ram_find_qos2_publish_callback\n");
	}
	if (qos2_publish_data->prev_packet_id > publish_in_buffer->packet_identifier) {
		RRR_BUG("Wrong order of elements in buffer in %s\n", __func__);
	}
	if (publish_in_buffer->packet_identifier == 0) {
		RRR_BUG("Packet ID was zero in %s\n", __func__);
	}
	if (RRR_MQTT_P_GET_TYPE(publish_in_buffer) != RRR_MQTT_P_TYPE_PUBLISH) {
		RRR_BUG("Non-PUBLISH packet %s in qos2 buffer in %s\n", __func__,
				RRR_MQTT_P_GET_TYPE_NAME(publish_in_buffer));
	}

	if (publish_in_buffer->packet_identifier == publish_received->packet_identifier) {
		qos2_publish_data->publish_in_buffer = publish_in_buffer;
		ret = RRR_FIFO_SEARCH_STOP;
		goto out;
	}
	else if (publish_in_buffer->packet_identifier > publish_received->packet_identifier) {
		ret = RRR_FIFO_SEARCH_STOP;
		goto out;
	}

	qos2_publish_data->prev_packet_id = publish_in_buffer->packet_identifier;

	out:
	return ret;

}

static int __rrr_mqtt_session_ram_receive_publish (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) > 2) {
		RRR_BUG("Invalid QoS %u in %s\n", RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish), __func__);
	}

	// Make sure newly generated ACKs aren't re-sent immediately when the queues are maintained
	publish->last_attempt = rrr_time_get_64();

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 0) {
		// QOS 0 packets are released immediately

		RRR_DBG_3("Receive PUBLISH QOS 0 packet %p with id %u add directly to publish queue\n",
				publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

		RRR_MQTT_P_INCREF(publish);
		ram_session->ram_data->delivery_method(ram_session, publish);
		RRR_MQTT_P_DECREF(publish);
	}
	else if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 1) {
		// QOS 1 packets are released when we send PUBACK

		RRR_DBG_3("Receive PUBLISH QOS 1 packet %p with id %u dup %u add to QoS 1/2 queue\n",
				publish, RRR_MQTT_P_GET_IDENTIFIER(publish), publish->dup);

		if (__rrr_mqtt_session_ram_fifo_write_ordered (
				&ram_session->from_remote_buffer.buffer,
				(struct rrr_mqtt_p *) publish,
				publish->packet_identifier
		) != 0) {
			RRR_MSG_0("Could not write to from_remote_queue in %s\n", __func__);
			ret = RRR_MQTT_SESSION_ERROR;
			goto out;
		}
	}
	else if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 2) {
		// QOS 2 packets are released when we send PUBCOMP

		struct find_qos2_publish_data callback_data = {
				publish,
				NULL,
				0
		};

		// Callback will INCREF the packet it finds
		int ret_tmp = rrr_fifo_read_minimum (
				&ram_session->from_remote_buffer.buffer,
				NULL,
				__rrr_mqtt_session_ram_find_qos2_publish_callback,
				&callback_data,
				(uint64_t) publish->packet_identifier - 1
		);
		if (ret_tmp != 0) {
			if ((ret_tmp & RRR_FIFO_CALLBACK_ERR) != 0) {
				RRR_MSG_0("Soft error while iterating QoS2 publish queue in %s\n", __func__);
				ret |= RRR_MQTT_SESSION_ERROR;
				ret_tmp = ret_tmp & ~(RRR_FIFO_CALLBACK_ERR);
			}
			if (ret_tmp != 0) {
				RRR_MSG_0("Internal error while iterating QoS2 publish queue in %s\n", __func__);
				ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
			}
			goto out;
		}

		struct rrr_mqtt_p_publish *publish_in_buffer = callback_data.publish_in_buffer;

		if (publish_in_buffer == NULL) {
			RRR_DBG_3("Receive PUBLISH packet %p with id %u add to QoS2 queue\n",
					publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

			if (__rrr_mqtt_session_ram_fifo_write_ordered (
					&ram_session->from_remote_buffer.buffer,
					(struct rrr_mqtt_p *) publish,
					publish->packet_identifier
			) != 0) {
				RRR_MSG_0("Could not write to from_remote_queue in %s\n", __func__);
				ret = RRR_MQTT_SESSION_ERROR;
				goto out;
			}
		}
		else {
			RRR_DBG_3("Receive duplicate PUBLISH packet %p with id %u, already in QoS2 queue\n",
					publish, RRR_MQTT_P_GET_IDENTIFIER(publish));

			if ((((publish_in_buffer->payload != NULL) ^ (publish->payload != NULL)) == 1) ||
				(publish_in_buffer->payload != NULL && (publish_in_buffer->payload->length != publish->payload->length))
			) {
				RRR_MSG_0("Received a QoS2 PUBLISH packet with equal id to another packet of different size\n");
				ret = RRR_MQTT_SESSION_ERROR;
			}
			if (publish->dup != 1) {
				RRR_MSG_0("Received a re-sent QoS2 PUBLISH packet which did not have DUP flag set\n");
				ret = RRR_MQTT_SESSION_ERROR;
			}

			goto out;
		}
	}
	else {
		RRR_BUG("Invalid QOS in __rrr_mqtt_session_ram_receive_publish");
	}

	out:
	return ret;
}

struct iterate_send_queue_callback_data {
		int (*callback)(struct rrr_mqtt_p *packet, void *arg);
		void *callback_arg;
		uint64_t complete_publish_grace_time_usec;
		uint64_t retry_interval_usec;
		struct rrr_mqtt_session_collection_ram_data *ram_data;
		struct rrr_mqtt_session_ram *ram_session;
		struct rrr_mqtt_session_iterate_send_queue_counters *counters;
};

int __rrr_mqtt_session_ram_packet_ack_complete (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p *packet,
		uint64_t complete_publish_grace_time_usec
) {
	int ret = 0;

	packet->planned_expiry_time = rrr_time_get_64() + (complete_publish_grace_time_usec);

	RRR_DBG_3("%s %p id %u is complete, starting grace time of %" PRIu64 " usecs.\n",
			RRR_MQTT_P_GET_TYPE_NAME(packet),
			packet,
			RRR_MQTT_P_GET_IDENTIFIER(packet),
			complete_publish_grace_time_usec
	);

	if ((ret = __rrr_mqtt_session_ram_fifo_write_simple (
			&ram_session->publish_grace_buffer.buffer,
			packet
	)) != 0) {
		RRR_MSG_0("Could not add packet to publish grace queue in %s\n", __func__);
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_iterate_send_queue_callback_packet_maintain (
		struct iterate_send_queue_callback_data *iterate_callback_data,
		struct rrr_mqtt_p *packet
) {
	struct rrr_mqtt_session_iterate_send_queue_counters *counters = iterate_callback_data->counters;

	int ret = RRR_FIFO_OK;

	// Packets for which we expect ACK are retained in the queue to be matched
	// with their ACKs later
	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;

		if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 0 && publish->last_attempt != 0) {
			goto out_ack_complete;
		}
		else if (
			(RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 1 && publish->qos_packets.puback != NULL) ||
			(RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 2 && publish->qos_packets.pubcomp != NULL)
		) {
			goto out_ack_complete;
		}
		else {
			goto out_ack_missing;
		}
	}
	else if (
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		struct rrr_mqtt_p_sub_usub *sub_usub = (struct rrr_mqtt_p_sub_usub *) packet;
		if (sub_usub->sub_usuback != NULL) {
			goto out_ack_complete;
		}
		goto out_ack_missing;
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PINGREQ) {
		struct rrr_mqtt_p_pingreq *pingreq = (struct rrr_mqtt_p_pingreq *) packet;
		if (pingreq->pingresp_received != 0) {
			goto out_discard;
		}
		goto out_ack_missing;
	}

	if (packet->last_attempt != 0) {
		// Last attempt is non-zero for packet not requiring ACK, it is complete
		goto out_discard;
	}

	goto out;

	out_ack_missing:
		counters->maintain_ack_missing_counter++;
		goto out;
	out_ack_complete:
		counters->maintain_ack_complete_counter++;
		if ((ret = __rrr_mqtt_session_ram_packet_ack_complete (
				iterate_callback_data->ram_session,
				packet,
				iterate_callback_data->complete_publish_grace_time_usec
		)) != 0) {
			goto out;
		}
	out_discard:
		counters->maintain_deleted_counter++;
		ret = RRR_FIFO_SEARCH_GIVE | RRR_FIFO_SEARCH_FREE;
	out:
		return ret;
}

static int __rrr_mqtt_session_ram_packet_identifier_ensure (
		struct rrr_mqtt_session_collection_ram_data *ram_data,
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p *packet
) {
	int ret = 0;

	if (packet->packet_identifier != 0) {
		goto out;
	}

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH ||
		RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
		RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		uint16_t packet_identifier = rrr_mqtt_id_pool_get_id(&ram_session->id_pool);
		if (packet_identifier == 0) {
			RRR_DBG_2("ID pool exhausted while iterating MQTT send queue, must wait until more packets are sent to remote\n");
			// Retry immediately
			packet->last_attempt = 0;
			ret = RRR_FIFO_SEARCH_STOP;
			goto out;
		}

		RRR_DBG_3("Setting new packet identifier %u for packet %p type %s while iterating send queue\n",
				packet_identifier, packet, RRR_MQTT_P_GET_TYPE_NAME(packet));

		RRR_MQTT_P_SET_PACKET_ID_WITH_RELEASER (
				packet,
				packet_identifier,
				__rrr_mqtt_session_ram_release_packet_id,
				ram_data,
				ram_session
		);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBACK ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREC ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBREL ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBCOMP ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBACK ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBACK
	) {
		RRR_BUG("Message ID was zero for %s packet in %s\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet), __func__);
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_iterate_send_queue_callback_process_publish (
		struct rrr_mqtt_p **packet_to_transmit,
		int *delete_now,
		struct iterate_send_queue_callback_data *iterate_callback_data,
		struct rrr_mqtt_p_publish *publish
) {
	struct rrr_mqtt_session_iterate_send_queue_counters *counters = iterate_callback_data->counters;

	int ret = 0;

	*packet_to_transmit = NULL;

	{
		int do_drop = 0;
		if ((ret = iterate_callback_data->ram_session->ram_data->pretransmit_method (&do_drop, publish)) != 0) {
			goto out;
		}
		if (do_drop) {

			goto out;
		}
	}

	if (publish->qos_packets.puback != NULL ||
		publish->qos_packets.pubcomp != NULL) {
		// Nothing more to do for this QoS handshake
		goto out;
	}

	if (	publish->is_outbound &&
		RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) > 0 &&
		publish->qos_packets.pubcomp == NULL &&
		publish->qos_packets.pubrec == NULL &&
		publish->planned_expiry_time == 0
	) {
		counters->incomplete_qos_publish_counter++;
	}

	if (	publish->last_attempt == 0 &&
		publish->is_outbound != 0 && (
			counters->incomplete_qos_publish_counter >= iterate_callback_data->ram_session->max_in_flight ||
			(
				iterate_callback_data->ram_session->session_properties.numbers.receive_maximum != 0 &&
				counters->incomplete_qos_publish_counter >= iterate_callback_data->ram_session->session_properties.numbers.receive_maximum
			)
		)
	) {
		// Only print messages once per iteration

		// Hard-coded limit
		if (counters->incomplete_qos_publish_counter == iterate_callback_data->ram_session->max_in_flight) {
			RRR_DBG_3("Session %p max in flight %u/%u reached\n",
					iterate_callback_data->ram_session,
					counters->incomplete_qos_publish_counter,
					iterate_callback_data->ram_session->max_in_flight
			);
		}

		// Limit from CONNECT properties
		if (counters->incomplete_qos_publish_counter == iterate_callback_data->ram_session->session_properties.numbers.receive_maximum) {
			RRR_DBG_3("Session %p receive maximum from properties %u/%u reached\n",
					iterate_callback_data->ram_session,
					counters->incomplete_qos_publish_counter,
					iterate_callback_data->ram_session->session_properties.numbers.receive_maximum
			);
		}

		goto out;
	}

	// NOTE ! This functions handles packets in both directions. For a given PUBLISH packet,
	//        the most recent ACK not acknowledged by remote will be sent.

	if ((RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 0 || RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 1) && publish->is_outbound == 1) {
		if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 0) {
			*delete_now = 1;
		}
		*packet_to_transmit = (struct rrr_mqtt_p *) publish;
	}
	else if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish) == 2) {
		if (publish->is_outbound == 1) {
			// PUBCOMP not yet received for transmitted PUBREL
			if (publish->qos_packets.pubcomp == NULL && publish->qos_packets.pubrel != NULL) {
				*packet_to_transmit = (struct rrr_mqtt_p *) publish->qos_packets.pubrel;
			}
			else if (publish->qos_packets.pubrec == NULL) {
				*packet_to_transmit = (struct rrr_mqtt_p *) publish;
			}
		}
		else {
			// PUBREL not yet received for transmitted PUBREC
			if (publish->qos_packets.pubrel == NULL && publish->qos_packets.pubrec != NULL) {
				*packet_to_transmit = (struct rrr_mqtt_p *) publish->qos_packets.pubrec;
			}
		}
	}

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_iterate_send_queue_callback_process_sub_usb (
		struct rrr_mqtt_p **packet_to_transmit,
		struct iterate_send_queue_callback_data *iterate_callback_data,
		struct rrr_mqtt_p_sub_usub *sub_usub
) {
	(void)(iterate_callback_data);

	*packet_to_transmit = (struct rrr_mqtt_p *) (sub_usub->sub_usuback != NULL ? NULL : (struct rrr_mqtt_p *) sub_usub);

	return 0;
}

static int __rrr_mqtt_session_ram_packet_transmit (
		struct rrr_mqtt_p *packet_to_transmit,
		const struct rrr_mqtt_p *packet_holder,
		int (*callback)(struct rrr_mqtt_p *packet, void *arg),
		void *callback_arg
) {
	if (packet_to_transmit->dup != 0) {
		RRR_DBG_1("!! Retransmit !! Packet of type %s id %u\n",
				RRR_MQTT_P_GET_TYPE_NAME(packet_to_transmit), RRR_MQTT_P_GET_IDENTIFIER(packet_to_transmit));
	}

	RRR_DBG_3 ("Transmission of %s %p identifier %u last attempt %" PRIu64 " holder packet is %p\n",
			RRR_MQTT_P_GET_TYPE_NAME(packet_to_transmit),
			packet_to_transmit,
			packet_to_transmit->packet_identifier,
			packet_holder->last_attempt,
			packet_holder
	);

	return callback (
			packet_to_transmit,
			callback_arg
	);
}

static int __rrr_mqtt_session_ram_iterate_send_queue_callback_final (
		struct iterate_send_queue_callback_data *iterate_callback_data,
		struct rrr_mqtt_p *packet_to_transmit,
		const struct rrr_mqtt_p *packet_holder
) {
	int ret = 0;

	ret = __rrr_mqtt_session_ram_packet_transmit (
			packet_to_transmit,
			packet_holder,
			iterate_callback_data->callback,
			iterate_callback_data->callback_arg
	);

	if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
		RRR_MSG_0("Internal error from callback in %s, return was %i\n", __func__, ret);
		ret = RRR_FIFO_GLOBAL_ERR;
		goto out;
	}
	else if (ret == RRR_FIFO_SEARCH_STOP) {
		// Callback wants to stop (with no CALLBACK_ERR set), this is OK
		goto out;
	}
	else if (ret != 0) {
		RRR_MSG_0("Soft error from callback in %s, return was %i\n", __func__, ret);
		ret = RRR_FIFO_CALLBACK_ERR|RRR_FIFO_SEARCH_STOP;
		goto out;
	}
	else {
		ret = RRR_FIFO_OK;
	}

	out:
	return ret;
}

static void __rrr_mqtt_session_ram_iterate_send_queue_callback_check_transmit_or_retransmit (
		int *do_transmit,
		struct iterate_send_queue_callback_data *iterate_callback_data,
		struct rrr_mqtt_p *packet
) {
	if (	packet->last_attempt != 0 &&
			rrr_time_get_64() - packet->last_attempt > iterate_callback_data->retry_interval_usec
	) {
		packet->last_attempt = 0;
		packet->dup = 1;
	}

	*do_transmit = (packet->last_attempt == 0 ? 1 : 0);
}

static int __rrr_mqtt_session_ram_iterate_send_queue_callback (RRR_FIFO_READ_CALLBACK_ARGS) {
	// Context is fifo_search
	// Note that counters all start on zero as iteration begins

	struct iterate_send_queue_callback_data *iterate_callback_data = arg;
	struct rrr_mqtt_session_iterate_send_queue_counters *counters = iterate_callback_data->counters;
	struct rrr_mqtt_p *packet = (struct rrr_mqtt_p *) data;
	(void)(size);

	int ret = RRR_FIFO_OK;

	int do_delete_now = 0;
	int do_transmit = 0;

	if ((ret = __rrr_mqtt_session_ram_iterate_send_queue_callback_packet_maintain (iterate_callback_data, packet)) != 0) {
		goto out;
	}

	if ((ret = __rrr_mqtt_session_ram_packet_identifier_ensure (
			iterate_callback_data->ram_data,
			iterate_callback_data->ram_session,
			packet
	)) != 0) {
		goto out;
	}

	__rrr_mqtt_session_ram_iterate_send_queue_callback_check_transmit_or_retransmit (&do_transmit, iterate_callback_data, packet);

	struct rrr_mqtt_p *packet_to_transmit = NULL;

	// We must check all publishes to count in flight QoS correctly, event when they are not to be (re)sent this round
	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		if ((ret = __rrr_mqtt_session_ram_iterate_send_queue_callback_process_publish (
				&packet_to_transmit,
				&do_delete_now,
				iterate_callback_data,
				(struct rrr_mqtt_p_publish *) packet
		)) != 0) {
			goto out;
		}
	}
	else if (
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE ||
			RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE
	) {
		if ((ret = __rrr_mqtt_session_ram_iterate_send_queue_callback_process_sub_usb (
				&packet_to_transmit,
				iterate_callback_data,
				(struct rrr_mqtt_p_sub_usub *) packet
		)) != 0) {
			goto out;
		}
	}
	else {
		RRR_BUG("BUG: Unknown packet type %s in %s\n", RRR_MQTT_P_GET_TYPE_NAME(packet), __func__);
	}

	if (packet_to_transmit == NULL || !do_transmit) {
		goto out_check_delete_now;
	}

	++counters->sent_counter;

	ret = __rrr_mqtt_session_ram_iterate_send_queue_callback_final (
			iterate_callback_data,
			packet_to_transmit,
			packet
	);
	
	// Set the last attempt of the holder packet, as packet_to transmit
	// might be store inside another packet. Set last attempt regardless
	// of return value.
	packet->last_attempt = rrr_time_get_64();

	out_check_delete_now:
		if (do_delete_now) {
			ret |= RRR_FIFO_SEARCH_GIVE | RRR_FIFO_SEARCH_FREE;
		}
	out:
		return ret;
}

static int __rrr_mqtt_session_ram_iterate_send_queue (
		struct rrr_mqtt_session_iterate_send_queue_counters *counters,
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		int (*callback)(struct rrr_mqtt_p *packet, void *arg),
		void *callback_arg
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	if (rrr_fifo_merge (
			&ram_session->to_remote_buffer.buffer,
			&ram_session->to_remote_delayed_buffer.buffer
	) != 0) {
		RRR_MSG_0("Could not merge delayed queue into queue to remote in %s\n", __func__);
		ret = RRR_MQTT_SESSION_ERROR;
		goto out_print_message;
	}

	struct iterate_send_queue_callback_data callback_data = {
			callback,
			callback_arg,
			ram_session->complete_publish_grace_time_s * 1000 * 1000,
			ram_session->retry_interval_usec,
			ram_data,
			ram_session,
			counters
	};

	// (RE)TRANSMIT PACKETS IN WHICH PUBLISH ORIGINATIED FROM US AND MAINTAIN
	ret = rrr_fifo_search (
			&ram_session->to_remote_buffer.buffer,
			__rrr_mqtt_session_ram_iterate_send_queue_callback,
			&callback_data
	);

	counters->buffer_size = rrr_fifo_get_entry_count(&ram_session->to_remote_buffer.buffer);

	if ( counters->maintain_deleted_counter > 0 ||
	     counters->maintain_ack_complete_counter > 0 ||
	     counters->maintain_ack_missing_counter > 0
	) {
		RRR_DBG_3("Queue to remote %p delete %i ACK complete %i ACK missing %i buffer size is %i\n",
				&ram_session->to_remote_buffer.buffer,
				counters->maintain_deleted_counter,
				counters->maintain_ack_complete_counter,
				counters->maintain_ack_missing_counter,
				rrr_fifo_get_entry_count(&ram_session->to_remote_buffer.buffer));
	}

	if (ret != 0) {
		goto out_print_message;
	}

	// The returned counters should only contain status of the to_remote buffer
	struct rrr_mqtt_session_iterate_send_queue_counters counters_from_remote = {0};
	callback_data.counters = &counters_from_remote;

	// RETRANSMIT PACKETS IN WHICH PUBLISH ORIGINATIED FROM REMOTE AND MAINTAIN
	ret = rrr_fifo_search (
			&ram_session->from_remote_buffer.buffer,
			__rrr_mqtt_session_ram_iterate_send_queue_callback,
			&callback_data
	);

	if ( counters->maintain_deleted_counter > 0 ||
	     counters->maintain_ack_complete_counter > 0 ||
	     counters->maintain_ack_missing_counter > 0
	) {
		RRR_DBG_3("Queue from remote %p delete %i ACK complete %i ACK missing %i buffer size is %i\n",
				&ram_session->from_remote_buffer.buffer,
				counters->maintain_deleted_counter,
				counters->maintain_ack_complete_counter,
				counters->maintain_ack_missing_counter,
				rrr_fifo_get_entry_count(&ram_session->from_remote_buffer.buffer));
	}

	if (ret != 0) {
		goto out_print_message;
	}

	out_print_message:
	if ((ret & RRR_FIFO_GLOBAL_ERR) != 0) {
		RRR_MSG_0("Internal error while iterating buffer in %s\n", __func__);
		ret = RRR_MQTT_SESSION_INTERNAL_ERROR;
	}
	else if ((ret & RRR_FIFO_CALLBACK_ERR) != 0) {
		RRR_MSG_0("Soft error while iterating buffer in %s\n", __func__);
		ret = RRR_MQTT_SESSION_ERROR;
	}
	SESSION_RAM_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_notify_disconnect (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		uint8_t reason_v5
) {
	int ret = RRR_MQTT_SESSION_OK;
	int ret_delete = 0;

	SESSION_RAM_INCREF_OR_RETURN();

	RRR_DBG_2("Session notify disconnect expiry interval: %" PRIu32 " reason: %u\n",
			ram_session->session_properties.numbers.session_expiry,
			reason_v5
	);

	if (reason_v5 == RRR_MQTT_P_5_REASON_SESSION_TAKEN_OVER) {
		RRR_DBG_1("Session notify disconnect no deletion due to session take-over\n");
		ram_session->expire_time = 0; // Never
		goto out;
	}
	else {
		if (ram_session->session_properties.numbers.session_expiry == 0xffffffff) { // 8 f's
			ram_session->expire_time = 0; // Never
		}
		else if (ram_session->session_properties.numbers.session_expiry == 0) {
			ram_session->expire_time = rrr_time_get_64(); // Now
		}
		else {
			ram_session->expire_time = rrr_time_get_64() + ((uint64_t) 1000 * (uint64_t) 1000 * (uint64_t) ram_session->session_properties.numbers.session_expiry);
		}
	}

	if (ram_session->session_properties.numbers.session_expiry == 0) {
		RRR_DBG_1("Destroying session with zero session expiry upon disconnect\n");
		__rrr_mqtt_session_collection_remove (
				ram_data,
				ram_session
		);
		*session_to_find = NULL;

		__rrr_mqtt_session_collection_ram_stats_notify_delete(ram_data);

		ret_delete = RRR_MQTT_SESSION_DELETED;
	}

	if ((ret = __rrr_mqtt_session_ram_will_publish_notify_disconnect (
			ram_data,
			ram_session,
			reason_v5,
			ret_delete != 0 ? 1 : 0
	)) != 0) {
		goto out;
	}

	out:
	SESSION_RAM_DECREF();
	return ret | ret_delete;
}

static int __rrr_mqtt_session_ram_send_packet_now_process_ack (
		struct rrr_mqtt_session_ram *ram_session,
		struct rrr_mqtt_p *packet,
		int allow_missing_originating_packet
) {
	int ret = 0;

	int packet_was_outbound = 0;

	switch (RRR_MQTT_P_GET_TYPE(packet)) {
		case RRR_MQTT_P_TYPE_SUBACK:
		case RRR_MQTT_P_TYPE_UNSUBACK:
			goto out;
		case RRR_MQTT_P_TYPE_PUBACK:
		case RRR_MQTT_P_TYPE_PUBREC:
		case RRR_MQTT_P_TYPE_PUBCOMP:
			break;
		case RRR_MQTT_P_TYPE_PUBREL:
			packet_was_outbound = 1;
			break;
		default:
			RRR_BUG("Unknown packet %s in %s\n", RRR_MQTT_P_GET_TYPE_NAME(packet), __func__);
	};

	// Incref, make sure nothing bad happens
	RRR_MQTT_P_INCREF(packet);
	unsigned int match_count = 0;
	ret = __rrr_mqtt_session_ram_process_ack (
			&match_count,
			ram_session,
			packet,
			packet_was_outbound,
			allow_missing_originating_packet
	);
	RRR_MQTT_P_DECREF(packet);

	out:
	return ret;
}

static int __rrr_mqtt_session_ram_send_packet_queue (
		rrr_length *total_send_queue_count,
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	switch (RRR_MQTT_P_GET_TYPE(packet)) {
		case RRR_MQTT_P_TYPE_PUBLISH:
			{
				struct rrr_mqtt_p_publish *publish = (struct rrr_mqtt_p_publish *) packet;
				publish->packet_identifier = 0;
				publish->is_outbound = 1;
				RRR_DBG_3("Send new PUBLISH packet with topic '%s'\n", publish->topic);
			}
			break;
		case RRR_MQTT_P_TYPE_SUBSCRIBE:
			if ((ret = __rrr_mqtt_session_ram_add_subscriptions (
					ram_session,
					(struct rrr_mqtt_p_subscribe *) packet,
					NULL,
					NULL
			)) != RRR_MQTT_SESSION_OK) {
				goto out;
			}
			break;
		case RRR_MQTT_P_TYPE_UNSUBSCRIBE:
			break;
		default:
			RRR_BUG("Unknown packet type %s in %s\n", RRR_MQTT_P_GET_TYPE_NAME(packet), __func__);
	};

	if (__rrr_mqtt_session_ram_fifo_write_simple (
			&ram_session->to_remote_buffer.buffer,
			packet
	) != 0) {
		RRR_MSG_0("Could not write to to_remote_buffer in %s\n", __func__);
		ret = 1;
	}

	out:
	*total_send_queue_count = rrr_fifo_get_entry_count(&ram_session->to_remote_buffer.buffer);
	if (ret == 0) {
		RRR_DBG_3("Send packet %p with identifier %u of type %s (queued for sending, queue size is now %" PRIrrrl ")\n",
				packet, RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet), *total_send_queue_count);
	}
	SESSION_RAM_DECREF();
	return ret;
}

static int __rrr_mqtt_session_ram_send_packet_now (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet,
		int allow_missing_originating_packet,
		int (*send_now_callback)(struct rrr_mqtt_p *packet, void *arg),
		void *send_now_callback_arg
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	if ((ret = __rrr_mqtt_session_ram_send_packet_now_process_ack (ram_session, packet, allow_missing_originating_packet)) != 0) {
		goto out;
	}

	RRR_DBG_3("Send packet %p with identifier %u of type %s (send now)\n",
			packet, RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

	packet->last_attempt = rrr_time_get_64();

	if ((ret = __rrr_mqtt_session_ram_packet_transmit(packet, packet, send_now_callback, send_now_callback_arg)) != 0) {
		RRR_MSG_0("Send now callback failed in %s\n", __func__);
	}

	out:
	SESSION_RAM_DECREF();
	return ret;
}

struct session_ram_receive_new_subscription_callback_data {
	struct rrr_mqtt_subscription_collection *collection;
};

static int __rrr_mqtt_session_ram_receive_new_subscription_callback (
		const struct rrr_mqtt_subscription *subscription,
		void *arg
) {
	struct session_ram_receive_new_subscription_callback_data *callback_data = arg;

	struct rrr_mqtt_subscription *subscription_new = NULL;

	if (rrr_mqtt_subscription_clone(&subscription_new, subscription) != 0) {
		RRR_MSG_0("Could not clone subscription in %s\n", __func__);
		return 1;
	}

	RRR_LL_APPEND(callback_data->collection, subscription_new);

	return 0;
}

struct mqtt_p_queue_publish_from_retain_callback_data {
		struct rrr_mqtt_session_ram *ram_session;
};

static int __rrr_mqtt_p_queue_publish_from_retain_callback (
		const struct rrr_mqtt_p_publish *publish,
		const struct rrr_mqtt_subscription *subscription,
		void *callback_arg
) {
	struct mqtt_p_queue_publish_from_retain_callback_data *callback_data = callback_arg;

	int ret = 0;

	struct rrr_mqtt_p_publish *new_publish = NULL;

	if ((new_publish = rrr_mqtt_p_clone_publish (
			publish,
			1, 0, 0 // Preserve type flags, but DUP and Retain flags are always overwritten elsewhere
	)) == NULL) {
		RRR_MSG_0("Could not clone publish in %s\n", __func__);
		ret = 1;
		goto out;
	}

	new_publish->message_expiry_interval_properties_updated = 0;
	new_publish->is_outbound = 1;
	RRR_MQTT_P_PUBLISH_SET_FLAG_RETAIN(new_publish, 1);

	if (RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(new_publish) > subscription->qos_or_reason_v5) {
		// Downgrade QOS
		RRR_MQTT_P_PUBLISH_SET_FLAG_QOS(new_publish, subscription->qos_or_reason_v5);
	}

	__rrr_mqtt_session_ram_packet_reset_id((struct rrr_mqtt_p *) new_publish); 

	// Use delayed write to make the SUBACK packet for the subscriptions arrive first
	if (__rrr_mqtt_session_ram_fifo_write_simple (
			&callback_data->ram_session->to_remote_delayed_buffer.buffer,
			(struct rrr_mqtt_p *) new_publish
	) != 0) {
		RRR_MSG_0("Error while adding publish to queue in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_DBG_2(">=   Queue RETAIN PUBLISH topic '%s' qos %u for sending to client %s\n",
			publish->topic,
			RRR_MQTT_P_PUBLISH_GET_FLAG_QOS(publish),
			callback_data->ram_session->client_id_
	);

	out:
	RRR_MQTT_P_DECREF_IF_NOT_NULL(new_publish);
	return ret;
}

static int __rrr_mqtt_session_ram_receive_packet (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p *packet,
		unsigned int *ack_match_count
) {
	int ret = RRR_MQTT_SESSION_OK;

	struct rrr_mqtt_subscription_collection new_subscriptions = {0};

	SESSION_RAM_INCREF_OR_RETURN();

	if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_PUBLISH) {
		ret = __rrr_mqtt_session_ram_receive_publish(ram_session, (struct rrr_mqtt_p_publish *) packet);
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_SUBSCRIBE) {
		// The packet handler for SUBSCRIBE (in broker) is responsible for setting
		// error flag on invalid subscriptions in the packet. These are not added
		// to the session.

		struct session_ram_receive_new_subscription_callback_data callback_data_add = {
				&new_subscriptions
		};

		// Note : It is also possible to call the retain queue iteration directly
		//        from the new subscription callback, maybe that is better. If there's
		//        a lot of subscriptions however, it's better to collect all subscriptions
		//        first like we do now.

		struct rrr_mqtt_p_subscribe *subscribe = (struct rrr_mqtt_p_subscribe *) packet;

		// Parser must validate topic names, or we wil BUG() in subscription framework upon invalid topics

		if (RRR_LL_COUNT(subscribe->subscriptions) == 0) {
			RRR_BUG("BUG: No subscriptions in SUBSCRIBE in %s, parser has to catch this\n", __func__);
		}

		if ((ret = __rrr_mqtt_session_ram_add_subscriptions (
				ram_session,
				subscribe,
				__rrr_mqtt_session_ram_receive_new_subscription_callback,
				&callback_data_add
		)) != 0) {
			RRR_MSG_0("Error %i while adding subscriptions in %s\n", ret, __func__);
			goto out_decref;
		}

		if (RRR_LL_COUNT(&new_subscriptions) == 0) {
			goto out_decref;
		}

		struct mqtt_p_queue_publish_from_retain_callback_data callback_data_retain_iterate = {
				ram_session
		};

		if ((ret = __rrr_mqtt_session_collection_ram_iterate_retain (
				ram_data,
				&new_subscriptions,
				__rrr_mqtt_p_queue_publish_from_retain_callback,
				&callback_data_retain_iterate
		)) != 0) {
			RRR_MSG_0("Error %i while iterating retain queue in %s\n", ret, __func__);
			goto out_decref;
		}
	}
	else if (RRR_MQTT_P_GET_TYPE(packet) == RRR_MQTT_P_TYPE_UNSUBSCRIBE) {
		ret = __rrr_mqtt_session_ram_remove_subscriptions(ram_session, (struct rrr_mqtt_p_unsubscribe *) packet);
	}
	else if (RRR_MQTT_P_IS_ACK(packet)) {
		RRR_DBG_3("Receive ACK packet %p with identifier %u of type %s\n",
			packet, RRR_MQTT_P_GET_IDENTIFIER(packet), RRR_MQTT_P_GET_TYPE_NAME(packet));

		int packet_was_outbound = 0;
		switch (RRR_MQTT_P_GET_TYPE(packet)) {
			case RRR_MQTT_P_TYPE_PUBACK:
			case RRR_MQTT_P_TYPE_PUBREC:
			case RRR_MQTT_P_TYPE_PUBCOMP:
			case RRR_MQTT_P_TYPE_SUBACK:
			case RRR_MQTT_P_TYPE_UNSUBACK:
				packet_was_outbound = 1;
				break;
			case RRR_MQTT_P_TYPE_PUBREL:
				break;
			default:
				RRR_BUG("Unknown ACK packet %u in %s\n", RRR_MQTT_P_GET_TYPE(packet), __func__);
		};

		// Incref, make sure nothing bad happens
		RRR_MQTT_P_INCREF(packet);
		ret = __rrr_mqtt_session_ram_process_ack(ack_match_count, ram_session, packet, packet_was_outbound, 0);
		RRR_MQTT_P_DECREF(packet);
	}
	else {
		RRR_BUG("Unknown packet type %u in %s\n", RRR_MQTT_P_GET_TYPE(packet), __func__);
	}

	out_decref:
	rrr_mqtt_subscription_collection_clear(&new_subscriptions);

	SESSION_RAM_DECREF();

	return ret;
}

static int __rrr_mqtt_session_ram_will_publish_register (
		struct rrr_mqtt_session_collection *collection,
		struct rrr_mqtt_session **session_to_find,
		struct rrr_mqtt_p_publish *publish
) {
	int ret = RRR_MQTT_SESSION_OK;

	SESSION_RAM_INCREF_OR_RETURN();

	__rrr_mqtt_session_ram_will_publish_unregister(ram_session);

	if (publish != NULL) {
		RRR_MQTT_P_INCREF(publish);
		ram_session->will_publish = publish;
	}

	SESSION_RAM_DECREF();

	return ret;
}

const struct rrr_mqtt_session_collection_methods methods = {
		__rrr_mqtt_session_collection_ram_get_stats,
		__rrr_mqtt_session_collection_ram_iterate_and_clear_local_delivery,
		__rrr_mqtt_session_collection_ram_maintain_expire,
		__rrr_mqtt_session_collection_ram_destroy,
		__rrr_mqtt_session_collection_ram_get_session,
		__rrr_mqtt_session_collection_ram_register_callbacks,
		__rrr_mqtt_session_ram_init,
		__rrr_mqtt_session_ram_clean,
		__rrr_mqtt_session_ram_update_properties,
		__rrr_mqtt_session_ram_get_properties,
		__rrr_mqtt_session_ram_heartbeat,
		__rrr_mqtt_session_ram_iterate_send_queue,
		__rrr_mqtt_session_ram_notify_disconnect,
		__rrr_mqtt_session_ram_send_packet_queue,
		__rrr_mqtt_session_ram_send_packet_now,
		__rrr_mqtt_session_ram_receive_packet,
		__rrr_mqtt_session_ram_will_publish_register
};

static int __rrr_mqtt_session_collection_ram_new (
		struct rrr_mqtt_session_collection **sessions,
		int (*delivery_method)(RRR_MQTT_SESSION_RAM_DELIVERY_METHOD_ARGS),
		int (*pretransmit_method)(RRR_MQTT_SESSION_RAM_PRETRANSMIT_METHOD_ARGS),
		void *arg
) {
	int ret = 0;

	if (arg != NULL) {
		RRR_BUG("arg was not NULL in %s\n", __func__);
	}

	struct rrr_mqtt_session_collection_ram_data *ram_data = rrr_allocate(sizeof(*ram_data));
	if (ram_data == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset (ram_data, '\0', sizeof(*ram_data));

	if (rrr_mqtt_session_collection_init (
			(struct rrr_mqtt_session_collection *) ram_data,
			&methods
	) != 0) {
		RRR_MSG_0("Could not initialize session collection in %s\n", __func__);
		ret = 1;
		goto out_destroy_ram_data;
	}

	rrr_fifo_init_custom_refcount(&ram_data->retain_buffer.buffer, rrr_mqtt_p_standardized_incref, rrr_mqtt_p_standardized_decref);
	rrr_fifo_init_custom_refcount(&ram_data->publish_local_buffer.buffer, rrr_mqtt_p_standardized_incref, rrr_mqtt_p_standardized_decref);

	ram_data->delivery_method = delivery_method;
	ram_data->pretransmit_method = pretransmit_method;

	*sessions = (struct rrr_mqtt_session_collection *) ram_data;

	goto out;

//	out_destroy_collection:
//		rrr_mqtt_session_collection_destroy((struct rrr_mqtt_session_collection *)ram_data);
	out_destroy_ram_data:
		rrr_free(ram_data);
	out:
		return ret;
}


int rrr_mqtt_session_collection_ram_new_broker (struct rrr_mqtt_session_collection **sessions, void *arg) {
	return __rrr_mqtt_session_collection_ram_new (
			sessions,
			__rrr_mqtt_session_ram_delivery_forward,
			__rrr_mqtt_session_ram_pretransmit_forward,
			arg
	);
}

int rrr_mqtt_session_collection_ram_new_client (struct rrr_mqtt_session_collection **sessions, void *arg) {
	return __rrr_mqtt_session_collection_ram_new (
			sessions,
			__rrr_mqtt_session_ram_delivery_local,
			__rrr_mqtt_session_ram_pretransmit_local,
			arg
	);
}

