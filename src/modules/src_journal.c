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

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include "../lib/log.h"

#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/message_broker.h"
#include "../lib/random.h"
#include "../lib/array.h"
#include "../lib/rrr_strerror.h"
#include "../lib/stats/stats_instance.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/linked_list.h"
#include "../lib/util/gnu.h"
#include "../lib/util/rrr_time.h"

// No trailing or leading /
#define RRR_JOURNAL_TOPIC_PREFIX "rrr/journal"
#define RRR_JOURNAL_HOSTNAME_MAX_LEN 256

// Other threads must sleep when queue is full
#define RRR_JOURNAL_DELIVERY_QUEUE_SLEEP_LIMIT 5000
#define RRR_JOURNAL_DELIVERY_QUEUE_SLEEP_TIME_MS 5

struct journal_queue_entry {
	RRR_LL_NODE(struct journal_queue_entry);
	uint64_t timestamp;
	struct rrr_array array;
};

struct journal_queue {
	RRR_LL_HEAD(struct journal_queue_entry);
};

struct journal_data {
	struct rrr_instance_runtime_data *thread_data;

	int do_generate_test_messages;

	int log_hook_handle;

	pthread_mutex_t delivery_lock;
	struct journal_queue delivery_queue;
	uint64_t delivery_queue_sleep_event_count;

	int is_in_hook;
	int error_in_hook;

	uint64_t count_suppressed;
	uint64_t count_total;
	uint64_t count_processed;

	char *hostname;
};

static int journal_queue_entry_new (struct journal_queue_entry **target) {
	struct journal_queue_entry *node = NULL;

	*target = NULL;

	if ((node = malloc(sizeof(*node))) == NULL) {
		RRR_MSG_0("Could not allocate memory in journal_queue_entry_new\n");
		return 1;
	}

	memset(node, '\0', sizeof(*node));

	*target = node;

	return 0;
}

static void journal_queue_entry_destroy (struct journal_queue_entry *node) {
	rrr_array_clear(&node->array);
	free(node);
}

static int journal_data_init(struct journal_data *data, struct rrr_instance_runtime_data *thread_data) {

	// memset 0 is done in preload function, DO NOT do that here

	data->thread_data = thread_data;

	return 0;
}

static void journal_data_cleanup(void *arg) {
	struct journal_data *data = (struct journal_data *) arg;

	// DO NOT cleanup delivery_lock here, that is done in a separate function

	RRR_FREE_IF_NOT_NULL(data->hostname);

	pthread_mutex_lock(&data->delivery_lock);
	RRR_LL_DESTROY(&data->delivery_queue, struct journal_queue_entry, journal_queue_entry_destroy(node));
	pthread_mutex_unlock(&data->delivery_lock);
}

static int journal_parse_config (struct journal_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("journal_generate_test_messages", do_generate_test_messages, 0);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL("journal_hostname", hostname);

	if (data->hostname == NULL || *(data->hostname) == '\0') {
		char hostname[RRR_JOURNAL_HOSTNAME_MAX_LEN+1];

		if (gethostname(hostname, sizeof(hostname)) != 0) {
			RRR_MSG_0("Could not get system hostname in journal instance %s: %s\n",
					INSTANCE_D_NAME(data->thread_data), rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(data->hostname);
		if ((data->hostname = strdup(hostname)) == NULL) {
			RRR_MSG_0("Could not allocate memory for hostname in journal_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

// Lock must be initialized before other locks start to provide correct memory fence
static int journal_preload (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct journal_data *data = thread_data->private_data = thread_data->private_memory;

	int ret = 0;

	memset(data, '\0', sizeof(*data));

	if (rrr_posix_mutex_init(&data->delivery_lock, RRR_POSIX_MUTEX_IS_RECURSIVE) != 0) {
		RRR_MSG_0("Could not initialize lock in journal_preload\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

// Note : Context here is ANY thread
static void journal_log_hook (
		unsigned short loglevel_translated,
		unsigned short loglevel_orig,
		const char *prefix,
		const char *message,
		void *private_arg
) {
	struct journal_data *data = private_arg;

	(void)(loglevel_orig);

	// Make the calling thread pause a bit to reduce the amount of messages
	// coming in. This is done if we are unable to handle request due to
	// slowness of the readers of journal module. DO NOT sleep inside the
	// lock, that would make things worse by making journal module unable
	// to empty the delivery queue
	int do_sleep_before_return = 0;

	// This is a recursive lock
	pthread_mutex_lock(&data->delivery_lock);

	if (RRR_LL_COUNT(&data->delivery_queue) > RRR_JOURNAL_DELIVERY_QUEUE_SLEEP_LIMIT) {
		do_sleep_before_return = 1;
		data->delivery_queue_sleep_event_count++;
	}

	struct journal_queue_entry *entry = NULL;

	data->count_total++;

	if (	rrr_config_global.debuglevel != 0 &&
			rrr_config_global.debuglevel != RRR_DEBUGLEVEL_1 &&
			loglevel_translated > RRR_RFC5424_LOGLEVEL_ERROR
	) {
		// These messages must be suppressed to avoid generating new messages when processing log
		// messages created in this module
		data->count_suppressed++;
		goto out_unlock;
	}

	// In case of errors printed by the functions below, prevent recursion
	if (data->is_in_hook) {
		data->count_suppressed++;
		goto out_unlock;
	}

	data->count_processed++;

	data->is_in_hook = 1;

	if ((journal_queue_entry_new(&entry)) != 0) {
		goto out_unlock;
	}

	int ret = 0;
	ret |= rrr_array_push_value_u64_with_tag(&entry->array, "log_level_translated", loglevel_translated);
	ret |= rrr_array_push_value_str_with_tag(&entry->array, "log_prefix", prefix);
	ret |= rrr_array_push_value_str_with_tag(&entry->array, "log_message", message);

	if (ret != 0) {
		// Set error flag and leave is_in_hook set to prevent more errors before the threads exit
		data->error_in_hook = 1;
		goto out_unlock;
	}

	entry->timestamp = rrr_time_get_64();

	RRR_LL_APPEND(&data->delivery_queue, entry);
	entry = NULL;

	data->is_in_hook = 0;

	out_unlock:
		if (entry != NULL) {
			journal_queue_entry_destroy(entry);
		}
		pthread_mutex_unlock(&data->delivery_lock);
		if (do_sleep_before_return) {
			rrr_posix_usleep(RRR_JOURNAL_DELIVERY_QUEUE_SLEEP_TIME_MS * 1000);
		}
		return;
}

struct journal_write_message_callback_data {
	struct journal_data *data;
	int entry_count;
	int entry_count_limit;
};

static int journal_write_message_callback (struct rrr_msg_holder *entry, void *arg) {
	struct journal_write_message_callback_data *callback_data = arg;
	struct journal_data *data = callback_data->data;

	int ret = 0;

	char *topic_tmp = NULL;
	char *topic_tmp_final = NULL;
	struct rrr_msg_msg *reading = NULL;
	struct journal_queue_entry *queue_entry = NULL;

	pthread_mutex_lock (&data->delivery_lock);

	queue_entry = RRR_LL_SHIFT(&data->delivery_queue);

	if (queue_entry == NULL) {
		ret = RRR_MESSAGE_BROKER_DROP;
		goto out;
	}

	if (rrr_array_push_value_str_with_tag(&queue_entry->array, "log_hostname", data->hostname) != 0) {
		RRR_MSG_0("Could not push hostname to message in journal_write_message_callback of instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	struct rrr_type_value *prefix_value = rrr_array_value_get_by_tag(&queue_entry->array, "log_prefix");

	if (prefix_value == NULL || !RRR_TYPE_IS_STR_EXCACT(prefix_value->definition->type)) {
		RRR_BUG("BUG: log_prefix not set or of wrong type in journal_write_message_callback\n");
	}

	if (rrr_type_definition_str.to_str(&topic_tmp, prefix_value) != 0) {
		RRR_MSG_0("Could not get string from log prefix in journal_write_message_callback\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	if (rrr_asprintf(&topic_tmp_final, "%s/%s", RRR_JOURNAL_TOPIC_PREFIX, topic_tmp) < 0) {
		RRR_MSG_0("Could not allocate memory for prefix in journal_write_message_callback\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

//	printf ("topic: %s\n", topic_tmp_final);

	if (rrr_array_new_message_from_collection (
				&reading,
				&queue_entry->array,
				queue_entry->timestamp,
				topic_tmp_final,
				strlen(topic_tmp_final)
	) != 0) {
		RRR_MSG_0("Could create new message in journal_write_message_callback\n");
		ret = RRR_MESSAGE_BROKER_ERR;
		goto out;
	}

	entry->message = reading;
	entry->data_length = MSG_TOTAL_SIZE(reading);

	reading = NULL;

	callback_data->entry_count++;

	if (RRR_LL_COUNT(&data->delivery_queue) > 0 && callback_data->entry_count < callback_data->entry_count_limit) {
		ret = RRR_MESSAGE_BROKER_AGAIN;
	}

	out:
	if (queue_entry != NULL) {
		journal_queue_entry_destroy(queue_entry);
	}
	pthread_mutex_unlock (&data->delivery_lock);
	RRR_FREE_IF_NOT_NULL(topic_tmp_final);
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	RRR_FREE_IF_NOT_NULL(reading);
	rrr_msg_holder_unlock(entry);
	return ret;
}

static void journal_unregister_handle(void *arg) {
	struct journal_data *data = (struct journal_data *) arg;
	if (data->log_hook_handle != 0) {
		rrr_log_hook_unregister(data->log_hook_handle);
		data->log_hook_handle = 0;
	}
}

static void journal_delivery_lock_cleanup(void *arg) {
	struct journal_data *data = (struct journal_data *) arg;
	pthread_mutex_destroy(&data->delivery_lock);
}

static void *thread_entry_journal (struct rrr_thread *thread) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct journal_data *data = thread_data->private_data = thread_data->private_memory;

	// This cleanup must happen after the hook is unregistered
	pthread_cleanup_push(journal_delivery_lock_cleanup, data);

	if (journal_data_init(data, thread_data) != 0) {
		RRR_MSG_0("Could not initialize data in journal instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	RRR_DBG_1 ("journal thread data is %p\n", thread_data);

	pthread_cleanup_push(journal_data_cleanup, data);
	pthread_cleanup_push(journal_unregister_handle, data);

	rrr_thread_start_condition_helper_nofork(thread);

	if (journal_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	rrr_log_hook_register(&data->log_hook_handle, journal_log_hook, data);

	if (rrr_config_global.debuglevel != 0 && rrr_config_global.debuglevel != RRR_DEBUGLEVEL_1) {
		RRR_DBG_1("Note: journal instance %s will suppress some messages due to debuglevel other than 1 being active\n",
				INSTANCE_D_NAME(thread_data));
	}

	uint64_t time_start = rrr_time_get_64();

	uint64_t prev_suppressed = 0;
	uint64_t prev_total = 0;
	uint64_t prev_processed = 0;

	uint64_t next_test_msg_time = 0;

	uint64_t prev_delivery_queue_sleep_event_count = 0;

	while (!rrr_thread_signal_encourage_stop_check(thread)) {
		rrr_thread_watchdog_time_update(thread);

		if (data->error_in_hook) {
			RRR_MSG_0("Error encountered inside log hook of journal instance %s, exiting\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		uint64_t time_now = rrr_time_get_64();

		if (data->do_generate_test_messages) {
			if (time_now > next_test_msg_time) {
				RRR_MSG_1("Log test message from journal instance %s per configuration\n", INSTANCE_D_NAME(thread_data));
				next_test_msg_time = time_now + 1000000; // 1000 ms
			}
		}

		struct journal_write_message_callback_data callback_data = {
			data,
			0,
			400
		};

		if (rrr_message_broker_write_entry (
				INSTANCE_D_BROKER(thread_data),
				INSTANCE_D_HANDLE(thread_data),
				NULL,
				0,
				0,
				journal_write_message_callback,
				&callback_data,
				INSTANCE_D_CANCEL_CHECK_ARGS(thread_data)
		)) {
			RRR_MSG_0("Could not create new message in journal instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		if (time_now - time_start > 1000000) {
			int output_buffer_count = 0;
			int delivery_ratelimit_active = 0;
			uint64_t delivery_queue_sleep_event_count = 0;
			int delivery_queue_count = 0;

			if (rrr_instance_default_set_output_buffer_ratelimit_when_needed (
					&output_buffer_count,
					&delivery_ratelimit_active,
					thread_data
			) != 0) {
				RRR_MSG_0("Error while setting ratelimit in journal instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}

			pthread_mutex_lock(&data->delivery_lock);
			delivery_queue_sleep_event_count = data->delivery_queue_sleep_event_count;
			delivery_queue_count = RRR_LL_COUNT(&data->delivery_queue);
			pthread_mutex_unlock(&data->delivery_lock);

			time_start = time_now;
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 0, "processed", data->count_processed - prev_processed);
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 1, "suppressed", data->count_suppressed - prev_suppressed);
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 2, "total", data->count_total - prev_total);
			rrr_stats_instance_update_rate (INSTANCE_D_STATS(thread_data), 3, "delivery_queue_sleeps", delivery_queue_sleep_event_count - prev_delivery_queue_sleep_event_count);
			rrr_stats_instance_post_unsigned_base10_text (
					INSTANCE_D_STATS(thread_data),
					"output_buffer_count",
					0,
					output_buffer_count
			);
			rrr_stats_instance_post_unsigned_base10_text (
					INSTANCE_D_STATS(thread_data),
					"delivery_queue_count",
					0,
					delivery_queue_count
			);

			prev_delivery_queue_sleep_event_count = delivery_queue_sleep_event_count;
			prev_processed = data->count_processed;
			prev_suppressed = data->count_suppressed;
			prev_total = data->count_total;
		}

		if (callback_data.entry_count == 0) {
			rrr_posix_usleep (50000); // 50 ms
		}
	}

	out_cleanup:
	RRR_DBG_1 ("Thread journal instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	pthread_exit(0);
}

static struct rrr_module_operations module_operations = {
	journal_preload,
	thread_entry_journal,
	NULL,
	NULL,
	NULL
};

static const char *module_name = "journal";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_module_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(void) {
}
