/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>

#include "../lib/log.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/messages/messages.h"
#include "../lib/poll_helper.h"
#include "../lib/array.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_util.h"
#include "../lib/message_holder/message_holder_collection.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/message_broker.h"

struct averager_data {
	struct rrr_instance_thread_data *thread_data;
	struct rrr_msg_msg_holder_collection input_list;
	struct rrr_msg_msg_holder_collection output_list;

	// Set this to 1 when others may read from our buffer
	int preserve_point_measurements;

	// Set this to 1 to delete incoming messages which are not readings and infos
	int discard_unknown_messages;

	unsigned int timespan;
	unsigned int interval;

	char *msg_topic;
};

// In seconds, keep x seconds of readings in the buffer
#define RRR_DEFAULT_AVERAGER_TIMESPAN 15

// Create an average/max/min-reading every x seconds
#define RRR_DEFAULT_AVERAGER_INTERVAL 10

// Messages when polling from sender comes in here
int averager_poll_callback(RRR_MODULE_POLL_CALLBACK_SIGNATURE) {
	struct rrr_msg_msg *message = entry->message;

	struct rrr_instance_thread_data *thread_data = arg;
	struct averager_data *averager_data = thread_data->private_data;

	int ret = 0;

	struct rrr_msg_msg_holder *dup_entry = NULL;
	struct rrr_msg_msg *dup_message = NULL;

	if (MSG_IS_MSG(message) && MSG_IS_ARRAY(message)) {
		rrr_msg_msg_holder_incref_while_locked(entry);
		RRR_LL_APPEND(&averager_data->input_list, entry);

		if (averager_data->preserve_point_measurements == 1) {
			dup_entry = NULL;

			if (rrr_msg_msg_holder_util_clone_no_locking(&dup_entry, entry) != 0) {
				RRR_MSG_0("Could not duplicate message in poll_callback of averager instance %s\n",
						INSTANCE_D_NAME(thread_data));
				ret = 1;
				goto out;
			}

			rrr_msg_msg_holder_lock(dup_entry);

			dup_message = dup_entry->message;
			dup_entry->message = NULL;
			dup_entry->data_length = 0;

			if (averager_data->msg_topic != NULL) {
				// This will re-allocate the message
				if (rrr_msg_msg_topic_set(&dup_message, averager_data->msg_topic, strlen(averager_data->msg_topic)) != 0) {
					RRR_MSG_0("Warning: Error while setting topic to '%s' in poll_callback of averager\n", averager_data->msg_topic);
				}
			}

			dup_entry->message = dup_message;
			dup_entry->data_length = MSG_TOTAL_SIZE(dup_message);
			dup_message = NULL;

			// Due to linked list
			rrr_msg_msg_holder_incref_while_locked(dup_entry);

			rrr_msg_msg_holder_unlock(dup_entry);

			RRR_LL_APPEND(&averager_data->output_list, dup_entry);
		}
	}
	else if (averager_data->discard_unknown_messages) {
		RRR_DBG_2 ("Averager instance %s: unknown message with timestamp %" PRIu64 ", discarding according to configuration\n",
				INSTANCE_D_NAME(thread_data), message->timestamp);
	}
	else {
		RRR_DBG_2 ("Averager instance %s: unknown message with timestamp %" PRIu64 ", writing to output buffer\n",
				INSTANCE_D_NAME(thread_data), message->timestamp);
		rrr_msg_msg_holder_incref_while_locked(entry);
		RRR_LL_APPEND(&averager_data->output_list, entry);
	}

	out:
		if (dup_entry != NULL) {
			rrr_msg_msg_holder_decref(dup_entry);
		}
		RRR_FREE_IF_NOT_NULL(dup_message);
		rrr_msg_msg_holder_unlock(entry);
		return ret;
}

void averager_maintain_buffer(struct averager_data *data) {
	uint64_t timespan_useconds = data->timespan * 1000000;
	uint64_t time_now = rrr_time_get_64();
	uint64_t min_time = time_now - timespan_useconds;

	RRR_LL_ITERATE_BEGIN(&data->input_list, struct rrr_msg_msg_holder);
		rrr_msg_msg_holder_lock(node);
		struct rrr_msg_msg *message = node->message;
		if (message->timestamp < min_time) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else {
			rrr_msg_msg_holder_unlock(node);
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->input_list, 0; rrr_msg_msg_holder_decref_while_locked_and_unlock(node));
}

struct averager_calculation {
	struct averager_data *data;
	unsigned long int max;
	unsigned long int min;
	unsigned long int sum;
	unsigned long int entries;

	uint64_t timestamp_from;
	uint64_t timestamp_to;
	uint64_t timestamp_max;
	uint64_t timestamp_min;
};

static int __averager_get_64_from_array (uint64_t *result, struct averager_data *averager_data, struct rrr_array *array, const char *tag) {
	struct rrr_type_value *value = NULL;

	int ret = 0;

	*result = 0;

	if ((value = rrr_array_value_get_by_tag(array, tag)) == NULL) {
		RRR_MSG_0("Could not find tag '%s' in array message in averager instance %s, dropping message\n",
				tag, INSTANCE_D_NAME(averager_data->thread_data));
		ret = 1;
		goto out;
	}
	if (!RRR_TYPE_IS_64(value->definition->type)) {
		RRR_MSG_0("Value '%s' from array message in averager instance %s was not of type 64, dropping message\n",
				tag, INSTANCE_D_NAME(averager_data->thread_data));
		ret = 1;
		goto out;
	}

	*result = *((uint64_t*) value->data);

	out:
	return ret;
}

int averager_process_message (
		struct averager_data *averager_data,
		struct averager_calculation *calculation,
		struct rrr_msg_msg_holder *entry_locked
) {
	struct rrr_msg_msg *message = entry_locked->message;
	struct rrr_array array_tmp = {0};

	int ret = 0;

	RRR_DBG_4("averager instance %s callback got a message from buffer with timestamp %" PRIu64 "\n",
			INSTANCE_D_NAME(averager_data->thread_data), message->timestamp);

	// NOTE : Not all errors are critical, some are user caused

	if (!MSG_IS_ARRAY(message)) {
		RRR_DBG_2 ("Averager: Ignoring a message which is not and array\n");
		ret = 0;
		goto out;
	}

	if (rrr_array_message_append_to_collection(&array_tmp, message) != 0) {
		RRR_MSG_0("Could not create array in averager_callback of instance %s\n",
				INSTANCE_D_NAME(averager_data->thread_data));
		ret = 1;
		goto out;
	}

	uint64_t data_numeric;
	uint64_t timestamp_from;
	uint64_t timestamp_to;

	if ((ret = __averager_get_64_from_array(&data_numeric, averager_data, &array_tmp, "measurement")) != 0) {
		ret = 0;
		goto out;
	}
	if ((ret = __averager_get_64_from_array(&timestamp_from, averager_data, &array_tmp, "timestamp_from")) != 0) {
		ret = 0;
		goto out;
	}
	if ((ret = __averager_get_64_from_array(&timestamp_to, averager_data, &array_tmp, "timestamp_to")) != 0) {
		ret = 0;
		goto out;
	}

	calculation->entries++;
	calculation->sum += data_numeric;
	if (data_numeric >= calculation->max) {
		calculation->max = data_numeric;
		calculation->timestamp_max = timestamp_from;
	}
	if (data_numeric < calculation->min) {
		calculation->min = data_numeric;
		calculation->timestamp_min = timestamp_from;
	}
	if (timestamp_from < calculation->timestamp_from) {
		calculation->timestamp_from = timestamp_from;
	}
	if (timestamp_to > calculation->timestamp_to) {
		calculation->timestamp_to = timestamp_to;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

struct averager_spawn_message_callback_data {
	struct rrr_array *array_tmp;
	struct averager_data *data;
};

int averager_spawn_message_callback (struct rrr_msg_msg_holder *new_entry, void *arg) {
	struct averager_spawn_message_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *message = NULL;

	if (rrr_array_new_message_from_collection (
			&message,
			callback_data->array_tmp,
			rrr_time_get_64(),
			callback_data->data->msg_topic,
			(callback_data->data->msg_topic != 0 ? strlen(callback_data->data->msg_topic) : 0)
	) != 0) {
		RRR_MSG_0 ("Could not create message in averager_spawn_message of instance %s\n",
				INSTANCE_D_NAME(callback_data->data->thread_data));
		ret = 1;
		goto out;
	}

	new_entry->data_length = MSG_TOTAL_SIZE(message);
	new_entry->message = message;
	message = NULL;

	out:
	rrr_msg_msg_holder_unlock(new_entry);
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

int averager_spawn_message (
	struct averager_data *data,
	uint64_t time_from,
	uint64_t time_to,
	uint64_t average,
	uint64_t max,
	uint64_t min
) {
//	struct rrr_msg_msg *message = NULL;

	struct rrr_array array_tmp = {0};

	int ret = 0;

	if (rrr_array_push_value_u64_with_tag(&array_tmp, "timestamp_from", time_from) != 0) {
		RRR_MSG_0("Could not push 64-value onto array in averager_spawn_message\n");
		ret = 1;
		goto out;
	}
	if (rrr_array_push_value_u64_with_tag(&array_tmp, "timestamp_to", time_to) != 0) {
		RRR_MSG_0("Could not push 64-value onto array in averager_spawn_message\n");
		ret = 1;
		goto out;
	}
	if (rrr_array_push_value_u64_with_tag(&array_tmp, "average", average) != 0) {
		RRR_MSG_0("Could not push 64-value onto array in averager_spawn_message\n");
		ret = 1;
		goto out;
	}
	if (rrr_array_push_value_u64_with_tag(&array_tmp, "max", max) != 0) {
		RRR_MSG_0("Could not push 64-value onto array in averager_spawn_message\n");
		ret = 1;
		goto out;
	}
	if (rrr_array_push_value_u64_with_tag(&array_tmp, "min", min) != 0) {
		RRR_MSG_0("Could not push 64-value onto array in averager_spawn_message\n");
		ret = 1;
		goto out;
	}

	struct averager_spawn_message_callback_data callback_data = {
			&array_tmp,
			data
	};

	if (rrr_msg_msg_broker_write_entry (
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			averager_spawn_message_callback,
			&callback_data
	) != 0) {
		RRR_MSG_0("Could not create and write array message to output buffer in averager instance %s\n",
				INSTANCE_D_NAME(data->thread_data));
		ret = 1;
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

int averager_calculate_average(struct averager_data *data) {
	struct averager_calculation calculation = {data, 0, ULONG_MAX, 0, 0, UINT64_MAX, 0, 0, 0};

	int ret = 0;

	RRR_LL_ITERATE_BEGIN(&data->input_list, struct rrr_msg_msg_holder);
		rrr_msg_msg_holder_lock(node);
		if ((ret = averager_process_message(data, &calculation, node)) != 0) {
			rrr_msg_msg_holder_unlock(node);
			RRR_LL_ITERATE_LAST();
		}
		RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(&data->input_list, 0; rrr_msg_msg_holder_decref_while_locked_and_unlock(node));

	if (ret != 0) {
		goto out;
	}

	if (calculation.entries == 0) {
		RRR_DBG_2 ("Averager: No entries, not averaging\n");
		return ret;
	}

	unsigned long int average = calculation.sum/calculation.entries;
	RRR_DBG_2 ("Average: %lu, Max: %lu, Min: %lu, Entries: %lu\n", average, calculation.max, calculation.min, calculation.entries);

	// Use the maximum timestamp for "to" for all three to make sure they can be written on block device
	// without newer timestamps getting written before older ones.

	ret |= averager_spawn_message (
			data,
			calculation.timestamp_from,
			calculation.timestamp_to,
			average,
			calculation.max,
			calculation.min
	);

	if (ret != 0) {
		RRR_MSG_0("Error when spawning messages in averager_calculate_average\n");
		return ret;
	}

	out:
	return ret;
}

void averager_data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct averager_data *data = (struct averager_data *) arg;
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
	rrr_msg_msg_holder_collection_clear (&data->input_list);
	rrr_msg_msg_holder_collection_clear (&data->output_list);
	RRR_FREE_IF_NOT_NULL(data->msg_topic);
}

int averager_data_init(struct averager_data *data, struct rrr_instance_thread_data *thread_data) {
	memset(data, '\0', sizeof(*data));

	data->thread_data = thread_data;

	return 0;
}

int averager_parse_config (struct averager_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint timespan = 0;
	rrr_setting_uint interval = 0;
	int preserve_points = 0;
	int discard_unknowns = 0;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->msg_topic, config, "avg_message_topic")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Syntax error in avg_message_topic for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_instance_config_read_unsigned_integer(&timespan, config, "avg_timespan")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Syntax error in avg_timespan for instance %s, must be a number\n", config->name);
			ret = 1;
			goto out;
		}
		timespan = RRR_DEFAULT_AVERAGER_TIMESPAN;
		ret = 0;
	}

	if ((ret = rrr_instance_config_read_unsigned_integer(&interval, config, "avg_interval")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Syntax error in avg_interval for instance %s, must be a number\n", config->name);
			ret = 1;
			goto out;
		}
		interval = RRR_DEFAULT_AVERAGER_INTERVAL;
		ret = 0;
	}

	if ((ret = rrr_instance_config_check_yesno(&preserve_points, config, "avg_preserve_points")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Syntax error in avg_preserve_points for instance %s, specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		preserve_points = 0;
		ret = 0;
	}

	if ((ret = rrr_instance_config_check_yesno(&discard_unknowns, config, "avg_discard_unknowns")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Syntax error in avg_discard_unknowns for instance %s, specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		discard_unknowns = 0;
		ret = 0;
	}

	data->discard_unknown_messages = discard_unknowns;
	data->timespan = timespan;
	data->interval = interval;
	data->preserve_point_measurements = preserve_points;

	out:

	return ret;
}

static void *thread_entry_averager(struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct averager_data *data = thread_data->private_data = thread_data->private_memory;


	int init_ret = 0;
	if ((init_ret = averager_data_init(data, thread_data)) != 0) {
		RRR_MSG_0("Could not initialize data in averager instance %s flags %i\n",
				INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	RRR_DBG_1 ("Averager thread data is %p\n", thread_data);

	pthread_cleanup_push(averager_data_cleanup, data);
//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (averager_parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_0("Could parse configuration in averager instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("Averager: Interval: %u, Timespan: %u, Preserve points: %i\n",
			data->interval, data->timespan, data->preserve_point_measurements);

	rrr_poll_add_from_thread_senders(thread_data->poll, thread_data);

	RRR_DBG_1 ("Averager started thread %p\n", thread_data);

	uint64_t previous_average_time = rrr_time_get_64();
	uint64_t average_interval_useconds = data->interval * 1000000;

	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		averager_maintain_buffer(data);

		if (rrr_poll_do_poll_delete(thread_data, thread_data->poll, averager_poll_callback, 50) != 0) {
			RRR_MSG_ERR("Error while polling in averager instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		uint64_t current_time = rrr_time_get_64();
		if (previous_average_time + average_interval_useconds < current_time) {
			if (averager_calculate_average(data) != 0) {
				RRR_MSG_ERR("Error while calculating in averager instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
			previous_average_time = current_time;
		}

		if (RRR_LL_COUNT(&data->output_list) > 0) {
			if (rrr_msg_msg_broker_write_entries_from_collection_unsafe (
					INSTANCE_D_BROKER(thread_data),
					INSTANCE_D_HANDLE(thread_data),
					&data->output_list
			) != 0) {
				RRR_MSG_ERR("Could not write to output buffer in averager instance %s\n",
						INSTANCE_D_NAME(thread_data));
				break;
			}
		}
	}

	out_message:

	RRR_DBG_1 ("Thread averager %p exiting\n", thread_data->thread);

//	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int averager_test_config (struct rrr_instance_config *config) {
	struct averager_data data;
	averager_data_init(&data, NULL);
	int ret = averager_parse_config(&data, config);
	averager_data_cleanup(&data);
	return ret;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_averager,
		NULL,
		averager_test_config,
		NULL,
		NULL
};

static const char *module_name = "averager";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	RRR_DBG_1 ("Destroy averager module\n");
}

