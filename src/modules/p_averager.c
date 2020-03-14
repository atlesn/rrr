/*

Read Route Record

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/messages.h"
#include "../lib/poll_helper.h"
#include "../global.h"

struct averager_data {
	struct rrr_fifo_buffer input_buffer;
	struct rrr_fifo_buffer output_buffer;

	// Set this to 1 when others may read from our buffer
	int preserve_point_measurements;

	// Set this to 1 to delete incoming messages which are not readings and infos
	int discard_unknown_messages;

	unsigned int timespan;
	unsigned int interval;
};

// In seconds, keep x seconds of readings in the buffer
#define RRR_DEFAULT_AVERAGER_TIMESPAN 15

// Create an average/max/min-reading every x seconds
#define RRR_DEFAULT_AVERAGER_INTERVAL 10

// Poll of our output buffer from other modules
int averager_poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct averager_data *avg_data = data->private_data;

	return rrr_fifo_read_clear_forward(&avg_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

// Poll of our output buffer from other modules
int averager_poll (RRR_MODULE_POLL_SIGNATURE) {
	struct averager_data *avg_data = data->private_data;

	return rrr_fifo_search(&avg_data->output_buffer, callback, poll_data, wait_milliseconds);
}

// Messages when polling from sender comes in here
int poll_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct rrr_message *message = (struct rrr_message *) data;

	struct rrr_instance_thread_data *thread_data = poll_data->private_data;
	struct averager_data *averager_data = thread_data->private_data;

	// TODO : If we get an info message, the average measurements may get lost due to them having lower timestamps

	// We route info messages directly to output and store point measurements in input buffer
	if (MSG_IS_MSG_POINT(message)) {
		RRR_DBG_2 ("Averager: size %lu measurement %" PRIu64 "\n", size, message->data_numeric);
		rrr_fifo_buffer_write_ordered(&averager_data->input_buffer, message->timestamp_from, data, size);
		if (averager_data->preserve_point_measurements == 1) {
			struct rrr_message *dup_message = rrr_message_duplicate(message);
			rrr_fifo_buffer_write_ordered(&averager_data->output_buffer, message->timestamp_from,
				(char*) dup_message, sizeof(*dup_message)
			);
		}
	}
	else if (MSG_IS_MSG_INFO(message)) {
		RRR_DBG_2 ("Averager: size %lu information message\n", size);
		rrr_fifo_buffer_write_ordered(&averager_data->output_buffer, message->timestamp_from, data, size);
	}
	else if (averager_data->discard_unknown_messages) {
		RRR_DBG_2 ("Averager: size %lu unknown message, disarding according to configuration\n", size);
		free(data);
	}
	else {
		RRR_DBG_2 ("Averager: size %lu unknown message, writing to output buffer\n", size);
		rrr_fifo_buffer_write_ordered(&averager_data->output_buffer, message->timestamp_from, data, size);
	}

	return 0;
}

void averager_maintain_buffer(struct averager_data *data) {
	uint64_t timespan_useconds = data->timespan * 1000000;
	uint64_t time_now = rrr_time_get_64();

	rrr_fifo_clear_order_lt(&data->input_buffer, time_now - timespan_useconds);
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

int averager_callback(struct rrr_fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct averager_calculation *calculation = poll_data->private_data;
	struct rrr_message *message = (struct rrr_message *) data;


	RRR_DBG_4("averager callbackgot packet from buffer of size %lu\n", size);

	if (!MSG_IS_MSG_POINT(message)) {
		RRR_DBG_2 ("Averager: Ignoring a message which is not point measurement\n");
		return RRR_FIFO_SEARCH_KEEP;
	}

	calculation->entries++;
	calculation->sum += message->data_numeric;
	if (message->data_numeric >= calculation->max) {
		calculation->max = message->data_numeric;
		calculation->timestamp_max = message->timestamp_from;
	}
	if (message->data_numeric < calculation->min) {
		calculation->min = message->data_numeric;
		calculation->timestamp_min = message->timestamp_from;
	}
	if (message->timestamp_from < calculation->timestamp_from) {
		calculation->timestamp_from = message->timestamp_from;
	}
	if (message->timestamp_to > calculation->timestamp_to) {
		calculation->timestamp_to = message->timestamp_to;
	}

	return RRR_FIFO_SEARCH_KEEP;
}

int averager_spawn_message (
	struct averager_data *data,
	long unsigned int class,
	uint64_t time_from,
	uint64_t time_to,
	uint64_t measurement
) {
	struct rrr_message *message = NULL;

	if (rrr_message_new_empty (
			&message,
			MSG_TYPE_MSG,
			0,
			class,
			time_from,
			time_to,
			measurement,
			0,
			0
	) != 0) {
		RRR_MSG_ERR ("Could not create message in averager_spawn_message\n");
		return 1;
	}

	rrr_fifo_buffer_write_ordered(&data->output_buffer, time_to, (char*) message, sizeof(*message));

	return 0;
}

int averager_calculate_average(struct averager_data *data) {
	struct averager_calculation calculation = {data, 0, ULONG_MAX, 0, 0, UINT64_MAX, 0, 0, 0};
	struct rrr_fifo_callback_args poll_data = {NULL, &calculation, 0};

	int ret = 0;

	rrr_fifo_search(&data->input_buffer, averager_callback, &poll_data, 50);

	if (calculation.entries == 0) {
		RRR_DBG_2 ("Averager: No entries, not averaging\n");
		return ret;
	}

	unsigned long int average = calculation.sum/calculation.entries;
	RRR_DBG_2 ("Average: %lu, Max: %lu, Min: %lu, Entries: %lu\n", average, calculation.max, calculation.min, calculation.entries);

	// Use the maximum timestamp for "to" for all three to make sure they can be written on block device
	// without newer timestamps getting written before older ones.
	ret |= averager_spawn_message(data, MSG_CLASS_AVG, calculation.timestamp_from, calculation.timestamp_to, average);
	ret |= averager_spawn_message(data, MSG_CLASS_MAX, calculation.timestamp_max, calculation.timestamp_to+1, calculation.max);
	ret |= averager_spawn_message(data, MSG_CLASS_MIN, calculation.timestamp_min, calculation.timestamp_to+2, calculation.min);

	if (ret != 0) {
		RRR_MSG_ERR("Error when spawning messages in averager_calculate_average\n");
		return ret;
	}

	return ret;
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct averager_data *data = (struct averager_data *) arg;
	rrr_fifo_buffer_invalidate(&data->input_buffer);
	rrr_fifo_buffer_invalidate(&data->output_buffer);
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
}

int data_init(struct averager_data *data) {
	memset(data, '\0', sizeof(*data));
	int ret = 0;
	ret |= rrr_fifo_buffer_init(&data->input_buffer) << 0;
	ret |= rrr_fifo_buffer_init(&data->output_buffer) << 1;
	if (ret != 0) {
		data_cleanup(data);
	}

	return ret;
}

int parse_config (struct averager_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	rrr_setting_uint timespan = 0;
	rrr_setting_uint interval = 0;
	int preserve_points = 0;
	int discard_unknowns = 0;


	if ((ret = rrr_instance_config_read_unsigned_integer(&timespan, config, "avg_timespan")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Syntax error in avg_timespan for instance %s, must be a number\n", config->name);
			ret = 1;
			goto out;
		}
		timespan = RRR_DEFAULT_AVERAGER_TIMESPAN;
		ret = 0;
	}

	if ((ret = rrr_instance_config_read_unsigned_integer(&interval, config, "avg_interval")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Syntax error in avg_interval for instance %s, must be a number\n", config->name);
			ret = 1;
			goto out;
		}
		interval = RRR_DEFAULT_AVERAGER_INTERVAL;
		ret = 0;
	}

	if ((ret = rrr_instance_config_check_yesno(&preserve_points, config, "avg_preserve_points")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Syntax error in avg_preserve_points for instance %s, specify yes or no\n", config->name);
			ret = 1;
			goto out;
		}
		preserve_points = 0;
		ret = 0;
	}

	if ((ret = rrr_instance_config_check_yesno(&discard_unknowns, config, "avg_discard_unknowns")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Syntax error in avg_discard_unknowns for instance %s, specify yes or no\n", config->name);
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
	if ((init_ret = data_init(data)) != 0) {
		RRR_MSG_ERR("Could not initalize data in averager instance %s flags %i\n",
				INSTANCE_D_NAME(thread_data), init_ret);
		pthread_exit(0);
	}

	struct poll_collection poll;

	RRR_DBG_1 ("Averager thread data is %p\n", thread_data);

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		RRR_MSG_ERR("Could parse configuration in averager instance %s\n",
				INSTANCE_D_NAME(thread_data));
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	RRR_DBG_1 ("Averager: Interval: %u, Timespan: %u, Preserve points: %i\n",
			data->interval, data->timespan, data->preserve_point_measurements);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		RRR_MSG_ERR("Averager requires poll_delete from senders\n");
		goto out_message;
	}

	RRR_DBG_1 ("Averager started thread %p\n", thread_data);

	uint64_t previous_average_time = rrr_time_get_64();
	uint64_t average_interval_useconds = data->interval * 1000000;

	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_update_watchdog_time(thread_data->thread);

		averager_maintain_buffer(data);

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		uint64_t current_time = rrr_time_get_64();
		if (previous_average_time + average_interval_useconds < current_time) {
			if (averager_calculate_average(data) != 0) {
				goto out_message;
			}
			previous_average_time = current_time;
		}
	}

	out_message:

	RRR_DBG_1 ("Thread averager %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct averager_data data;
	data_init(&data);
	int ret = parse_config(&data, config);
	data_cleanup(&data);
	return ret;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_averager,
		NULL,
		averager_poll,
		NULL,
		averager_poll_delete,
		NULL,
		test_config,
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

