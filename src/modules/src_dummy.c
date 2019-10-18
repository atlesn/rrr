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

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>

#include "../lib/instance_config.h"
#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/ip.h"
#include "../global.h"

struct dummy_data {
	struct fifo_buffer buffer;
	int no_generation;
	int no_sleeping;
};

static int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct dummy_data *dummy_data = data->private_data;
	return fifo_read_clear_forward(&dummy_data->buffer, NULL, callback, poll_data, wait_milliseconds);
}

static int poll (RRR_MODULE_POLL_SIGNATURE) {
	struct dummy_data *dummy_data = data->private_data;
	return fifo_search(&dummy_data->buffer, callback, poll_data, wait_milliseconds);
}

static int inject (RRR_MODULE_INJECT_SIGNATURE) {
	struct dummy_data *data = thread_data->private_data;
	VL_DEBUG_MSG_2("dummy: writing data from inject function\n");

	fifo_buffer_write(&data->buffer, message->message, message->data_length);
	message->message = NULL;

	ip_buffer_entry_destroy(message);

	return 0;
}

int data_init(struct dummy_data *data) {
	memset(data, '\0', sizeof(*data));
	int ret = fifo_buffer_init(&data->buffer);
	return ret;
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct dummy_data *data = (struct dummy_data *) arg;
	fifo_buffer_invalidate(&data->buffer);
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
}

int parse_config (struct dummy_data *data, struct rrr_instance_config *config) {
	int ret = 0;
	int yesno = 0;

	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "dummy_no_generation")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 1; // Default to yes
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing dummy_no_generation setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->no_generation = yesno;

	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "dummy_no_sleeping")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 0; // Default to no
			ret = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing dummy_no_sleeping setting of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->no_sleeping = yesno;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void *thread_entry_dummy (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct dummy_data *data = thread_data->private_data = thread_data->private_memory;

	if (data_init(data) != 0) {
		VL_MSG_ERR("Could not initalize data in dummy instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	VL_DEBUG_MSG_1 ("Dummy thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parse failed for instance %s\n", INSTANCE_D_NAME(thread_data));
		goto out_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	// If we are not sleeping we need to enable automatic rate limiting on our output buffer
	if (data->no_sleeping == 1) {
		VL_DEBUG_MSG_1("dummy instance %s enabling rate limit on output buffer\n", INSTANCE_D_NAME(thread_data));
		fifo_buffer_set_do_ratelimit(&data->buffer, 1);
	}

	uint64_t time_start = time_get_64();
	int generated_count = 0;
	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		if (data->no_generation == 0) {
			uint64_t time = time_get_64();

			struct vl_message *reading = message_new_reading(time, time);

			VL_DEBUG_MSG_3("dummy: writing data measurement %" PRIu64 "\n", reading->data_numeric);
			fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading));
			generated_count++;
		}

		uint64_t time_now = time_get_64();

		if (time_now - time_start > 1000000) {
			VL_DEBUG_MSG_1("dummy instance %s messages per second %i\n",
					INSTANCE_D_NAME(thread_data), generated_count);
			generated_count = 0;
			time_start = time_now;
		}
		if (data->no_sleeping == 0) {
			usleep (50000); // 50 ms
		}

	}

	out_cleanup:
	VL_DEBUG_MSG_1 ("Thready dummy instance %s exiting\n", INSTANCE_D_MODULE_NAME(thread_data));
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct dummy_data data;
	int ret = 0;
	if ((ret = data_init(&data)) != 0) {
		goto err;
	}
	ret = parse_config(&data, config);
	data_cleanup(&data);
	err:
	return ret;
}

static struct module_operations module_operations = {
	NULL,
	thread_entry_dummy,
	NULL,
	poll,
	NULL,
	poll_delete,
	NULL,
	test_config,
	inject,
	NULL
};

static const char *module_name = "dummy";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
		data->module_name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(void) {
}


