/*

Voltage Logger

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
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>

#include "../lib/instance_config.h"
#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../global.h"

struct dummy_data {
	struct fifo_buffer buffer;
	int no_generation;
};

static int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct dummy_data *dummy_data = data->private_data;
	return fifo_read_clear_forward(&dummy_data->buffer, NULL, callback, poll_data);
}

static int poll (RRR_MODULE_POLL_SIGNATURE) {
	struct dummy_data *dummy_data = data->private_data;
	return fifo_search(&dummy_data->buffer, callback, poll_data);
}

static int inject (RRR_MODULE_INCJECT_SIGNATURE) {
	struct dummy_data *data = thread_data->private_data;
	VL_DEBUG_MSG_2("dummy: writing data from inject function\n");
	fifo_buffer_write(&data->buffer, (char*)message, sizeof(*message));
	return 0;
}

void data_init(struct dummy_data *data) {
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->buffer);
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

	memset(data, '\0', sizeof(*data));

	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "dummy_no_generation")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing blockdev_always_tag settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->no_generation = yesno;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

static void *thread_entry_dummy(struct vl_thread_start_data *start_data) {
	struct instance_thread_data *thread_data = start_data->private_arg;
	struct dummy_data *data = thread_data->private_data = thread_data->private_memory;

	thread_data->thread = start_data->thread;

	data_init(data);

	VL_DEBUG_MSG_1 ("Dummy thread data is %p\n", thread_data);

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	static const char *dummy_msg = "Dummy measurement of time";

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		if (data->no_generation == 0) {
			uint64_t time = time_get_64();

			struct vl_message *reading = message_new_reading(time, time);

			VL_DEBUG_MSG_2("dummy: writing data\n");
			fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading));
		}

		usleep (750000); // 750 ms

	}

	VL_DEBUG_MSG_1 ("Dummy received encourage stop\n");

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	return 0;
}

static struct module_operations module_operations = {
	thread_entry_dummy,
	poll,
	NULL,
	poll_delete,
	NULL,
	test_config,
	inject
};

static const char *module_name = "dummy";

__attribute__((constructor)) void load() {
}

void init(struct instance_dynamic_data *data) {
		data->module_name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload() {
}


