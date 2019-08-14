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
#include <inttypes.h>

#include "../blockdevlogger/src/include/bdl.h"
#include "../lib/poll_helper.h"
#include "../lib/settings.h"
#include "../lib/instance_config.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../global.h"

// Should not be smaller than module max
#define VL_BLOCKDEV_MAX_SENDERS VL_MODULE_MAX_SENDERS

// Tag entries when new and when saved externally
#define VL_BLOCKDEV_TAG_NEW		(1<<0)
#define VL_BLOCKDEV_TAG_SAVED	(1<<1)

struct blockdev_data {
	char *device_path;
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
	struct bdl_session device_session;
	int do_bdl_reset;
	int always_tag_saved;
};

int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct blockdev_data *blockdev_data = data->private_data;
	return fifo_read_clear_forward(&blockdev_data->output_buffer, NULL, callback, poll_data, wait_milliseconds);
}

void data_cleanup (void *arg) {
	struct blockdev_data *blockdev_data = arg;
	fifo_buffer_invalidate(&blockdev_data->input_buffer);
	fifo_buffer_invalidate(&blockdev_data->output_buffer);

	if (blockdev_data->device_path != NULL) {
		free(blockdev_data->device_path);
	}

	while (blockdev_data->device_session.usercount > 0) {
		bdl_close_session(&blockdev_data->device_session);
	}
}

int data_init (struct blockdev_data *data) {
	memset(data, '\0', sizeof(*data));

	int ret = 0;
	ret |= fifo_buffer_init(&data->input_buffer);
	ret |= fifo_buffer_init(&data->output_buffer);
	if (ret != 0) {
		data_cleanup(data);
	}
	return ret;
}

int parse_config (struct blockdev_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	memset(data, '\0', sizeof(*data));

	char *device_path = NULL;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&device_path, config, "device_path")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			VL_MSG_ERR("Error while parsing device_path settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->device_path = device_path;

	if (data->device_path == NULL) {
		VL_MSG_ERR ("blockdev instance %s: Device must be specified (device_path=DEVICE)\n", config->name);
		return 1;
	}

	int yesno = 0;
	if ((ret = rrr_instance_config_check_yesno (&yesno, config, "blockdev_always_tag")) != 0) {
		if (ret == RRR_SETTING_NOT_FOUND) {
			yesno = 0;
		}
		else {
			VL_MSG_ERR("Error while parsing blockdev_always_tag settings of instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	data->always_tag_saved = yesno;

	/* On error, memory is freed by data_cleanup */

	out:
	return ret;
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct instance_thread_data *thread_data = poll_data->source;
	struct blockdev_data *blockdev_data = thread_data->private_data;

	struct vl_message *reading = (struct vl_message *) data;
	VL_DEBUG_MSG_3 ("blockdev: Result from buffer: %s timestamp to %" PRIu64 " size %lu\n", reading->data, reading->timestamp_to, size);

	fifo_buffer_write_ordered(&blockdev_data->input_buffer, reading->timestamp_to, data, size);

	return 0;
}

struct update_test_data {
	struct vl_message *message;
};

struct bdl_update_info update_test(void *arg, struct bdl_update_callback_data *update_data) {
	struct update_test_data *update_test_data = arg;
	struct bdl_update_info update_info;
	memset(&update_info, '\0', sizeof(update_info));

	const struct vl_message *message = (const struct vl_message *) update_data->data;

	if (VL_DEBUGLEVEL_3) {
		VL_DEBUG_MSG ("blockdev update_test: Application data: %" PRIu64 "\n", update_data->application_data);
		VL_DEBUG_MSG ("blockdev update_test: Timestamp from: %" PRIu64 " vs %" PRIu64 " vs %" PRIu64 "\n",
				update_data->timestamp, update_test_data->message->timestamp_from, message->timestamp_from);
		VL_DEBUG_MSG ("blockdev update_test: Timestamp to: %" PRIu64 " vs %" PRIu64 " vs %" PRIu64 "\n",
				update_data->timestamp, update_test_data->message->timestamp_to, message->timestamp_to);
		VL_DEBUG_MSG ("blockdev update_test: Class: %" PRIu32 " vs %" PRIu32 "\n",
				update_test_data->message->class, message->class);
		VL_DEBUG_MSG ("blockdev update_test: Data length: %" PRIu64 " vs %" PRIu32 " vs %" PRIu32 "\n",
				update_data->data_length, update_test_data->message->length, message->length);

		for (unsigned int j = 0; j < update_test_data->message->length; j++) {
			VL_DEBUG_MSG ("%02x-", update_test_data->message->data[j]);
		}
		VL_DEBUG_MSG ("\n");
		for (unsigned int j = 0; j < message->length; j++) {
			VL_DEBUG_MSG ("%02x-", message->data[j]);
		}
		VL_DEBUG_MSG ("\n");
	}
	if (
			(update_data->application_data & VL_BLOCKDEV_TAG_SAVED) == 1 ||
			message->timestamp_from != update_test_data->message->timestamp_from ||
			message->timestamp_to != update_test_data->message->timestamp_to ||
			message->length != update_test_data->message->length ||
			message->class != update_test_data->message->class ||
			memcmp(message->data, update_test_data->message->data, message->length) != 0
	) {
		update_info.do_update = 0;
		update_info.do_break = 0;
		goto out;
	}

	VL_DEBUG_MSG_2 ("blockdev: Updating appdata for entry with timestamp %" PRIu64 "\n", update_test_data->message->timestamp_to);

	update_info.do_update = 1;
	update_info.do_break = 1;
	update_info.new_appdata |= VL_BLOCKDEV_TAG_SAVED;

	out:
	return update_info;
}

int write_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct blockdev_data *blockdev_data = poll_data->private_data;
	struct vl_message *message = (struct vl_message *) data;

	int err;

	if (message->type == MSG_TYPE_TAG) {
		// TODO : Maybe store some ACKs first in a buffer and run the update only once
		struct update_test_data update_test_data;
		update_test_data.message = message;

		int result;

		// Match only NEW entries
		err = bdl_read_update_application_data (
			&blockdev_data->device_session,
			message->timestamp_to,
			VL_BLOCKDEV_TAG_NEW,
			update_test, &update_test_data,
			&result
		);

		if (result > 1) {
			VL_MSG_ERR ("blockdev: Bug: Updated more than 1 entry\n");
			pthread_exit(0);
		}
	}
	else {
		err = bdl_write_block (
			&blockdev_data->device_session,
			data, size,
			(blockdev_data->always_tag_saved == 1 ? VL_BLOCKDEV_TAG_SAVED : VL_BLOCKDEV_TAG_NEW), message->timestamp_to, 10
		);
	}

	if (err == BDL_WRITE_ERR_TIMESTAMP) {
		VL_MSG_ERR ("blockdev: Some entry with a higher timestamp has been written, discard this entry.\n");
		free(data);
		return FIFO_SEARCH_GIVE;
	}
	else if (err == BDL_WRITE_ERR_SIZE) {
		VL_MSG_ERR ("blockdev: Blocks on the device are not big enough to fit our data.\n");
		blockdev_data->do_bdl_reset = 1;
		return FIFO_CALLBACK_ERR;
	}
	else if (err != 0) {
		VL_MSG_ERR ("blockdev: Could not write data to device (error %i), leaving it in the buffer\n", err);
		blockdev_data->do_bdl_reset = 1;
		return FIFO_CALLBACK_ERR;
	}

	VL_DEBUG_MSG_3 ("blockdev: Data was written to device successfully\n");

	free(data);
	return FIFO_SEARCH_GIVE;
}

int write_to_device(struct blockdev_data *data) {
	struct fifo_callback_args poll_data = {NULL, data, 0};
	fifo_search(&data->input_buffer, write_callback, &poll_data, 50);

	return 0;
}

struct get_new_entries_data {
	struct blockdev_data *blockdev_data;
	int entries_counter;
};

struct bdl_update_info get_new_entries_callback(void *arg, struct bdl_update_callback_data *update_callback_data) {
	struct get_new_entries_data *callback_data = arg;
	struct blockdev_data *blockdev_data = callback_data->blockdev_data;

	uint64_t data_length = update_callback_data->data_length;
	const char *data = update_callback_data->data;

	struct bdl_update_info ret;
	if (data_length != sizeof(struct vl_message)) {
		VL_MSG_ERR ("blockdev: Warning: Entry size in entry from device did not match expected length (%" PRIu64 ") vs (%lu). Tagging it as saved.",
			data_length, sizeof(struct vl_message)
		);

		ret.do_update = 1;
		ret.new_appdata = VL_BLOCKDEV_TAG_SAVED;

		goto out;
	}

	struct vl_message *message = malloc(sizeof(*message));
	memcpy(message, data, sizeof(*message));
	fifo_buffer_write(&blockdev_data->output_buffer, (char*)message, sizeof(*message));

	callback_data->entries_counter++;
	ret.do_update = 0;
	ret.new_appdata = 0;

	out:
	return ret;
}


int get_new_entries(struct instance_thread_data *thread_data) {
	struct blockdev_data *blockdev_data = thread_data->private_data;

	struct get_new_entries_data callback_data;
	callback_data.blockdev_data = blockdev_data;
	callback_data.entries_counter = 0;

	// TODO : Possibly have a minimum time for this search
	// Match only NEW entries
	int result;
	int err = bdl_read_update_application_data (
		&blockdev_data->device_session,
		0, VL_BLOCKDEV_TAG_NEW,
		get_new_entries_callback, &callback_data,
		&result
	);

	if (err) {
		VL_MSG_ERR("Warning: Error return from blockdev while reading entries\n");
	}
	else {
		VL_DEBUG_MSG_1 ("blockdev: Read %i entries with NEW state from device\n", callback_data.entries_counter);
	}

	return err;
}

static void *thread_entry_blockdev (struct vl_thread *thread) {
	struct instance_thread_data *thread_data = thread->private_data;
	struct blockdev_data *data = thread_data->private_data = thread_data->private_memory;
	struct poll_collection poll;

	if (data_init(data) != 0) {
		VL_MSG_ERR("Could not initalize data in blockdev instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	poll_collection_init(&poll);
	pthread_cleanup_push(poll_collection_clear_void, &poll);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, thread);

	thread_set_state(thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);

	VL_DEBUG_MSG_1 ("blockdev thread data is %p\n", thread_data);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		VL_MSG_ERR("Configuration parsing failed for blockdev instance '%s'\n", thread_data->init_data.module->instance_name);
		goto out_message;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (poll_add_from_thread_senders_and_count(&poll, thread_data, RRR_POLL_POLL_DELETE) != 0) {
		VL_MSG_ERR("Blockdev requires poll_delete from senders\n");
		goto out_message;
	}

	VL_DEBUG_MSG_1 ("blockdev started thread %p\n", thread_data);

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		VL_DEBUG_MSG_5 ("blockdev polling\n");

		int err = 0;

		if (poll_do_poll_delete_simple (&poll, thread_data, poll_callback, 50) != 0) {
			break;
		}

		if (data->do_bdl_reset == 1) {
			VL_DEBUG_MSG_2 ("blockdev close session\n");
			while (data->device_session.usercount > 0) {
				bdl_close_session(&data->device_session);
			}
			data->do_bdl_reset = 0;
		}

		if (data->device_session.usercount == 0) {
			VL_DEBUG_MSG_2 ("blockdev start session\n");
			if (bdl_start_session(&data->device_session, data->device_path, 1) != 0) { // 1 == no memorymapping
				VL_MSG_ERR ("blockdev: Could not open block device %s\n", data->device_path);
				continue;
			}

			// Get entries from device which are not tagged as saved in remote database
			VL_DEBUG_MSG_1 ("blockdev: Reading NEW entries from device\n");
			get_new_entries(thread_data);
		}

		VL_DEBUG_MSG_5 ("blockdev write\n");
		write_to_device(data);

		if (err != 0) {
			break;
		}
	}

	out_message:
	VL_DEBUG_MSG_1 ("Thread blockdev %p exiting\n", thread_data->thread);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct blockdev_data data;
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
		thread_entry_blockdev,
		NULL,
		NULL,
		NULL,
		poll_delete,
		NULL,
		test_config,
		NULL,
		NULL
};

static const char *module_name = "blockdev";

__attribute__((constructor)) void load(void) {
}

void init(struct instance_dynamic_data *data) {
	data->private_data = NULL;
	data->module_name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(void) {
	VL_DEBUG_MSG_1 ("Destroy blockdev module\n");
}

