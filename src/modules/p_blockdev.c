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
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <bdl/bdl.h>

#include "../modules.h"
#include "../lib/messages.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/cmdlineparser/cmdline.h"

// Should not be smaller than module max
#define VL_BLOCKDEV_MAX_SENDERS VL_MODULE_MAX_SENDERS

// Tag entries when new and when saved externally
#define VL_BLOCKDEV_TAG_NEW		(1<<0)
#define VL_BLOCKDEV_TAG_SAVED	(1<<1)

struct blockdev_data {
	const char *device_path;
	struct fifo_buffer input_buffer;
	struct fifo_buffer output_buffer;
	struct bdl_session device_session;
	int do_bdl_reset;
};

int poll_delete (
	struct module_thread_data *data,
	int (*callback)(struct fifo_callback_args *caller_data, char *data, unsigned long int size),
	struct fifo_callback_args *poll_data
) {
	struct blockdev_data *blockdev_data = data->private_data;
	return fifo_read_clear_forward(&blockdev_data->output_buffer, NULL, callback, poll_data);
}


int data_init_parse_cmd (struct blockdev_data *data, struct cmd_data *cmd) {
	memset(data, '\0', sizeof(*data));

	const char *device_path = cmd_get_value(cmd, "device_path", 0);

	data->device_path = device_path;

	if (data->device_path == NULL) {
		fprintf (stderr, "blockdev: Device must be specified (device_path=DEVICE)\n");
		return 1;
	}

	fifo_buffer_init(&data->input_buffer);
	fifo_buffer_init(&data->output_buffer);

	return 0;
}

void data_cleanup (void *arg) {
	struct blockdev_data *blockdev_data = arg;
	fifo_buffer_invalidate(&blockdev_data->input_buffer);
	fifo_buffer_invalidate(&blockdev_data->output_buffer);

	while (blockdev_data->device_session.usercount > 0) {
		bdl_close_session(&blockdev_data->device_session);
	}
}

int poll_callback(struct fifo_callback_args *poll_data, char *data, unsigned long int size) {
	struct module_thread_data *thread_data = poll_data->source;
	struct blockdev_data *blockdev_data = thread_data->private_data;

	struct vl_message *reading = (struct vl_message *) data;
	printf ("blockdev: Result from buffer: %s timestamp to %" PRIu64 " size %lu\n", reading->data, reading->timestamp_to, size);

	fifo_buffer_write_ordered(&blockdev_data->input_buffer, reading->timestamp_to, data, size);

	return 0;
}

struct update_test_data {
	struct vl_message *message;
};

struct bdl_update_info update_test(void *arg, uint64_t timestamp, uint64_t application_data, uint64_t data_length, const char *data) {
	struct update_test_data *update_test_data = arg;
	struct bdl_update_info update_info;
	memset(&update_info, '\0', sizeof(update_info));

	const struct vl_message *message = (const struct vl_message *) data;

	printf ("blockdev update_test: Application data: %" PRIu64 "\n", application_data);

	printf ("blockdev update_test: Timestamp from: %" PRIu64 " vs %" PRIu64 " vs %" PRIu64 "\n",
			timestamp, update_test_data->message->timestamp_from, message->timestamp_from);

	printf ("blockdev update_test: Timestamp to: %" PRIu64 " vs %" PRIu64 " vs %" PRIu64 "\n",
			timestamp, update_test_data->message->timestamp_to, message->timestamp_to);

	printf ("blockdev update_test: Class: %" PRIu32 " vs %" PRIu32 "\n",
			update_test_data->message->class, message->class);

	printf ("blockdev update_test: Data length: %" PRIu64 " vs %" PRIu32 " vs %" PRIu32 "\n",
			data_length, update_test_data->message->length, message->length);

	for (int j = 0; j < update_test_data->message->length; j++) {
		printf ("%02x-", update_test_data->message->data[j]);
	}
	printf ("\n");
	for (int j = 0; j < message->length; j++) {
		printf ("%02x-", message->data[j]);
	}
	printf ("\n");

	if (
			(application_data & VL_BLOCKDEV_TAG_SAVED) == 1 ||
			message->timestamp_from != update_test_data->message->timestamp_from ||
			message->timestamp_to != update_test_data->message->timestamp_to ||
			message->length != update_test_data->message->length ||
			message->class != update_test_data->message->class ||
			memcmp(message->data, update_test_data->message->data, message->length) != 0
	) {
		// TODO : escape from loop when entry found
		update_info.do_update = 0;
		goto out;
	}

	printf ("blockdev: Updating appdata for entry\n");

	update_info.do_update = 1;
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

		printf ("blockdev: Result from bld_update_application_data: %i\n", result);

		if (result > 1) {
			fprintf (stderr, "blockdev: Error: Updated more than 1 entry\n");
			pthread_exit(0);
		}
	}
	else {
		err = bdl_write_block (
			&blockdev_data->device_session,
			data, size,
			VL_BLOCKDEV_TAG_NEW, message->timestamp_to, 10
		);
	}

	if (err == BDL_WRITE_ERR_TIMESTAMP) {
		printf ("blockdev: Some entry with a higher timestamp has been written, discard this entry.\n");
		free(data);
		return FIFO_SEARCH_GIVE;
	}
	else if (err == BDL_WRITE_ERR_SIZE) {
		printf ("blockdev: Blocks on the device are not big enough to fit our data.\n");
		blockdev_data->do_bdl_reset = 1;
		return FIFO_SEARCH_ERR;
	}
	else if (err != 0) {
		fprintf (stderr, "blockdev: Could not write data to device (error %i), leaving it in the buffer\n", err);
		blockdev_data->do_bdl_reset = 1;
		return FIFO_SEARCH_ERR;
	}

	printf ("blockdev: Data was written to device successfully\n");

	free(data);
	return FIFO_SEARCH_GIVE;
}

int write_to_device(struct blockdev_data *data) {
	struct fifo_callback_args poll_data = {NULL, data};
	fifo_search(&data->input_buffer, write_callback, &poll_data);

	return 0;
}

struct get_new_entries_data {
	struct blockdev_data *blockdev_data;
	int entries_counter;
};

struct bdl_update_info get_new_entries_callback(void *arg, uint64_t timestamp, uint64_t application_data, uint64_t data_length, const char *data) {
	struct get_new_entries_data *callback_data = arg;
	struct blockdev_data *blockdev_data = callback_data->blockdev_data;

	struct bdl_update_info ret;
	if (data_length != sizeof(struct vl_message)) {
		fprintf (stderr,
			"blockdev: Warning: Entry size in entry from device did not match expected length (%" PRIu64 ") vs (%lu). Tagging it as saved.",
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


int get_new_entries(struct module_thread_data *thread_data) {
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

	printf ("blockdev: Read %i entries with NEW state from device\n", callback_data.entries_counter);

	return 0;
}

static void *thread_entry_blockdev(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	unsigned long int senders_count = thread_data->senders_count;
	struct blockdev_data *data = (struct blockdev_data *) thread_data->private_memory;
	thread_data->private_data = data;

	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);

	if (data_init_parse_cmd(data, start_data->cmd) != 0) {
		pthread_exit(0);
	}

	thread_set_state(start_data->thread, VL_THREAD_STATE_INITIALIZED);
	thread_signal_wait(thread_data->thread, VL_THREAD_SIGNAL_START);
	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	printf ("blockdev thread data is %p\n", thread_data);


	if (senders_count > VL_BLOCKDEV_MAX_SENDERS) {
		fprintf (stderr, "Too many senders for blockdev module, max is %i\n", VL_BLOCKDEV_MAX_SENDERS);
		goto out_message;
	}

	int (*poll[VL_BLOCKDEV_MAX_SENDERS])(
			struct module_thread_data *data,
			int (*callback)(
					struct fifo_callback_args *poll_data,
					char *data,
					unsigned long int size
			),
			struct fifo_callback_args *caller_data
	);


	for (int i = 0; i < senders_count; i++) {
		printf ("blockdev: found sender %p\n", thread_data->senders[i]);
		poll[i] = thread_data->senders[i]->module->operations.poll_delete;

		if (poll[i] == NULL) {
			fprintf (stderr, "blockdev cannot use this sender, lacking poll delete function.\n");
			goto out_message;
		}
	}

	printf ("blockdev started thread %p\n", thread_data);

	if (senders_count == 0) {
		fprintf (stderr, "Error: Sender was not set for blockdev processor module\n");
		goto out_message;
	}

	while (thread_check_encourage_stop(thread_data->thread) != 1) {
		update_watchdog_time(thread_data->thread);

		int err = 0;

		for (int i = 0; i < senders_count; i++) {
			struct fifo_callback_args poll_data = {thread_data, NULL};
			int res = poll[i](thread_data->senders[i], poll_callback, &poll_data);
			if (!(res >= 0)) {
				printf ("blockdev module received error from poll function\n");
				err = 1;
				break;
			}
		}

		if (data->do_bdl_reset == 1) {
			while (data->device_session.usercount > 0) {
				bdl_close_session(&data->device_session);
			}
			data->do_bdl_reset = 0;
		}

		if (data->device_session.usercount == 0) {
			if (bdl_start_session(&data->device_session, data->device_path) != 0) {
				fprintf (stderr, "blockdev: Could not open block device %s\n", data->device_path);
				goto sleep;
			}

			// Get entries from device which are not tagged as saved in remote database
			printf ("blockdev: Reading NEW entries from device\n");
			get_new_entries(thread_data);
		}

		write_to_device(data);

		if (err != 0) {
			break;
		}

		sleep:
		usleep (100000); // 100 ms
	}

	out_message:
	printf ("Thread blockdev %p exiting\n", thread_data->thread);

	out:
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_blockdev,
		NULL,
		NULL,
		poll_delete
};

static const char *module_name = "blockdev";

__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
	data->private_data = NULL;
	data->name = module_name;
	data->type = VL_MODULE_TYPE_PROCESSOR;
	data->operations = module_operations;
	data->dl_ptr = NULL;
}

void unload(struct module_dynamic_data *data) {
	printf ("Destroy blockdev module\n");
}

