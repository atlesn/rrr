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

- -------------------------------------------------------------------
- -- Original software for USB-device:
- -------------------------------------------------------------------

voltage monitor and plotter for single channel USBVoltmeter from
   http://digital-measure.com

This is the actual code which pulls the numbers out of the voltmeter. It is
   based on code provided by digital-measure.com

Modified to fit 2-channel device with unitversion == 5 && subtype == 7. 
   Atle Solbakken atle@goliathdns.no

- -------------------------------------------------------------------

*/

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <usb.h>

#include "../lib/instance_config.h"
#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../lib/instances.h"
#include "../lib/messages.h"
#include "../lib/array.h"
#include "../lib/ip.h"
#include "../lib/ip_buffer_entry.h"
#include "../lib/array.h"
#include "../global.h"

struct voltmonitor_data {
	struct rrr_instance_thread_data *thread_data;

	struct rrr_fifo_buffer buffer;
	usb_dev_handle *usb_handle;
	struct usb_device *usb_device;

	float usb_calibration;
	int usb_channel;

	char *msg_topic;

	pthread_mutex_t cleanup_lock;
};


static void usb_cleanup(void *arg) {
	struct voltmonitor_data *data = (struct voltmonitor_data *) arg;

	if (data->usb_handle != NULL) {
		usb_close(data->usb_handle);
		data->usb_handle = NULL;
	}
	if (data->usb_device != NULL) {
		data->usb_device = NULL;
	}
	/*if (data->usb_first_bus != NULL) {
		struct usb_bus *next_bus = NULL;
		struct usb_bus *bus = data->usb_first_bus;
		for ( bus = data->usb_first_bus ; bus ; bus = next_bus ) {
			struct usb_device *dev;
			next_bus = bus->next;

			struct usb_device *next_device = NULL;
			for ( dev = bus->devices ; dev ; dev = next_device ) {
				next_device = dev->next;
				usb_free_dev(dev);
			}

			usb_free_bus(bus);
		}
		data->usb_first_bus = NULL;
	}*/

	return;
}

static int usb_connect(struct voltmonitor_data *data) {
	struct usb_device *founddev = NULL;

	usb_find_busses();
	usb_find_devices();

	struct usb_bus *next_bus = NULL;
	struct usb_bus *bus = usb_get_busses();

	for ( ; bus ; bus = next_bus ) {
		struct usb_device *dev;
		next_bus = bus->next;

		struct usb_device *next_device = NULL;
		for ( dev = bus->devices ; dev ; dev = next_device ) {
			next_device = dev->next;
			if (founddev == NULL && dev->descriptor.idVendor == 0x04d8 && dev->descriptor.idProduct == 0xfc39 ) {
				founddev = dev;
			}
		}
	}

	if ( ! founddev ) {
		RRR_MSG_ERR ("voltmonitor: USB dev not found\n");
		goto err_out;
	}

	usb_dev_handle *h = usb_open ( founddev );

	if ( ! h ) {
		RRR_MSG_ERR ("voltmonitor: USB open failed\n");
		goto err_out;
	}

	char drivername[64] ;
	if ( usb_get_driver_np ( h, 0, drivername, sizeof(drivername) ) == 0 ) {
		RRR_DBG_2 ( "voltage monitor usb device driver: %s\n", drivername );
		
		if ( drivername[0] != 0 ) {
			RRR_DBG_2 ( "voltagemonitor releasing driver\n" );
			
			if ( usb_detach_kernel_driver_np ( h, 0 ) ) {
				RRR_MSG_ERR ("voltmonitor: release kernel USB driver failed\n");
				goto err_close_device;
			}
		}
	}

	if ( usb_claim_interface ( h, 0 ) ) {
		RRR_MSG_ERR ("voltmonitor: USB claim failed\n");
		goto err_close_device;
	}

	// write report to get device info
	char outbuf[64];
	memset(outbuf, '\0', 64);
	outbuf[0] = 0xff;
	outbuf[1] = 0x37;
	if ( usb_interrupt_write ( h, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
		RRR_MSG_ERR ("voltmonitor: USB write failed\n");
		goto err_close_device;
	}

	// read device info report
	char inbuf[64];
	memset(inbuf, '\0', 64);
	if ( usb_interrupt_read ( h, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
		RRR_MSG_ERR ("voltmonitor: USB read failed\n");
		goto err_close_device;
	}

	int subtype = inbuf[6];
	int unitversion = inbuf[5];

	RRR_DBG_2 ( "voltagemonitor device subtype: %d\n", subtype );
	RRR_DBG_2 ( "voltagemonitor unitversion: %d\n", unitversion );
	
	if ( unitversion != 5 || subtype != 7 ) {
		RRR_MSG_ERR ("voltmonitor: Unknown USB voltmeter version\n");
		goto err_close_device;
	}

	data->usb_handle = h;
	data->usb_device = founddev;

	return 0;

	err_close_device:
	usb_close(h);

	err_out:

	return 1;
}

static int usb_read_voltage(struct voltmonitor_data *data, int *millivolts) {
	if (data->usb_channel > 2 || data->usb_channel < 1) {
		RRR_MSG_ERR ("voltmonitor: Channel must be 1 or 2, got %i\n", data->usb_channel);
		exit(EXIT_FAILURE);
	}

	RRR_DBG_2 ("Read voltage channel %i calibration %f\n", data->usb_channel, data->usb_calibration);

	unsigned int channel = data->usb_channel - 1;

	if (data->usb_handle == NULL) {
		if (usb_connect(data) != 0) {
			RRR_MSG_ERR ("voltmonitor: USB-device connect failed\n");
		}
		if (data->usb_handle == NULL) {
			RRR_MSG_ERR ("voltmonitor: USB-device not ready\n");
			goto err_out;
		}
	}

	// trigger measurement
	char outbuf[64];
	memset ( outbuf, 255, 64 );
	outbuf[0] = 0x37;
		if ( usb_interrupt_write ( data->usb_handle, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
			RRR_MSG_ERR ("voltmonitor: USB write failed\n");
			goto err_close_device;
		}

	char inbuf[64];
	memset ( inbuf, 255, 64 );
		if ( usb_interrupt_read ( data->usb_handle, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
			RRR_MSG_ERR ( "voltagemonitor read failed\n" );
			RRR_MSG_ERR ("voltmonitor: USB read failed\n");
			goto err_close_device;
		}

		if ( inbuf[0] != 0x37 ) {
			RRR_MSG_ERR ("voltmonitor: USB parse failed, 0x37 not found\n");
			goto err_close_device;
		}

	if (RRR_DEBUGLEVEL_3) {
		for (int j = 0; j < 64; j++) {
			RRR_DBG ("%02x ", inbuf[j]);
		}
		RRR_DBG ("\n");
	}

	unsigned int channel_add = (channel == 0 ? 0 : 4);

	unsigned char negative_1 = ( inbuf[1 + channel_add] & 0x20 ) ? 0 : 1;

	unsigned char tmp_1;

	// inbuf1 inbuf2 inbuf3     tmp

	tmp_1 = inbuf[2 + channel_add];
	inbuf[1 + channel_add] <<= 3;
	tmp_1 >>= 5;
	inbuf[1 + channel_add] += tmp_1;
	inbuf[2 + channel_add] <<= 3;
	inbuf[3 + channel_add] >>= 5;
	inbuf[2 + channel_add]  += inbuf[3 + channel_add];

	float value_1 = ( (unsigned int) inbuf[1 + channel_add] << 8 )  + inbuf[2 + channel_add];
		if ( negative_1 ) {
			value_1 -= 65535;
		}

	value_1 = value_1 * 400 / 65535.0 * data->usb_calibration;

	*millivolts = value_1 * 1000;

	RRR_DBG_2 ("voltmonitor reading: %04f - %d\n", value_1, *millivolts);

	return 0;

	err_close_device:

	usb_close(data->usb_handle);
	data->usb_handle = NULL;
	data->usb_device = NULL;

	err_out:

	return 1;
}

static int poll_delete (RRR_MODULE_POLL_SIGNATURE) {
	struct voltmonitor_data *voltmonitor_data = data->private_data;
	return  rrr_fifo_buffer_read_clear_forward(&voltmonitor_data->buffer, NULL, callback, poll_data, wait_milliseconds);
}

static int poll (RRR_MODULE_POLL_SIGNATURE) {
	struct voltmonitor_data *voltmonitor_data = data->private_data;
	return rrr_fifo_buffer_search(&voltmonitor_data->buffer, callback, poll_data, wait_milliseconds);
}

int data_init(struct voltmonitor_data *data, struct rrr_instance_thread_data *thread_data) {
	data->thread_data = thread_data;
	memset(data, '\0', sizeof(*data));
	return rrr_fifo_buffer_init(&data->buffer);
}

void data_cleanup(void *arg) {
	struct voltmonitor_data *data = (struct voltmonitor_data *) arg;
	rrr_fifo_buffer_clear(&data->buffer);
	RRR_FREE_IF_NOT_NULL(data->msg_topic);
}

int convert_float(const char *value, float *result) {
	char *err;
	*result = strtof(value, &err);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int convert_integer_10(const char *value, int *result) {
	char *err;
	*result = strtol(value, &err, 10);

	if (err[0] != '\0') {
		return 1;
	}

	return 0;
}

int parse_config(struct voltmonitor_data *data, struct rrr_instance_config *config) {
	int ret = 0;

	char *vm_calibration = NULL;
	char *vm_channel = NULL;

	if ((ret = rrr_instance_config_get_string_noconvert_silent(&data->msg_topic, config, "vm_message_topic")) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_ERR("Syntax error in vm_message_topic for instance %s\n", config->name);
			ret = 1;
			goto out;
		}
	}

	rrr_instance_config_get_string_noconvert_silent (&vm_calibration, config, "vm_calibration");
	rrr_instance_config_get_string_noconvert_silent (&vm_channel, config, "vm_channel");

	float calibration = 1.124;
	int channel = 1;

	if (vm_calibration != NULL) {
		if (convert_float(vm_calibration, &calibration) != 0) {
			RRR_MSG_ERR ("Syntax error in vm_calibration parameter, could not understand the number '%s'\n", vm_calibration);
			ret = 1;
			goto out;
		}
	}
	if (vm_channel != NULL) {
		if (convert_integer_10(vm_channel, &channel) != 0) {
			RRR_MSG_ERR ("Syntax error in vm_channel parameter, could not understand the number '%s'\n", vm_channel);
			ret = 1;
			goto out;
		}
		if (channel != 1 && channel != 2) {
			RRR_MSG_ERR ("vm_channel must be 1 or 2\n");
			ret = 1;
			goto out;
		}
	}

	data->usb_calibration = calibration;
	data->usb_channel = channel;

	out:

	if (vm_calibration != NULL) {
		free(vm_calibration);
	}
	if (vm_channel!= NULL) {
		free(vm_channel);
	}

	return ret;
}

static int spawn_message (struct voltmonitor_data *data, uint64_t value) {
	int ret = 0;

	struct rrr_array array_tmp = {0};
	struct rrr_message *message = NULL;

	uint64_t time_now = rrr_time_get_64();

	if (rrr_array_push_value_64_with_tag(&array_tmp, "measurement", value) != 0) {
		RRR_MSG_ERR("Error while pushing value to array in spawn_message of voltmonitor\n");
		ret = 1;
		goto out;
	}
	if (rrr_array_push_value_64_with_tag(&array_tmp, "timestamp_from", rrr_time_get_64()) != 0) {
		RRR_MSG_ERR("Error while pushing value to array in spawn_message of voltmonitor\n");
		ret = 1;
		goto out;
	}
	if (rrr_array_push_value_64_with_tag(&array_tmp, "timestamp_to", rrr_time_get_64()) != 0) {
		RRR_MSG_ERR("Error while pushing value to array in spawn_message of voltmonitor\n");
		ret = 1;
		goto out;
	}

	if (rrr_array_new_message_from_collection (
			&message,
			&array_tmp,
			time_now,
			data->msg_topic,
			(data->msg_topic != 0 ? strlen(data->msg_topic) : 0)
	) != 0) {
		RRR_MSG_ERR("Could not create message in spawn_message of voltmonitor\n");
		ret = 1;
		goto out;
	}

	rrr_fifo_buffer_write(&data->buffer, (char*)message, sizeof(*message));
	message = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message);
	rrr_array_clear(&array_tmp);
	return ret;
}

int inject (struct rrr_instance_thread_data *thread_data, struct rrr_ip_buffer_entry *entry) {
	struct voltmonitor_data *data = thread_data->private_data = thread_data->private_memory;
	struct rrr_message *message = entry->message;

	int ret = 0;

	struct rrr_array array_tmp = {0};

	if (!MSG_IS_ARRAY(message)) {
		RRR_BUG("Message to voltmonitor inject was not an array\n");
	}

	if (rrr_array_message_to_collection(&array_tmp, message) != 0) {
		RRR_BUG("Could not create array collection from message in voltmonitor inject\n");
	}

	uint64_t value = 0;
	if (rrr_array_get_value_unsigned_64_by_tag(&value, &array_tmp, "measurement", 0)) {
		RRR_BUG("Could not get value from array in voltmonitor inject\n");
	}

	RRR_DBG_1("voltmonitor instance %s inject value %" PRIu64 "\n",
			INSTANCE_D_NAME(thread_data), value);

	if (spawn_message(data, value) != 0) {
		RRR_BUG("Error while spawning message in voltmonitor inject\n");
	}

	rrr_array_clear(&array_tmp);
	rrr_ip_buffer_entry_destroy(entry);
	return ret;
}

static void *thread_entry_voltmonitor (struct rrr_thread *thread) {
	struct rrr_instance_thread_data *thread_data = thread->private_data;
	struct voltmonitor_data *data = thread_data->private_data = thread_data->private_memory;

	thread_data->thread = thread;

	if (data_init(data, thread_data) != 0) {
		RRR_MSG_ERR("Could not initalize data in voltmonitor instance %s\n", INSTANCE_D_NAME(thread_data));
		pthread_exit(0);
	}

	pthread_cleanup_push(data_cleanup, data);

	RRR_DBG_1 ("voltmonitor thread data is %p\n", thread_data);

//	pthread_cleanup_push(rrr_thread_set_stopping, thread);

	rrr_thread_set_state(thread, RRR_THREAD_STATE_INITIALIZED);
	rrr_thread_signal_wait(thread_data->thread, RRR_THREAD_SIGNAL_START);
	rrr_thread_set_state(thread, RRR_THREAD_STATE_RUNNING);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		pthread_exit(0);
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	usb_init();

	pthread_cleanup_push(usb_cleanup, data);

	while (!rrr_thread_check_encourage_stop(thread_data->thread)) {
		rrr_thread_update_watchdog_time(thread_data->thread);

		int millivolts;
		if (usb_read_voltage(data, &millivolts) != 0) {
			RRR_MSG_ERR ("voltmonitor: Voltage reading failed\n");
			usleep (1000000); // 1000 ms
			continue;
		}

		if (spawn_message(data, abs(millivolts)) != 0) {
			RRR_MSG_ERR("Error when spawning message in averager instance %s\n",
					INSTANCE_D_NAME(thread_data));
			break;
		}

		usleep (250000); // 250 ms

	}

	RRR_DBG_1 ("voltmonitor received encourage stop\n");

//	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static int test_config (struct rrr_instance_config *config) {
	struct voltmonitor_data data;
	int ret = 0;

	if ((ret = data_init(&data, NULL)) != 0) {
		goto err;
	}

	ret = parse_config(&data, config);
	data_cleanup(&data);

	err:
	return ret;
}

static struct rrr_module_operations module_operations = {
		NULL,
		thread_entry_voltmonitor,
		NULL,
		poll,
		NULL,
		poll_delete,
		NULL,
		test_config,
		inject,
		NULL
};

static const char *module_name = "voltmonitor";

__attribute__((constructor)) void load(void) {
}

void init(struct rrr_instance_dynamic_data *data) {
		data->module_name = module_name;
		data->type = RRR_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(void) {
}

