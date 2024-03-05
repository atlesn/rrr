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

#ifdef RRR_WITH_USB
#include <usb.h>
#endif

#include "../lib/log.h"
#include "../lib/allocator.h"
#include "../lib/instance_config.h"
#include "../lib/threads.h"
#include "../lib/instances.h"
#include "../lib/array.h"
#include "../lib/array.h"
#include "../lib/message_broker.h"
#include "../lib/messages/msg_msg.h"
#include "../lib/ip/ip.h"
#include "../lib/message_holder/message_holder.h"
#include "../lib/message_holder/message_holder_struct.h"
#include "../lib/util/rrr_time.h"

struct voltmonitor_data {
	struct rrr_instance_runtime_data *thread_data;

#ifdef RRR_WITH_USB
	usb_dev_handle *usb_handle;
	struct usb_device *usb_device;
#endif

	rrr_setting_double usb_calibration;
	rrr_setting_uint usb_channel;

	int do_spawn_test_measurements;

	char *msg_topic;
	uint16_t msg_topic_len;

	pthread_mutex_t cleanup_lock;
};

#ifndef RRR_WITH_USB
static void usb_cleanup(struct voltmonitor_data *data) {
	(void)(data);
}
#else
static void usb_cleanup(struct voltmonitor_data *data) {
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
#endif

#ifdef RRR_WITH_USB
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
		RRR_MSG_0 ("voltmonitor: USB dev not found\n");
		goto err_out;
	}

	usb_dev_handle *h = usb_open ( founddev );

	if ( ! h ) {
		RRR_MSG_0 ("voltmonitor: USB open failed\n");
		goto err_out;
	}

	char drivername[64] ;
	if ( usb_get_driver_np ( h, 0, drivername, sizeof(drivername) ) == 0 ) {
		RRR_DBG_1 ( "voltage monitor usb device driver: %s\n", drivername );
		
		if ( drivername[0] != 0 ) {
			RRR_DBG_1 ( "voltagemonitor releasing driver\n" );
			
			if ( usb_detach_kernel_driver_np ( h, 0 ) ) {
				RRR_MSG_0 ("voltmonitor: release kernel USB driver failed\n");
				goto err_close_device;
			}
		}
	}

	if ( usb_claim_interface ( h, 0 ) ) {
		RRR_MSG_0 ("voltmonitor: USB claim failed\n");
		goto err_close_device;
	}

	// write report to get device info
	char outbuf[64];
	memset(outbuf, '\0', 64);
	outbuf[0] = 0xff;
	outbuf[1] = 0x37;
	if ( usb_interrupt_write ( h, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
		RRR_MSG_0 ("voltmonitor: USB write failed\n");
		goto err_close_device;
	}

	// read device info report
	char inbuf[64];
	memset(inbuf, '\0', 64);
	if ( usb_interrupt_read ( h, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
		RRR_MSG_0 ("voltmonitor: USB read failed\n");
		goto err_close_device;
	}

	int subtype = inbuf[6];
	int unitversion = inbuf[5];

	RRR_DBG_1 ( "voltagemonitor device subtype: %d\n", subtype );
	RRR_DBG_1 ( "voltagemonitor unitversion: %d\n", unitversion );
	
	if ( unitversion != 5 || subtype != 7 ) {
		RRR_MSG_0 ("voltmonitor: Unknown USB voltmeter version\n");
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
#endif

#ifndef RRR_WITH_USB
static int usb_read_voltage(struct voltmonitor_data *data, int *millivolts) {
	(void)(data);
	*millivolts = 0;
	return 0;
}
#else
static int usb_read_voltage(struct voltmonitor_data *data, int *millivolts) {
	if (data->usb_channel > 2 || data->usb_channel < 1) {
		RRR_MSG_0 ("voltmonitor: Channel must be 1 or 2, got %i\n", data->usb_channel);
		exit(EXIT_FAILURE);
	}

	RRR_DBG_3 ("Read voltage channel %i calibration %f\n", data->usb_channel, data->usb_calibration);

	unsigned int channel = data->usb_channel - 1;

	if (data->usb_handle == NULL) {
		if (usb_connect(data) != 0) {
			RRR_MSG_0 ("voltmonitor: USB-device connect failed\n");
		}
		if (data->usb_handle == NULL) {
			RRR_MSG_0 ("voltmonitor: USB-device not ready\n");
			goto err_out;
		}
	}

	// trigger measurement
	char outbuf[64];
	memset ( outbuf, 255, 64 );
	outbuf[0] = 0x37;
		if ( usb_interrupt_write ( data->usb_handle, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
			RRR_MSG_0 ("voltmonitor: USB write failed\n");
			goto err_close_device;
		}

	char inbuf[64];
	memset ( inbuf, 255, 64 );
		if ( usb_interrupt_read ( data->usb_handle, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
			RRR_MSG_0 ( "voltagemonitor read failed\n" );
			RRR_MSG_0 ("voltmonitor: USB read failed\n");
			goto err_close_device;
		}

		if ( inbuf[0] != 0x37 ) {
			RRR_MSG_0 ("voltmonitor: USB parse failed, 0x37 not found\n");
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
#endif

static void data_init(struct voltmonitor_data *data, struct rrr_instance_runtime_data *thread_data) {
	memset(data, '\0', sizeof(*data));
	data->thread_data = thread_data;
}

static void data_cleanup(void *arg) {
	struct voltmonitor_data *data = (struct voltmonitor_data *) arg;
	RRR_FREE_IF_NOT_NULL(data->msg_topic);
}

static int parse_config(struct voltmonitor_data *data, struct rrr_instance_config_data *config) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_TOPIC("vm_message_topic", msg_topic, msg_topic_len);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_DOUBLE("vm_calibration", usb_calibration, 1.124);
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED("vm_channel", usb_channel, 1);

	if (data->usb_channel != 1 && data->usb_channel != 2) {
		RRR_MSG_0 ("Parameter vm_channel must be 1 or 2 in in voltmonitor instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	// Undocumented parameters, used in test suite
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO("vm_spawn_test_measurements", do_spawn_test_measurements, 0);

	out:

	return ret;
}

struct volmonitor_spawn_message_callback_data {
	struct voltmonitor_data *data;
	const struct rrr_array *array_tmp;
	uint64_t time_now;
};

static int voltmonitor_spawn_message_callback (struct rrr_msg_holder *entry, void *arg) {
	struct volmonitor_spawn_message_callback_data *callback_data = arg;

	int ret = 0;

	struct rrr_msg_msg *message = NULL;

	if (rrr_array_new_message_from_array (
			&message,
			callback_data->array_tmp,
			callback_data->time_now,
			callback_data->data->msg_topic,
			(callback_data->data->msg_topic != NULL ? callback_data->data->msg_topic_len : 0)
	) != 0) {
		RRR_MSG_0("Could not create message in volmonitor_spawn_message of voltmonitor instance %s\n",
				INSTANCE_D_NAME(callback_data->data->thread_data));
		ret = 1;
		goto out;
	}

	entry->message = message;
	entry->data_length = MSG_TOTAL_SIZE(message);

	message = NULL;

	out:
	rrr_msg_holder_unlock(entry);
	RRR_FREE_IF_NOT_NULL(message);
	return ret;
}

static int voltmonitor_spawn_message (struct voltmonitor_data *data, int value) {
	int ret = 0;

	struct rrr_array array_tmp = {0};

	const uint64_t time_now = rrr_time_get_64();

	ret |= rrr_array_push_value_i64_with_tag(&array_tmp, "measurement", value);
	ret |= rrr_array_push_value_u64_with_tag(&array_tmp, "timestamp_from", time_now);
	ret |= rrr_array_push_value_u64_with_tag(&array_tmp, "timestamp_to", time_now);

	if (ret != 0) {
		RRR_MSG_0("Error while pushing values to array in volmonitor_spawn_message of voltmonitor instance %s\n",
			INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	struct volmonitor_spawn_message_callback_data callback_data = {
		data,
		&array_tmp,
		time_now
	};

	if ((ret = rrr_message_broker_write_entry(
			INSTANCE_D_BROKER_ARGS(data->thread_data),
			NULL,
			0,
			0,
			NULL,
			voltmonitor_spawn_message_callback,
			&callback_data,
			INSTANCE_D_CANCEL_CHECK_ARGS(data->thread_data)
	)) != 0) {
		RRR_MSG_0("Could not spawn message in voltmonitor instance %s\n", INSTANCE_D_NAME(data->thread_data));
		goto out;
	}

	out:
	rrr_array_clear(&array_tmp);
	return ret;
}

static int voltmonitor_spawn_test_messages (struct voltmonitor_data *data) {
	int ret = 0;
	for (int i = 2; i <= 8; i += 2) {
		if ((ret = voltmonitor_spawn_message(data, i)) != 0) {
			break;
		}
	}
	return ret;
}

static int voltmonitor_periodic (RRR_EVENT_FUNCTION_PERIODIC_ARGS) {
	struct rrr_thread *thread = arg;
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct voltmonitor_data *data = thread_data->private_data = thread_data->private_memory;

	int millivolts = 0;

	if (data->do_spawn_test_measurements) {
		goto out;
	}

	if (usb_read_voltage(data, &millivolts) != 0) {
		RRR_MSG_0 ("voltmonitor: Voltage reading failed\n");
		goto out;
	}

	if (voltmonitor_spawn_message(data, abs(millivolts)) != 0) {
		RRR_MSG_0("Error when spawning message in averager instance %s\n",
			INSTANCE_D_NAME(thread_data));
		return RRR_EVENT_ERR;
	}

	out:
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(thread);
}


static int voltmonitor_init (RRR_INSTANCE_INIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct voltmonitor_data *data = thread_data->private_data = thread_data->private_memory;

	data_init(data, thread_data);

	RRR_DBG_1 ("voltmonitor thread data is %p\n", thread_data);
#ifndef RRR_WITH_USB
	RRR_MSG_0("Warning: voltmonitor compiled without USB support. All readings will be 0.\n");
#endif

	rrr_thread_start_condition_helper_nofork(thread);

	if (parse_config(data, thread_data->init_data.instance_config) != 0) {
		goto data_cleanup;
	}

	rrr_instance_config_check_all_settings_used(thread_data->init_data.instance_config);

	if (data->do_spawn_test_measurements) {
		if (voltmonitor_spawn_test_messages(data) != 0) {
			RRR_MSG_0("Could not spawn test messages in voltmonitor instance %s\n",
					INSTANCE_D_NAME(thread_data));
			goto usb_cleanup;
		}
	}

	if (rrr_event_function_periodic_set (
			INSTANCE_D_EVENTS_H(thread_data),
			250 * 1000, // 250 ms
			voltmonitor_periodic
	) != 0) {
		RRR_MSG_0("Failed to set periodic function in voltmonitor instance %s\n", INSTANCE_D_NAME(thread_data));
		goto usb_cleanup;
	}

	return 0;

	usb_cleanup:
		usb_cleanup(data);
	data_cleanup:
		data_cleanup(data);
		return 1;
}

static void voltmonitor_deinit (RRR_INSTANCE_DEINIT_ARGS) {
	struct rrr_instance_runtime_data *thread_data = thread->private_data;
	struct voltmonitor_data *data = thread_data->private_data = thread_data->private_memory;

	RRR_DBG_1 ("voltmonitor received encourage stop\n");

	usb_cleanup(data);
	data_cleanup(data);

	*shutdown_complete = 1;
}

static const char *module_name = "voltmonitor";

__attribute__((constructor)) void construct(void) {
#ifdef RRR_WITH_USB
	usb_init();
#endif
}

void load (struct rrr_instance_module_data *data) {
	data->module_name = module_name;
	data->type = RRR_MODULE_TYPE_SOURCE;
	data->private_data = NULL;
	data->init = voltmonitor_init;
	data->deinit = voltmonitor_deinit;
}

void unload (void) {
}

