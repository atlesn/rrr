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

#include "../lib/vl_time.h"
#include "../lib/threads.h"
#include "../lib/buffer.h"
#include "../modules.h"
#include "../lib/messages.h"
#include "../lib/measurement.h"

#define VL_VOLTMONITOR_CHANNEL 1


// From libusb
void usb_free_dev(struct usb_device *dev);
void usb_free_bus(struct usb_bus *bus);

struct voltmonitor_data {
	struct fifo_buffer buffer;
	usb_dev_handle *usb_handle;
	struct usb_device *usb_device;

	struct usb_bus *usb_first_bus;

	float usb_calibration;
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
	if (data->usb_first_bus != NULL) {
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
	}

	return;
}

static int usb_connect(struct voltmonitor_data *data) {
	struct usb_bus *bus;
	struct usb_device *founddev = NULL;

	struct usb_bus *next_bus = NULL;
	data->usb_first_bus = usb_get_busses();
	for ( bus = data->usb_first_bus ; bus ; bus = next_bus ) {
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
		fprintf (stderr, "voltmonitor: USB dev not found\n");
		goto err_out;
	}

	usb_dev_handle *h = usb_open ( founddev );

	if ( ! h ) {
		fprintf (stderr, "voltmonitor: USB open failed\n");
		goto err_out;
	}
	
	char drivername[64] ;
	if ( usb_get_driver_np ( h, 0, drivername, sizeof(drivername) ) == 0 ) {
//		printf ( "driver: %s\n", drivername );
		
		if ( drivername[0] != 0 ) {
//			printf ( "releasing driver\n" );
			
			if ( usb_detach_kernel_driver_np ( h, 0 ) ) {
				fprintf (stderr, "voltmonitor: release kernel USB driver failed\n");
				goto err_close_device;
			}
		}
	}
	
	if ( usb_claim_interface ( h, 0 ) ) {
		fprintf (stderr, "voltmonitor: USB claim failed\n");
		goto err_close_device;
	}

	// write report to get device info
	unsigned char outbuf[64];
	memset(outbuf, '\0', 64);
	outbuf[0] = 0xff;
	outbuf[1] = 0x37;
	if ( usb_interrupt_write ( h, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
		fprintf (stderr, "voltmonitor: USB write failed\n");
		goto err_close_device;
	}

	// read device info report
	unsigned char inbuf[64];
	memset(inbuf, '\0', 64);
	if ( usb_interrupt_read ( h, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
		fprintf (stderr, "voltmonitor: USB read failed\n");
		goto err_close_device;
	}
	
	int subtype = inbuf[6];
	int unitversion = inbuf[5];

	// I had to adjust 'calib' by use of an usual digital voltmeter
	//float calib = 1.0 + ( ( (float)( ((unsigned int)inbuf[8] << 8) + inbuf[7] ) ) - 30000.0 ) * 0.00001;


	// For debugging uncomment the following lines
	//printf ( "subtype: %d\n", subtype );
	//printf ( "unitversion: %d\n", unitversion );
	//printf ( "calib: %f\n", calib );
	
	if ( unitversion != 5 || subtype != 7 ) {
		fprintf (stderr, "voltmonitor: Unknown USB voltmeter version\n");
		goto err_close_device;
	}

	data->usb_handle = h;
    data->usb_calibration = 1.124 + ( ( (float)( ((unsigned int)inbuf[8] << 8) + inbuf[7] ) ) - 30000.0 ) * 0.00001;
	data->usb_device = founddev;

	return 0;

	err_close_device:
	usb_close(h);

	err_out:

	return 1;
}

static int usb_read_voltage(struct voltmonitor_data *data, unsigned int channel, int *millivolts) {
	if (channel > 1) {
		fprintf (stderr, "voltmonitor: Channel must be 0 or 1, got %u\n", channel);
		exit(EXIT_FAILURE);
	}
	if (data->usb_handle == NULL) {
		if (usb_connect(data) != 0) {
			fprintf (stderr, "voltmonitor: USB-device connect failed\n");
		}
		if (data->usb_handle == NULL) {
			fprintf (stderr, "voltmonitor: USB-device not ready\n");
			goto err_out;
		}
	}

	// trigger measurement
	unsigned char outbuf[64];
	memset ( outbuf, 255, 64 );
	outbuf[0] = 0x37;
		if ( usb_interrupt_write ( data->usb_handle, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
			fprintf (stderr, "voltmonitor: USB write failed\n");
			goto err_close_device;
		}

	unsigned char inbuf[64];
	memset ( inbuf, 255, 64 );
		if ( usb_interrupt_read ( data->usb_handle, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
			printf ( "read failed\n" );
			fprintf (stderr, "voltmonitor: USB read failed\n");
			goto err_close_device;
		}

		if ( inbuf[0] != 0x37 ) {
			fprintf (stderr, "voltmonitor: USB parse failed, 0x37 not found\n");
			goto err_close_device;
		}
/*
	for (int j = 0; j < 64; j++) {
		printf ("%02x ", inbuf[j]);
	}
	printf ("\n");
*/
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

	printf ("%04f - %d\n", value_1, *millivolts);

	return 0;

	err_close_device:

	usb_close(data->usb_handle);
	data->usb_handle = NULL;
	data->usb_device = NULL;

	err_out:

	return 1;
}


static int poll_delete (
		struct module_thread_data *data,
		void (*callback)(void *caller_data, char *data, unsigned long int size),
		struct module_thread_data *caller_data
) {
	struct voltmonitor_data *voltmonitor_data = data->private_data;
	int res = fifo_read_clear_forward(&voltmonitor_data->buffer, NULL, callback, caller_data);
	printf ("Poll result was: %i\n", res);
	if (res == 0) {
		return VL_POLL_EMPTY_RESULT_OK;
	}
	else if (res >= 1) {
		return VL_POLL_RESULT_OK;
	}
	else {
		return VL_POLL_RESULT_ERR;
	}
}

static int poll (
		struct module_thread_data *data,
		void (*callback)(void *caller_data, char *data, unsigned long int size),
		struct module_thread_data *caller_data
) {
	struct voltmonitor_data *voltmonitor_data = data->private_data;
	int res = fifo_read_forward(&voltmonitor_data->buffer, NULL, callback, caller_data);
	printf ("Poll result was: %i\n", res);
	if (res == 0) {
		return VL_POLL_EMPTY_RESULT_OK;
	}
	else if (res >= 1) {
		return VL_POLL_RESULT_OK;
	}
	else {
		return VL_POLL_RESULT_ERR;
	}
}

struct voltmonitor_data *data_init(struct module_thread_data *module_thread_data) {
	// Use special memory region provided in module_thread_data which we don't have to free
	struct voltmonitor_data *data = (struct voltmonitor_data *) module_thread_data->private_memory;
	memset(data, '\0', sizeof(*data));
	fifo_buffer_init(&data->buffer);
	return data;
}

void data_cleanup(void *arg) {
	// Make sure all readers have left and invalidate buffer
	struct voltmonitor_data *data = (struct voltmonitor_data *) arg;
	fifo_buffer_invalidate(&data->buffer);
	// Don't destroy mutex, threads might still try to use it
	//fifo_buffer_destroy(&data->buffer);
}

static void *thread_entry_voltmonitor(struct vl_thread_start_data *start_data) {
	struct module_thread_data *thread_data = start_data->private_arg;
	thread_data->thread = start_data->thread;
	struct voltmonitor_data *data = data_init(thread_data);

	printf ("voltmonitor thread data is %p\n", thread_data);

	usb_init();
	usb_find_busses();
	usb_find_devices();

	pthread_cleanup_push(usb_cleanup, data);
	pthread_cleanup_push(data_cleanup, data);
	pthread_cleanup_push(thread_set_stopping, start_data->thread);
	thread_data->private_data = data;

	static const char *voltmonitor_msg = "voltmonitor measurement";

	thread_set_state(start_data->thread, VL_THREAD_STATE_RUNNING);

	while (!thread_check_encourage_stop(thread_data->thread)) {
		update_watchdog_time(thread_data->thread);

		uint64_t time = time_get_64();
		int millivolts;
		if (usb_read_voltage(data, VL_VOLTMONITOR_CHANNEL, &millivolts) != 0) {
			fprintf (stderr, "voltmonitor: Voltage reading failed\n");
			struct vl_message *reading = reading_new_info(time, "Voltmonitor: problems with USB-device");
			fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading));

			usleep (1000000); // 1000 ms
			usb_find_busses();
			usb_find_devices();
			continue;
		}

		struct vl_message *reading = reading_new(abs(millivolts), time);
		fifo_buffer_write(&data->buffer, (char*)reading, sizeof(*reading));

		usleep (250000); // 250 ms

	}

	printf ("voltmonitor received encourage stop\n");

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit(0);
}

static struct module_operations module_operations = {
		thread_entry_voltmonitor,
		poll,
		NULL,
		poll_delete
};

static const char *module_name = "voltmonitor";


__attribute__((constructor)) void load() {
}

void init(struct module_dynamic_data *data) {
		data->name = module_name;
		data->type = VL_MODULE_TYPE_SOURCE;
		data->operations = module_operations;
		data->dl_ptr = NULL;
		data->private_data = NULL;
}

void unload(struct module_dynamic_data *data) {
}

