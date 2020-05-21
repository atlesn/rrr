/*
voltage monitor and plotter for single channel USBVoltmeter from
   http://digital-measure.com

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

This is the actual code which pulls the numbers out of the voltmeter. It is
   based on code provided by digital-measure.com

--------------------------------------------------------------------------

2018-02-27

Modified to fit 2-channel device with unitversion == 5 && subtype == 7. 

!!!!! TEST VERSION, NOT CALIBRATED !!!!!

Atle Solbakken atle@goliathdns.no

--------------------------------------------------------------------------


to download the usb drivers (ubuntu and debian): sudo apt-get install libusb-dev
to compile the source code: gcc checkvoltage.c -o checkvoltage -lusb
to run the voltmeter: sudo ./checkvoltage
*/

#include <stdio.h>
#include <stdlib.h>
#include <usb.h>
#include <unistd.h>
#include <string.h>



int main ( int argc, char** argv ) {
	usb_init();
	usb_find_busses();
	usb_find_devices();
	
	struct usb_bus *bus;
	struct usb_device *founddev = NULL;

	for ( bus = usb_get_busses() ; bus ; bus = bus->next ) {
		struct usb_device *dev;
		for ( dev = bus->devices ; dev ; dev = dev->next ) {
			if ( dev->descriptor.idVendor == 0x04d8 && dev->descriptor.idProduct == 0xfc39 ) {
				founddev = dev;
			}
		}
	}
	
	if ( ! founddev ) {
		printf ( "dev not found\n" );
		return 1;
	}
	
	usb_dev_handle *h = usb_open ( founddev );
	
	if ( ! h ) {
		printf ( "open failed\n" );
		return 1;
	}
	
	char drivername[64] ;
	if ( usb_get_driver_np ( h, 0, drivername, sizeof(drivername) ) == 0 ) {
//		printf ( "driver: %s\n", drivername );
		
		if ( drivername[0] != 0 ) {
//			printf ( "releasing driver\n" );
			
			if ( usb_detach_kernel_driver_np ( h, 0 ) ) {
				printf ( "release kernel driver failed\n" );
				return 1;
			}
		}
	}
	
	if ( usb_claim_interface ( h, 0 ) ) {
		printf ( "claim failed\n" );
		return 1;
	}

	// write report to get device info
	unsigned char outbuf[64];
	outbuf[0] = 0xff;
	outbuf[1] = 0x37;
	if ( usb_interrupt_write ( h, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
		printf ( "write failed\n" );
		return 1;
	}

	// read device info report
	unsigned char inbuf[64];
	if ( usb_interrupt_read ( h, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
		printf ( "read failed\n" );
		return 1;
	}
	
	// I had to adjust 'calib' by use of an usual digital voltmeter
	//float calib = 1.0 + ( ( (float)( ((unsigned int)inbuf[8] << 8) + inbuf[7] ) ) - 30000.0 ) * 0.00001;
        float calib = 1.124 + ( ( (float)( ((unsigned int)inbuf[8] << 8) + inbuf[7] ) ) - 30000.0 ) * 0.00001;
	int subtype = inbuf[6];
	int unitversion = inbuf[5];

	// For debugging uncomment the following lines
	//printf ( "subtype: %d\n", subtype );
	//printf ( "unitversion: %d\n", unitversion );
	//printf ( "calib: %f\n", calib );
	
	int i = 100;

/*	if ( unitversion == 3 && subtype == 1 ) {
		goto version_ok;
	}
	else*/ if ( unitversion == 5 && subtype == 7 ) {
		goto version_ok;
	}

	goto version_notok;
	version_ok:

	// just make only 1 measurement. If you want to do more just increase i to the wanted value
	while ( i-- ) {
                // wait for approx. 500ms for the next measruement
		rrr_posix_usleep ( 250000 );
		
		// trigger measurement
		unsigned char outbuf[64];
		memset ( outbuf, 255, 64 );
		outbuf[0] = 0x37;
			if ( usb_interrupt_write ( h, 1, outbuf, sizeof(outbuf), 1000 ) != 64 ) {
				printf ( "write failed\n" );
				return 1;
			}
		
		unsigned char inbuf[64];
		memset ( inbuf, 255, 64 );
			if ( usb_interrupt_read ( h, 1, inbuf, sizeof(inbuf), 1000 ) != 64 ) {
				printf ( "read failed\n" );
				return 1;
			}
		
			if ( inbuf[0] != 0x37 ) {
				printf ( "parse failed, 0x37 not found\n" );
				continue;
			}

		for (int j = 0; j < 64; j++) {
			printf ("%02x ", inbuf[j]);
		}
		printf ("\n");

		unsigned char negative_1 = ( inbuf[1] & 0x20 ) ? 0 : 1;
		unsigned char negative_2 = ( inbuf[5] & 0x20 ) ? 0 : 1;
		
		unsigned char tmp_1;
		unsigned char tmp_2;
		
		// inbuf1 inbuf2 inbuf3     tmp
		
		tmp_1 = inbuf[2];
		inbuf[1] <<= 3;
		tmp_1 >>= 5;
		inbuf[1] += tmp_1;
		inbuf[2] <<= 3;
		inbuf[3] >>= 5;
		inbuf[2]  += inbuf[3];
		
		tmp_2 = inbuf[6];
		inbuf[5] <<= 3;
		tmp_2 >>= 5;
		inbuf[5] += tmp_2;
		inbuf[6] <<= 3;
		inbuf[7] >>= 5;
		inbuf[6]  += inbuf[7];

		float value_1 = ( (unsigned int) inbuf[1] << 8 )  + inbuf[2];
			if ( negative_1 ) {
				value_1 -= 65535;
			}

		float value_2 = ( (unsigned int) inbuf[5] << 8 )  + inbuf[6];
			if ( negative_2 ) {
				value_2 -= 65535;
			}
		
		value_1 = value_1 * 400 / 65535.0 * calib;
		value_2 = value_2 * 400 / 65535.0 * calib;
		printf ( "%0.4f", value_1 );
		printf ( " - %0.4f\n", value_2 );
	}
	
	if ( usb_close (  h ) ) {
		printf ( "close failed\n" );
		return 1;
	}
	printf ("\n");
	return 0;	

	version_notok:
	printf ( "unsupported device, unitversion=%d subtype=%d\n", unitversion, subtype );
	return 1;
}
