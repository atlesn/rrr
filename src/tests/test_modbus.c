/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <assert.h>
#include <string.h>

#include "test.h"
#include "test_modbus.h"
#include "../lib/log.h"
#include "../lib/modbus/rrr_modbus.h"

static void __rrr_test_modbus_make_response (uint8_t *buf, rrr_length *buf_size) {
	switch(buf[7]) { // Function code
		case 0x01:
			assert(buf[10] == 0 && buf[11] == 16); // Quantity
			buf[8] = 2;     // Byte count
			buf[9] = 0x01;  // Coil status 0
			buf[10] = 0x01; // Coil status 1
			(*buf_size)--;
			break;
		default:
			assert(0);
	}
}

// Update if changed in the library
#define TRANSACTION_MAX 32

#define VERIFY_BYTE(i,v)                                                                        \
    do {if (buf[i] != v) {                                                                      \
        TEST_MSG("Modbus mismatch at byte %d. Expected %d but value was %d.\n", i, v, buf[i]);  \
	ret = 1;                                                                                \
	goto out;                                                                               \
    }} while(0)

#define VERIFY_SIZE(s)                                                                          \
    do {if (buf_size != s) {                                                                    \
        TEST_MSG("Modbus size mismatch. Expected %d but size was %d.\n", s, buf_size);          \
	ret = 1;                                                                                \
	goto out;                                                                               \
    }} while(0)

#define WRITE()                                                                                 \
    do {buf_size = (rrr_length) sizeof(buf);                                                    \
    if (rrr_modbus_client_write (client, buf, &buf_size) != RRR_MODBUS_OK) {                    \
        TEST_MSG("Failed to write package\n");                                                  \
        ret = 1;                                                                                \
        goto out;                                                                               \
    }} while(0)

int rrr_test_modbus (void) {
	int ret = 0;

	struct rrr_modbus_client *client;
	uint8_t buf[256];
	uint8_t buf2[256];
	rrr_length buf_size;
	rrr_length buf_size2;

	if ((ret = rrr_modbus_client_new (&client)) != 0) {
		TEST_MSG("Failed to create modbus client\n");
		ret = 1;
		goto out_final;
	}

	TEST_MSG("Testing request function 01 'read coils'\n");
	if ((ret = rrr_modbus_client_req_01_read_coils (client, 0x1234, 16)) != 0) {
		TEST_MSG("Failed to create modbus read coil package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	// Nothing more to write, must return DONE
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	VERIFY_SIZE(12);
	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 0);     // Transaction ID low
	VERIFY_BYTE(2, 0);     // Protocol ID high
	VERIFY_BYTE(3, 0);     // Protocol ID low
	VERIFY_BYTE(4, 0);     // Length high
	VERIFY_BYTE(5, 6);     // Length low
	VERIFY_BYTE(6, 0xff);  // Unit ID
	VERIFY_BYTE(7, 1);     // Function code
	VERIFY_BYTE(8, 0x12);  // Starting address high
	VERIFY_BYTE(9, 0x34);  // Starting address low
	VERIFY_BYTE(10, 0x00); // Quantity high
	VERIFY_BYTE(11, 0x10); // Quantity low

	TEST_MSG("Testing transaction ID increment\n");
	if ((ret = rrr_modbus_client_req_01_read_coils (client, 0x1234, 16)) != 0) {
		TEST_MSG("Failed to create modbus read coil package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 1);     // Transaction ID low

	memcpy(buf2, buf, sizeof(buf));
	__rrr_test_modbus_make_response (buf, &buf_size2);

	TEST_MSG("Testing fill up transaction queue\n");
	for (int i = 0; i < TRANSACTION_MAX; i++) {
		assert (rrr_modbus_client_req_01_read_coils (client, 0x1234, 16) == RRR_MODBUS_OK);
	}

	// Transaciton queue is now full

	if (rrr_modbus_client_req_01_read_coils (client, 0x1234, 16) == RRR_MODBUS_BUSY) {
		TEST_MSG("Return from request function was not BUSY\n");
		ret = 1;
		goto out;
	}

	for (int i = 0; i < TRANSACTION_MAX; i++) {
		assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_OK);
	}
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	// Transaciton queue is now empty

	assert (rrr_modbus_client_req_01_read_coils (client, 0x1234, 16) == RRR_MODBUS_OK);

	out:
		rrr_modbus_client_destroy(client);
	out_final:
		return ret;
}
