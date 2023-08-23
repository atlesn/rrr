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

#include "test.h"
#include "test_modbus.h"
#include "../lib/log.h"
#include "../lib/modbus/rrr_modbus.h"

#define VERIFY_BYTE(i,v)                                                                        \
    if (buf[i] != v) {                                                                          \
        TEST_MSG("Modbus mismatch at byte %d. Expected %d but value was %d.\n", i, v, buf[i]);  \
	ret = 1;                                                                                \
	goto out;                                                                               \
    }

#define VERIFY_SIZE(s)                                                                          \
    if (buf_size != s) {                                                                        \
        TEST_MSG("Modbus size mismatch. Expected %d but size was %d.\n", s, buf_size);          \
	ret = 1;                                                                                \
	goto out;                                                                               \
    }

int rrr_test_modbus (void) {
	int ret = 0;

	struct rrr_modbus_client *client;
	uint8_t buf[256];
	rrr_length buf_size;

	if ((ret = rrr_modbus_client_new (&client)) != 0) {
		TEST_MSG("Failed to create modbus client\n");
		ret = 1;
		goto out_final;
	}

	TEST_MSG("Testing request function 01 'read coils'\n");
	if ((ret = rrr_modbus_client_req_01_read_coils (client, 0x1234, 0x5678)) != 0) {
		TEST_MSG("Failed to create modbus read coil package\n");
		ret = 1;
		goto out;
	}

	buf_size = (rrr_length) sizeof(buf);
	if (rrr_modbus_client_write (client, buf, &buf_size) != RRR_MODBUS_OK) {
		TEST_MSG("Failed to write read coil package\n");
		ret = 1;
		goto out;
	}

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
	VERIFY_BYTE(10, 0x56); // Quantity high
	VERIFY_BYTE(11, 0x78); // Quantity low

	out:
		rrr_modbus_client_destroy(client);
	out_final:
		return ret;
}
