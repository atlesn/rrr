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

static void __rrr_test_modbus_make_response (
		uint8_t *dst_buf,
		rrr_length *dst_buf_size,
		const uint8_t *src_buf,
		const rrr_length *src_buf_size
) {
	assert(*dst_buf_size >= *src_buf_size);

	memcpy(dst_buf, src_buf, *src_buf_size);
	*dst_buf_size = *src_buf_size;

	switch(dst_buf[7]) { // Function code
		case 0x01:
		case 0x02:
			assert(dst_buf[10] == 0 && dst_buf[11] == 16); // Quantity
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 5;     // Length low
			dst_buf[8] = 2;     // Byte count
			dst_buf[9] = 0xAB;  // Coil status 0
			dst_buf[10] = 0xCD; // Coil status 1
			*dst_buf_size = 11;
			break;
		case 0x03:
			assert(dst_buf[10] == 0 && dst_buf[11] == 2); // Quantity
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 7;     // Length low
			dst_buf[8] = 4;     // Byte count
			dst_buf[9] = 0x12;  // Register a high
			dst_buf[10] = 0x34; // Register a low
			dst_buf[11] = 0x56; // Register b high
			dst_buf[12] = 0x78; // Register b low
			*dst_buf_size = 13;
			break;
		case 0x04:
			assert(dst_buf[10] == 0 && dst_buf[11] == 2); // Quantity
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 7;     // Length low
			dst_buf[8] = 4;     // Byte count
			dst_buf[9] = 0x9A;  // Register a high
			dst_buf[10] = 0xBC; // Register a low
			dst_buf[11] = 0xDE; // Register b high
			dst_buf[12] = 0xFF; // Register b low
			*dst_buf_size = 13;
			break;
		case 0x06:
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 6;     // Length low
			dst_buf[8] = 0x12;  // Register address high
			dst_buf[9] = 0x34;  // Register address low
			dst_buf[10] = 1;    // Register value high
			dst_buf[11] = 2;    // Register value low
			*dst_buf_size = 12;
			break;
		case 0x10:
			dst_buf[4] = 0;     // Length high
			dst_buf[5] = 6;     // Length low
			dst_buf[8] = 0x12;  // Register address high
			dst_buf[9] = 0x34;  // Register address low
			dst_buf[10] = 0;    // Quantity high
			dst_buf[11] = 2;    // Quantity low
			*dst_buf_size = 12;
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

static int __rrr_test_modbus_cb_req_transaction_private_data_create (void **result, void *private_data_arg, void *arg) {
	(void)(private_data_arg);
	(void)(arg);
	*result = NULL;
	return 0;
}

static void __rrr_test_modbus_cb_req_transaction_private_data_destroy (void *transaction_private_data) {
	(void)(transaction_private_data);
}

static int __rrr_test_modbus_cb_res_error (
		RRR_MODBUS_ERROR_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(function_code);
	(void)(error_code);
	(void)(transaction_private_data);

	*status = 0;

	return 0;
}

static int __rrr_test_modbus_cb_res_01_read_coils (
		RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(transaction_private_data);

	assert(function_code == 1);
	assert(byte_count == 2);
	assert(coil_status[0] == 0xAB);
	assert(coil_status[1] == 0xCD);

	*status = 1;

	return 0;
}

static int __rrr_test_modbus_cb_res_02_read_discrete_inputs (
		RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(transaction_private_data);

	assert(function_code == 2);
	assert(byte_count == 2);
	assert(coil_status[0] == 0xAB);
	assert(coil_status[1] == 0xCD);

	*status = 2;

	return 0;
}

static int __rrr_test_modbus_cb_res_03_read_holding_registers (
		RRR_MODBUS_BYTE_COUNT_AND_REGISTERS_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(transaction_private_data);

	assert(function_code == 3);
	assert(byte_count == 4);
	assert(register_value[0] == 0x12);
	assert(register_value[1] == 0x34);
	assert(register_value[2] == 0x56);
	assert(register_value[3] == 0x78);

	*status = 3;

	return 0;
}

static int __rrr_test_modbus_cb_res_04_read_input_registers (
		RRR_MODBUS_BYTE_COUNT_AND_REGISTERS_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(transaction_private_data);

	assert(function_code == 4);
	assert(byte_count == 4);
	assert(register_value[0] == 0x9A);
	assert(register_value[1] == 0xBC);
	assert(register_value[2] == 0xDE);
	assert(register_value[3] == 0xFF);

	*status = 4;

	return 0;
}

static int __rrr_test_modbus_cb_res_06_write_single_register (
		RRR_MODBUS_STARTING_ADDRESS_AND_REGISTER_VALUE_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(transaction_private_data);

	assert(function_code == 6);
	assert(starting_address == 0x1234);
	assert(register_value[0] == 1);
	assert(register_value[1] == 2);
	*status = 6;

	return 0;
}

static int __rrr_test_modbus_cb_res_16_write_multiple_register (
		RRR_MODBUS_STARTING_ADDRESS_AND_QUANTITY_CALLBACK_ARGS
) {
	int *status = arg;

	(void)(transaction_id);
	(void)(transaction_private_data);

	assert(function_code == 16);
	assert(starting_address == 0x1234);
	assert(quantity == 2);

	*status = 16;

	return 0;
}

int rrr_test_modbus (void) {
	int ret = 0;

	struct rrr_modbus_client *client;
	uint8_t buf[256];
	uint8_t buf2[256];
	uint8_t conents[4];
	rrr_length buf_size;
	rrr_length buf_size2;
	int cb_status = -1;

	const struct rrr_modbus_client_callbacks callbacks = {
		.cb_req_transaction_private_data_create = __rrr_test_modbus_cb_req_transaction_private_data_create,
		.cb_req_transaction_private_data_destroy = __rrr_test_modbus_cb_req_transaction_private_data_destroy,
		.cb_res_error = __rrr_test_modbus_cb_res_error,
		.cb_res_01_read_coils = __rrr_test_modbus_cb_res_01_read_coils,
		.cb_res_02_read_discrete_inputs = __rrr_test_modbus_cb_res_02_read_discrete_inputs,
		.cb_res_03_read_holding_registers = __rrr_test_modbus_cb_res_03_read_holding_registers,
		.cb_res_04_read_input_registers = __rrr_test_modbus_cb_res_04_read_input_registers,
		.cb_res_06_write_single_register = __rrr_test_modbus_cb_res_06_write_single_register,
		.cb_res_16_write_multiple_registers = __rrr_test_modbus_cb_res_16_write_multiple_register,
		.arg = &cb_status
	};

	if ((ret = rrr_modbus_client_new (&client)) != 0) {
		TEST_MSG("Failed to create modbus client\n");
		goto out_final;
	}

	rrr_modbus_client_callbacks_set(client, &callbacks);

	TEST_MSG("Testing request function 01 'read coils'\n");
	if ((ret = rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL)) != 0) {
		TEST_MSG("Failed to create modbus read coil package\n");
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

	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_OK);
	assert(cb_status == 1);

	TEST_MSG("Testing request function 02 'read discrete inputs'\n");

	if ((ret = rrr_modbus_client_req_02_read_discrete_inputs (client, 0x1234, 16, NULL)) != 0) {
		TEST_MSG("Failed to create modbus read discrete inputs package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	// Nothing more to write, must return DONE
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 1);     // Transaction ID low
	VERIFY_BYTE(7, 2);     // Function code
	VERIFY_BYTE(8, 0x12);  // Starting address high
	VERIFY_BYTE(9, 0x34);  // Starting address low
	VERIFY_BYTE(10, 0x00); // Quantity high
	VERIFY_BYTE(11, 0x10); // Quantity low

	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_OK);
	assert(cb_status == 2);

	TEST_MSG("Testing request function 03 'read holding registers'\n");

	if ((ret = rrr_modbus_client_req_03_read_holding_registers (client, 0x1234, 2, NULL)) != 0) {
		TEST_MSG("Failed to create modbus read holding registers package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	// Nothing more to write, must return DONE
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 2);     // Transaction ID low
	VERIFY_BYTE(7, 3);     // Function code
	VERIFY_BYTE(8, 0x12);  // Starting address high
	VERIFY_BYTE(9, 0x34);  // Starting address low
	VERIFY_BYTE(10, 0x00); // Quantity high
	VERIFY_BYTE(11, 0x02); // Quantity low

	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_OK);
	assert(cb_status == 3);

	TEST_MSG("Testing request function 04 'read input registers'\n");

	if ((ret = rrr_modbus_client_req_04_read_input_registers (client, 0x1234, 2, NULL)) != 0) {
		TEST_MSG("Failed to create modbus read input registers package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	// Nothing more to write, must return DONE
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 3);     // Transaction ID low
	VERIFY_BYTE(7, 4);     // Function code
	VERIFY_BYTE(8, 0x12);  // Starting address high
	VERIFY_BYTE(9, 0x34);  // Starting address low
	VERIFY_BYTE(10, 0x00); // Quantity high
	VERIFY_BYTE(11, 0x02); // Quantity low

	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_OK);
	assert(cb_status == 4);

	TEST_MSG("Testing request function 06 'write single register'\n");

	conents[0] = 1;
	conents[1] = 2;

	if ((ret = rrr_modbus_client_req_06_write_single_register (client, 0x1234, conents, NULL)) != 0) {
		TEST_MSG("Failed to create modbus write single register package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	// Nothing more to write, must return DONE
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 4);     // Transaction ID low
	VERIFY_BYTE(7, 6);     // Function code
	VERIFY_BYTE(8, 0x12);  // Starting address high
	VERIFY_BYTE(9, 0x34);  // Starting address low
	VERIFY_BYTE(10, 1);  // Register value high
	VERIFY_BYTE(11, 2);  // Register value low

	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_OK);
	assert(cb_status == 6);

	TEST_MSG("Testing request function 16 'write multiple registers'\n");

	conents[0] = 1;
	conents[1] = 2;
	conents[2] = 3;
	conents[3] = 4;

	if ((ret = rrr_modbus_client_req_16_write_multiple_registers (client, 0x1234, 2U, conents, NULL)) != 0) {
		TEST_MSG("Failed to create modbus write multiple registers package\n");
		ret = 1;
		goto out;
	}

	WRITE();

	// Nothing more to write, must return DONE
	assert(rrr_modbus_client_write (client, buf, &buf_size) == RRR_MODBUS_DONE);

	VERIFY_BYTE(0, 0);     // Transaction ID high
	VERIFY_BYTE(1, 5);     // Transaction ID low
	VERIFY_BYTE(7, 16);     // Function code
	VERIFY_BYTE(8, 0x12);  // Starting address high
	VERIFY_BYTE(9, 0x34);  // Starting address low
	VERIFY_BYTE(10, 0);  // Quantity high
	VERIFY_BYTE(11, 2);  // Quantity low
	VERIFY_BYTE(12, 4);  // byte count
	VERIFY_BYTE(13, 1);  // Register value 1 high
	VERIFY_BYTE(14, 2);  // Register value 1 low
	VERIFY_BYTE(15, 3);  // Register value 2 high
	VERIFY_BYTE(16, 4);  // Register value 2 low

	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_OK);
	assert(cb_status == 16);

	TEST_MSG("Testing malformed responses for function 01 'read_coils'\n");

	assert(rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) == 0);
	WRITE();
	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	buf2[4] = 0;     // Length high
	buf2[5] = 0;     // Length low
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_SOFT_ERROR);

	assert(rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) == 0);
	WRITE();
	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	buf2[4] = 0;     // Length high
	buf2[5] = 1;     // Length low
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_SOFT_ERROR);

	assert(rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) == 0);
	WRITE();
	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	buf2[8] = 20;     // Byte count
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_SOFT_ERROR);

	assert(rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) == 0);
	WRITE();
	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	buf2[8] = 1;     // Byte count
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_SOFT_ERROR);

	assert(rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) == 0);
	WRITE();
	buf_size2 = sizeof(buf2);
	__rrr_test_modbus_make_response (buf2, &buf_size2, buf, &buf_size);
	buf2[8] = 0;     // Byte count
	assert(rrr_modbus_client_read(client, buf2, &buf_size2) == RRR_MODBUS_SOFT_ERROR);

	rrr_modbus_client_destroy(client);
	assert(rrr_modbus_client_new (&client) == 0);
	rrr_modbus_client_callbacks_set(client, &callbacks);

	TEST_MSG("Testing fill up transaction queue\n");
	for (int i = 0; i < TRANSACTION_MAX; i++) {
		assert (rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) == RRR_MODBUS_OK);
	}

	// Transaciton queue is now full

	if (rrr_modbus_client_req_01_read_coils (client, 0x1234, 16, NULL) != RRR_MODBUS_BUSY) {
		TEST_MSG("Return from request function was not BUSY\n");
		ret = 1;
		goto out;
	}

	out:
		rrr_modbus_client_destroy(client);
	out_final:
		return ret;
}
