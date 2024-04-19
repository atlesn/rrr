/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MODBUS_H
#define RRR_MODBUS_H

#include <inttypes.h>

#include "../rrr_types.h"
#include "../read_constants.h"

#define RRR_MODBUS_OK          RRR_READ_OK
#define RRR_MODBUS_HARD_ERROR  RRR_READ_HARD_ERROR
#define RRR_MODBUS_SOFT_ERROR  RRR_READ_SOFT_ERROR
#define RRR_MODBUS_BUSY        RRR_READ_BUSY
#define RRR_MODBUS_DONE        RRR_READ_EOF
#define RRR_MODBUS_INCOMPLETE  RRR_READ_INCOMPLETE

#define RRR_MODBUS_FUNCTION_CODE_01_READ_COILS                 0x01
#define RRR_MODBUS_FUNCTION_CODE_02_READ_DISCRETE_INPUTS       0x02
#define RRR_MODBUS_FUNCTION_CODE_03_READ_HOLDING_REGISTERS     0x03
#define RRR_MODBUS_FUNCTION_CODE_04_READ_INPUT_REGISTERS       0x04
#define RRR_MODBUS_FUNCTION_CODE_06_WRITE_SINGLE_REGISTER      0x06
#define RRR_MODBUS_FUNCTION_CODE_16_WRITE_MULTIPLE_REGISTERS   0x10

#define RRR_MODBUS_ERROR_CALLBACK_ARGS \
    uint16_t transaction_id, uint8_t function_code, uint8_t error_code, void *transaction_private_data, void *arg

#define RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS \
    uint8_t function_code, uint16_t transaction_id, uint8_t byte_count, const uint8_t *coil_status, void *transaction_private_data, void *arg

#define RRR_MODBUS_BYTE_COUNT_AND_REGISTERS_CALLBACK_ARGS \
    uint8_t function_code, uint16_t transaction_id, uint8_t byte_count, const uint8_t *register_value, void *transaction_private_data, void *arg

#define RRR_MODBUS_STARTING_ADDRESS_AND_REGISTER_VALUE_CALLBACK_ARGS \
    uint8_t function_code, uint16_t transaction_id, uint16_t starting_address, const uint8_t *register_value, void *transaction_private_data, void *arg

#define RRR_MODBUS_STARTING_ADDRESS_AND_QUANTITY_CALLBACK_ARGS \
    uint8_t function_code, uint16_t transaction_id, uint16_t starting_address, uint16_t quantity, void *transaction_private_data, void *arg

struct rrr_modbus_client_callbacks {
	int  (*cb_req_transaction_private_data_create)(void **result, void *private_data_arg, void *arg);
	void (*cb_req_transaction_private_data_destroy)(void *transaction_private_data);
	int  (*cb_res_error)(RRR_MODBUS_ERROR_CALLBACK_ARGS);
	int  (*cb_res_01_read_coils)(RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS);
	int  (*cb_res_02_read_discrete_inputs)(RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS);
	int  (*cb_res_03_read_holding_registers)(RRR_MODBUS_BYTE_COUNT_AND_REGISTERS_CALLBACK_ARGS);
	int  (*cb_res_04_read_input_registers)(RRR_MODBUS_BYTE_COUNT_AND_REGISTERS_CALLBACK_ARGS);
	int  (*cb_res_06_write_single_regsister)(RRR_MODBUS_STARTING_ADDRESS_AND_REGISTER_VALUE_CALLBACK_ARGS);
	int  (*cb_res_16_write_multiple_regsisters)(RRR_MODBUS_STARTING_ADDRESS_AND_QUANTITY_CALLBACK_ARGS);
	void  *arg;
};

struct rrr_modbus_client;

int rrr_modbus_client_new (
		struct rrr_modbus_client **target
);
void rrr_modbus_client_destroy (
		struct rrr_modbus_client *client
);
void rrr_modbus_client_callbacks_set (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_client_callbacks *callbacks
);
int rrr_modbus_client_read (
		struct rrr_modbus_client *client,
		const uint8_t *data,
		rrr_length *data_size
);
int rrr_modbus_client_write (
		struct rrr_modbus_client *client,
		uint8_t *data,
		rrr_length *data_size
);
int rrr_modbus_client_req_01_read_coils (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_coils,
		void *private_data_arg
);
int rrr_modbus_client_req_02_read_discrete_inputs (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_coils,
		void *private_data_arg
);
int rrr_modbus_client_req_03_read_holding_registers (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_registers,
		void *private_data_arg
);
int rrr_modbus_client_req_04_read_input_registers (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_registers,
		void *private_data_arg
);
int rrr_modbus_client_req_06_write_single_register (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint8_t *contents,
		void *private_data_arg
);
int rrr_modbus_client_req_16_write_multiple_registers (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_registers,
		uint8_t *contents,
		void *private_data_arg
);
#endif /* RRR_MODBUS_H */

