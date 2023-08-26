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

#define RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS \
    uint16_t transaction_id, uint8_t byte_count, const uint8_t *coil_status, void *arg

struct rrr_modbus_client_callbacks {
	int (*cb_res_error)(uint16_t transaction_id, uint8_t function_code, uint8_t error_code, void *arg);
	int (*cb_res_01_read_coils)(RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS);
	int (*cb_res_02_read_discrete_inputs)(RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS);
	void *arg;
};

struct rrr_modbus_client;

int rrr_modbus_client_new (
		struct rrr_modbus_client **target
);
void rrr_modbus_client_destroy (
		struct rrr_modbus_client *target
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
		uint16_t quantity_of_coils
);
int rrr_modbus_client_req_02_read_discrete_inputs (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_coils
);

#endif /* RRR_MODBUS_H */

