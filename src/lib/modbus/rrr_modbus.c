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

#include <assert.h>

#include "rrr_modbus.h"

#include "../allocator.h"
#include "../rrr_types.h"
#include "../util/rrr_endian.h"
#include "../util/rrr_time.h"
#include "../helpers/string_builder.h"

#define RRR_MODBUS_CLIENT_TRANSACTION_MAX 32
#define RRR_MODBUS_CLIENT_TRANSACTION_TIMEOUT_S 1

#define RRR_MODBUS_FUNCTION_CODE_01_READ_COILS               0x01
#define RRR_MODBUS_FUNCTION_CODE_02_READ_DISCRETE_INPUTS     0x02
#define RRR_MODBUS_FUNCTION_CODE_03_READ_HOLDING_REGISTERS   0x03

struct rrr_modbus_mbap {
	uint16_t transaction_identifier;
	uint16_t protocol_identifier;
	uint16_t length;
	uint8_t unit_identifier;
} __attribute((__packed__));

struct rrr_modbus_req_address_and_amount {
	uint16_t starting_address;
	uint16_t amount;
} __attribute((__packed__));

typedef struct rrr_modbus_req_address_and_amount rrr_modbus_req_01_read_coils;
typedef struct rrr_modbus_req_address_and_amount rrr_modbus_req_02_read_discrete_inputs;
typedef struct rrr_modbus_req_address_and_amount rrr_modbus_req_03_read_holding_registers;

struct rrr_modbus_req {
	uint8_t function_code;
	union {
		rrr_modbus_req_01_read_coils               read_coils;
		rrr_modbus_req_02_read_discrete_inputs     read_discrete_inputs;
		rrr_modbus_req_03_read_holding_registers   read_holding_registers;
	};
} __attribute((__packed__));

#define RRR_MODBUS_REQ_SIZE(function) (sizeof(function) + 1)

struct rrr_modbus_res_error {
	uint8_t exception_code;
} __attribute((__packed__));

struct rrr_modbus_res_byte_count_and_status {
	uint8_t byte_count;
	uint8_t status[250];
} __attribute((__packed__));

typedef struct rrr_modbus_res_byte_count_and_status rrr_modbus_res_01_read_coils;
typedef struct rrr_modbus_res_byte_count_and_status rrr_modbus_res_02_read_discrete_inputs;
typedef struct rrr_modbus_res_byte_count_and_status rrr_modbus_res_03_read_holding_registers;

struct rrr_modbus_res {
	uint8_t function_code;
	union {
		struct rrr_modbus_res_error error;
		rrr_modbus_res_01_read_coils               read_coils;
		rrr_modbus_res_02_read_discrete_inputs     read_discrete_inputs;
		rrr_modbus_res_03_read_holding_registers   read_holding_registers;
	};
} __attribute((__packed__));

struct rrr_modbus_frame {
	struct rrr_modbus_mbap mbap;
	union {
		struct rrr_modbus_req req;
		struct rrr_modbus_res res;
	};
} __attribute((__packed__));

struct rrr_modbus_client_transaction {
	uint16_t transaction_id;
	struct rrr_modbus_req req;
	rrr_length req_size;
	uint64_t transmit_time;
	void *transaction_private_data;
};

struct rrr_modbus_client {
	uint16_t transaction_id_pos;
	struct rrr_modbus_client_transaction transactions[RRR_MODBUS_CLIENT_TRANSACTION_MAX];
	uint16_t transaction_write_pos;
	uint16_t transaction_transmit_pos;
	struct rrr_modbus_client_callbacks callbacks;
};

static void __rrr_modbus_req_init (
		struct rrr_modbus_req *req,
		uint8_t function_code
) {
	memset(req, '\0', sizeof(*req));
	req->function_code = function_code;
}

static void __rrr_modbus_client_transaction_migrate (
		struct rrr_modbus_client_transaction *target,
		struct rrr_modbus_client_transaction *source
) {
	*target = *source;

	// Don't free private data in transaction, transfer ownership to target

	memset(source, '\0', sizeof(*source));
}

static void __rrr_modbus_client_transaction_reset (
		struct rrr_modbus_client *client,
		struct rrr_modbus_client_transaction *transaction
) {
	if (transaction->transaction_private_data == NULL)
		return;
	client->callbacks.cb_req_transaction_private_data_destroy(transaction->transaction_private_data);
	memset(transaction, '\0', sizeof(*transaction));
}

int rrr_modbus_client_new (
		struct rrr_modbus_client **target
) {
	int ret = 0;

	struct rrr_modbus_client *client;

	*target = NULL;

	if ((client = rrr_allocate_zero(sizeof(*client))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*target = client;

	out:
	return ret;
}

void rrr_modbus_client_destroy (
		struct rrr_modbus_client *client
) {
	for (int i = 0; i < RRR_MODBUS_CLIENT_TRANSACTION_MAX; i++) {
		struct rrr_modbus_client_transaction *transaction = &client->transactions[i];
		__rrr_modbus_client_transaction_reset(client, transaction);
	}
	
	rrr_free(client);
}

void rrr_modbus_client_callbacks_set (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_client_callbacks *callbacks
) {
	client->callbacks = *callbacks;
}

static int __rrr_modbus_client_transaction_find_and_consume (
		struct rrr_modbus_client_transaction *transaction,
		struct rrr_modbus_client *client,
		uint16_t transaction_id
) {
	for (int i = 0; i < RRR_MODBUS_CLIENT_TRANSACTION_MAX; i++) {
		struct rrr_modbus_client_transaction *transaction_check = &client->transactions[i];

		if (transaction_check->transmit_time == 0) {
			continue;
		}

		if (transaction_id == transaction_check->transaction_id) {
			__rrr_modbus_client_transaction_migrate(transaction, transaction_check);
			return 0;
		}
	}

	RRR_MSG_0("Transaction with id %d not found\n", transaction_id);

	return 1;
}

static int __rrr_modbus_client_receive_byte_count_and_status (
		struct rrr_modbus_client *client,
		uint8_t function_code,
		int is_register,
		const struct rrr_modbus_client_transaction *transaction,
		const struct rrr_modbus_res_byte_count_and_status *pdu,
		uint16_t pdu_size,
		int (*callback)(RRR_MODBUS_BYTE_COUNT_AND_COILS_CALLBACK_ARGS)
) {
	if (pdu->byte_count == 0) {
		RRR_MSG_0("Invalid size 0 of bytes field in %s\n",
			__func__);
		return RRR_MODBUS_SOFT_ERROR;
	}

	if (pdu->byte_count != pdu_size - 2) {
		RRR_MSG_0("Invalid size of bytes field %d<>%d in %s\n",
			pdu->byte_count, pdu_size - 2, __func__);
		return RRR_MODBUS_SOFT_ERROR;
	}

	const uint16_t expected_amount = rrr_be16toh(transaction->req.read_coils.amount);
	const uint16_t expected_bytes  = is_register
		? expected_amount * 2
		: (expected_amount + 7) / 8
	;

	if (pdu->byte_count != expected_bytes) {
		RRR_MSG_0("Unexpected size of bytes field %d<>%d for amount %d of %s in %s\n",
			pdu->byte_count,
			expected_bytes,
			expected_amount,
			(is_register ? "registers" : "coils"),
			__func__);
		return RRR_MODBUS_SOFT_ERROR;
	}

	if (callback == NULL) {
		RRR_BUG("Callback for function 0x%02x not set in %s\n", function_code, __func__);
	}

	return callback (
			function_code,
			transaction->transaction_id,
			pdu->byte_count,
			pdu->status,
			transaction->transaction_private_data,
			client->callbacks.arg
	);
}

static int __rrr_modbus_client_receive_01_read_coils (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_client_transaction *transaction,
		const rrr_modbus_res_01_read_coils *pdu,
		uint16_t pdu_size
) {
	return __rrr_modbus_client_receive_byte_count_and_status (
			client,
			RRR_MODBUS_FUNCTION_CODE_01_READ_COILS,
			0, /* Not register */
			transaction,
			pdu,
			pdu_size,
			client->callbacks.cb_res_01_read_coils
	);
}

static int __rrr_modbus_client_receive_02_read_discrete_inputs (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_client_transaction *transaction,
		const rrr_modbus_res_02_read_discrete_inputs *pdu,
		uint16_t pdu_size
) {
	return __rrr_modbus_client_receive_byte_count_and_status (
			client,
			RRR_MODBUS_FUNCTION_CODE_02_READ_DISCRETE_INPUTS,
			0, /* Not register */
			transaction,
			pdu,
			pdu_size,
			client->callbacks.cb_res_02_read_discrete_inputs
	);
}

static int __rrr_modbus_client_receive_03_read_holding_registers (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_client_transaction *transaction,
		const rrr_modbus_res_03_read_holding_registers *pdu,
		uint16_t pdu_size
) {
	return __rrr_modbus_client_receive_byte_count_and_status (
			client,
			RRR_MODBUS_FUNCTION_CODE_03_READ_HOLDING_REGISTERS,
			1, /* Is register */
			transaction,
			pdu,
			pdu_size,
			client->callbacks.cb_res_03_read_holding_registers
	);
}

#define VALIDATE_FRAME_SIZE(type)                                                                             \
    do {if (frame_size > sizeof(frame->mbap) + sizeof(frame->res.type) + sizeof(frame->res.function_code)) {  \
        RRR_MSG_0("Max frame size exceeded for received frame %" PRIrrrl ">%llu\n",                           \
	    frame_size, (unsigned long long) (sizeof(frame->mbap) + sizeof(frame->res.type)));                \
        return RRR_MODBUS_SOFT_ERROR;                                                                         \
    }} while(0)

#define VALIDATE_TRANSACTION_FUNCTION_CODE(code)                                       \
    do {if (code != transaction.req.function_code) {                                   \
        RRR_MSG_0("Function code mismatch for received frame %d<>%d\n",                \
            frame->res.function_code - 0x80, transaction.req.function_code);           \
        return RRR_MODBUS_SOFT_ERROR;                                                  \
    }} while(0)

static int __rrr_modbus_client_receive (
		struct rrr_modbus_client *client,
		struct rrr_modbus_frame *frame,
		rrr_length frame_size
) {
	int ret = RRR_MODBUS_OK;

	struct rrr_modbus_client_transaction transaction = {0};

	RRR_DBG_3("Receive frame of size %" PRIrrrl "\n", frame_size);

	if (__rrr_modbus_client_transaction_find_and_consume (
			&transaction,
			client,
			frame->mbap.transaction_identifier
	) != 0) {
		ret = RRR_MODBUS_SOFT_ERROR;
		goto out;
	}

	if (frame->res.function_code > 0x80) {
		VALIDATE_FRAME_SIZE(error);
		VALIDATE_TRANSACTION_FUNCTION_CODE(frame->res.function_code - 0x80);
		if (client->callbacks.cb_res_error == NULL) {
			RRR_BUG("Error callback not set in %s\n", __func__);
		}
		ret = client->callbacks.cb_res_error (
				transaction.transaction_id,
				frame->res.function_code - 0x80,
				frame->res.error.exception_code,
				transaction.transaction_private_data,
				client->callbacks.arg
		);
		goto out;
	}

	VALIDATE_TRANSACTION_FUNCTION_CODE(frame->res.function_code);

	const rrr_length pdu_size = frame_size - sizeof(frame->mbap);
	assert (pdu_size <= 0xfffe); /* Data length in mbap minus 1 byte for unit identifier */

	switch (frame->res.function_code) {
		case 0x01:
			VALIDATE_FRAME_SIZE(read_coils);
			ret = __rrr_modbus_client_receive_01_read_coils (client, &transaction, &frame->res.read_coils, (uint16_t) pdu_size);
			break;
		case 0x02:
			VALIDATE_FRAME_SIZE(read_discrete_inputs);
			ret = __rrr_modbus_client_receive_02_read_discrete_inputs (client, &transaction, &frame->res.read_discrete_inputs, (uint16_t) pdu_size);
			break;
		case 0x03:
			VALIDATE_FRAME_SIZE(read_holding_registers);
			ret = __rrr_modbus_client_receive_03_read_holding_registers (client, &transaction, &frame->res.read_holding_registers, (uint16_t) pdu_size);
			break;
		default:
			RRR_BUG("Function code %d not implemented in %s\n", frame->res.function_code, __func__);
	};

	if (ret != 0) {
		goto out;
	}

	out:
	__rrr_modbus_client_transaction_reset(client, &transaction);
	return ret;
}

int rrr_modbus_client_read (
		struct rrr_modbus_client *client,
		const uint8_t *data,
		rrr_length *data_size
) {
	int ret = 0;

	rrr_length data_pos = 0;
	struct rrr_modbus_frame frame;

	RRR_DBG_3("Read data of size %" PRIrrrl "\n", *data_size);

	if (RRR_DEBUGLEVEL_6) {
		struct rrr_string_builder string = {0};
		for (size_t i = 0; i < *data_size; i++) {
			if (i % 16 == 0) {
				rrr_string_builder_append_format(&string, "\n   ");
			}
			rrr_string_builder_append_format(&string, " 0x%02x", data[i]);
		}
		RRR_DBG_6("Read data of size %" PRIrrrl ":%s\n", *data_size, rrr_string_builder_buf(&string));
		rrr_string_builder_clear(&string);
	}

	if (*data_size < sizeof(frame.mbap)) {
		ret = RRR_MODBUS_INCOMPLETE;
		goto out;
	}

	memcpy(&frame.mbap, data, sizeof(frame.mbap));

	frame.mbap.transaction_identifier = rrr_be16toh(frame.mbap.transaction_identifier);
	frame.mbap.protocol_identifier = rrr_be16toh(frame.mbap.protocol_identifier);
	frame.mbap.length = rrr_be16toh(frame.mbap.length);
	data_pos += 6;

	const rrr_length frame_size = data_pos + frame.mbap.length;

	if (frame.mbap.length < 1) {
		RRR_MSG_0("Received frame with zero in length field\n");
		ret = RRR_MODBUS_SOFT_ERROR;
		goto out;
	}

	if (*data_size < frame_size) {
		ret = RRR_MODBUS_INCOMPLETE;
		goto out;
	}

	// Unit identifier (value ignored)
	data_pos += 1;

	const rrr_length pdu_size = frame_size - data_pos;

	if (pdu_size < 1) {
		RRR_MSG_0("Received frame with zero PDU length\n");
		ret = RRR_MODBUS_SOFT_ERROR;
		goto out;
	}

	if (pdu_size > sizeof(frame.res)) {
		RRR_MSG_0("Received PDU frame exceeding maximum length\n");
		ret = RRR_MODBUS_SOFT_ERROR;
		goto out;
	}

	memcpy(&frame.res, data + data_pos, pdu_size);

	if ((ret = __rrr_modbus_client_receive (client, &frame, frame_size)) != RRR_MODBUS_OK) {
		goto out;
	}

	data_pos += pdu_size;
	assert(frame_size == data_pos);

	*data_size = data_pos;

	out:
	return ret;
}

int rrr_modbus_client_write (
		struct rrr_modbus_client *client,
		uint8_t *data,
		rrr_length *data_size
) {
	int ret = RRR_MODBUS_OK;

	struct rrr_modbus_frame frame = {0};
	struct rrr_modbus_client_transaction *transaction = &client->transactions[client->transaction_transmit_pos];

	if (transaction->req_size == 0 || transaction->transmit_time != 0) {
		ret = RRR_MODBUS_DONE;
		goto out;
	}

	RRR_DBG_3("Transmitting transaction %d function code %d from position %d\n",
			transaction->transaction_id, transaction->req.function_code, client->transaction_transmit_pos);
	
	const rrr_biglength frame_mbap_length = transaction->req_size + sizeof(frame.mbap.unit_identifier);
	assert(frame_mbap_length <= 0xffff && frame_mbap_length > 1);

	frame.mbap.transaction_identifier = rrr_htobe16(transaction->transaction_id);
	frame.mbap.protocol_identifier = rrr_htobe16(0);
	frame.mbap.length = rrr_htobe16((uint16_t) frame_mbap_length);
	frame.mbap.unit_identifier = 0xff;

	rrr_biglength size_total = sizeof(frame.mbap) + transaction->req_size;
	assert (size_total <= *data_size);

	memcpy(data, &frame.mbap, sizeof(frame.mbap));
	memcpy(data + sizeof(frame.mbap), &transaction->req, transaction->req_size);
	*data_size = (rrr_length) size_total;

	client->transaction_transmit_pos++;
	if (client->transaction_transmit_pos == RRR_MODBUS_CLIENT_TRANSACTION_MAX) {
		client->transaction_transmit_pos = 0;
	}

	transaction->transmit_time = rrr_time_get_64();

	out:
	return ret;
}

static int __rrr_modbus_client_transaction_reserve (
		uint16_t *transaction_write_pos,
		struct rrr_modbus_client *client
) {
	int ret = 0;

	const struct rrr_modbus_client_transaction *transaction = &client->transactions[client->transaction_write_pos];
	if (transaction->req_size > 0) {
		if (transaction->transmit_time > 0 &&
		    transaction->transmit_time < rrr_time_get_64() - RRR_MODBUS_CLIENT_TRANSACTION_TIMEOUT_S * 1000 * 1000
		) {
			uint64_t time_since_transmit_ms = (rrr_time_get_64() - transaction->transmit_time) / 1000;
			RRR_MSG_0("Modbus client transaction timeout for function code %d transaction id %u. No response from server within %" PRIu64 " ms while the limit is %d s.\n",
					transaction->req.function_code,
					transaction->transaction_id,
					time_since_transmit_ms,
					RRR_MODBUS_CLIENT_TRANSACTION_TIMEOUT_S
			);
			ret = RRR_MODBUS_SOFT_ERROR;
			goto out;
		}

		ret = RRR_MODBUS_BUSY;
		goto out;
	}

	*transaction_write_pos = client->transaction_write_pos++;
	if (client->transaction_write_pos == RRR_MODBUS_CLIENT_TRANSACTION_MAX) {
		client->transaction_write_pos = 0;
	}

	out:
	return ret;
}

static int __rrr_modbus_client_req_push (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_req *req,
		rrr_length req_size,
		void *private_data_arg
) {
	int ret = 0;

	uint16_t transaction_write_pos;
	void *transaction_private_data;

	if ((ret = client->callbacks.cb_req_transaction_private_data_create (
			&transaction_private_data,
			private_data_arg,
			client->callbacks.arg
	)) != 0) {
		goto out;
	}

	if ((ret = __rrr_modbus_client_transaction_reserve (&transaction_write_pos, client)) != 0) {
		goto out_destroy_transaction_private_data;
	}

	struct rrr_modbus_client_transaction *transaction = &client->transactions[transaction_write_pos];

	transaction->transaction_id = client->transaction_id_pos++;
	transaction->req = *req;
	transaction->req_size = req_size;
	transaction->transmit_time = 0;
	transaction->transaction_private_data = transaction_private_data;

	RRR_DBG_3("Pushed transaction %d function code %d to position %d\n",
			transaction->transaction_id, transaction->req.function_code, transaction_write_pos);

	goto out;
	out_destroy_transaction_private_data:
		client->callbacks.cb_req_transaction_private_data_destroy(transaction_private_data);
	out:
		return ret;
}

static int __rrr_modbus_client_req_address_and_amount (
		struct rrr_modbus_client *client,
		uint8_t function_code,
		uint16_t starting_address,
		uint16_t amount,
		void *private_data_arg
) {
	struct rrr_modbus_req req;

	__rrr_modbus_req_init (&req, function_code);

	req.read_coils.starting_address = rrr_htobe16(starting_address);
	req.read_coils.amount = rrr_htobe16(amount);

	return __rrr_modbus_client_req_push(client, &req, RRR_MODBUS_REQ_SIZE(req.read_coils), private_data_arg);
}

int rrr_modbus_client_req_01_read_coils (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_coils,
		void *private_data_arg
) {
	assert(quantity_of_coils >= 1 && quantity_of_coils <= 2000);

	return __rrr_modbus_client_req_address_and_amount (
			client,
			RRR_MODBUS_FUNCTION_CODE_01_READ_COILS,
			starting_address,
			quantity_of_coils,
			private_data_arg
	);
}

int rrr_modbus_client_req_02_read_discrete_inputs (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_coils,
		void *private_data_arg
) {
	assert(quantity_of_coils >= 1 && quantity_of_coils <= 2000);

	return __rrr_modbus_client_req_address_and_amount (
			client,
			RRR_MODBUS_FUNCTION_CODE_02_READ_DISCRETE_INPUTS,
			starting_address,
			quantity_of_coils,
			private_data_arg
	);
}

int rrr_modbus_client_req_03_read_holding_registers (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_registers,
		void *private_data_arg
) {
	assert(quantity_of_registers >= 1 && quantity_of_registers <= 125);

	return __rrr_modbus_client_req_address_and_amount (
			client,
			RRR_MODBUS_FUNCTION_CODE_03_READ_HOLDING_REGISTERS,
			starting_address,
			quantity_of_registers,
			private_data_arg
	);
}
