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

#define RRR_MODBUS_CLIENT_TRANSACTION_MAX 32
#define RRR_MODBUS_CLIENT_TRANSACTION_TIMEOUT_S 1

#define RRR_MODBUS_FUNCTION_CODE_01_READ_COILS      0x01

struct rrr_modbus_mbap {
	uint16_t transaction_identifier;
	uint16_t protocol_identifier;
	uint16_t length;
	uint8_t unit_identifier;
} __attribute((__packed__));

struct rrr_modbus_req {
	uint8_t function_code;
	union {
		struct rrr_modbus_req_01_read_coils req_01_read_coils;
	};
} __attribute((__packed__));

#define RRR_MODBUS_REQ_SIZE(function) (sizeof(function) + 1)

struct rrr_modbus_res {
	uint8_t function_code;
	union {
		struct rrr_modbus_res_error error;
		struct rrr_modbus_res_01_read_coils res_01_read_coils;
	};
} __attribute((__packed__));

struct rrr_modbus_frame {
	struct rrr_modbus_mbap mbap;
	union {
		struct rrr_modbus_req req;
		struct rrr_modbus_res res;
	};
} __attribute((__packed__));

struct rrr_modbus_server {
	uint8_t dummy;
};

struct rrr_modbus_client_transaction {
	uint16_t transaction_id;
	struct rrr_modbus_req req;
	rrr_length req_size;
	uint64_t transmit_time;
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
		struct rrr_modbus_client *target
) {
	rrr_free(target);
}

void rrr_modbus_client_callbacks_set (
		struct rrr_modbus_client *client,
		const struct rrr_modbus_client_callbacks *callbacks
) {
	client->callbacks = *callbacks;
}

int rrr_modbus_client_read (
		struct rrr_modbus_client *client,
		const uint8_t data,
		rrr_length data_size
) {
}

int rrr_modbus_client_write (
		struct rrr_modbus_client *client,
		uint8_t *data,
		rrr_length *data_size
) {
	int ret = RRR_MODBUS_OK;

	struct rrr_modbus_frame frame = {0};
	const struct rrr_modbus_client_transaction *transaction = &client->transactions[client->transaction_transmit_pos];

	if (transaction->req_size == 0) {
		ret = RRR_MODBUS_DONE;
		goto out;
	}

	assert(transaction->transmit_time == 0);

	frame.mbap.transaction_identifier = rrr_htobe16(transaction->transaction_id);
	frame.mbap.protocol_identifier = rrr_htobe16(0);
	frame.mbap.length = rrr_htobe16(transaction->req_size + sizeof(frame.mbap.unit_identifier));
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

	out:
	return ret;
}

static int __rrr_modbus_client_transaction_reserve (
		uint8_t *transaction_write_pos,
		struct rrr_modbus_client *client
) {
	int ret = 0;

	const struct rrr_modbus_client_transaction *transaction = &client->transactions[client->transaction_write_pos];
	if (transaction->req_size > 0) {
		if (transaction->transmit_time > 0 &&
		    transaction->transmit_time < rrr_time_get_64() - RRR_MODBUS_CLIENT_TRANSACTION_TIMEOUT_S * 1000 * 1000
		) {
			RRR_MSG_0("Modbus client transaction timeout for function code %d transaction id %s. No response from server within %d seconds.\n",
					transaction->req.function_code,
					transaction->transaction_id,
					RRR_MODBUS_CLIENT_TRANSACTION_TIMEOUT_S
			);
			ret = RRR_MODBUS_HARD_ERROR;
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
		rrr_length req_size
) {
	int ret = 0;

	uint8_t transaction_write_pos;

	if ((ret = __rrr_modbus_client_transaction_reserve (&transaction_write_pos, client)) != 0) {
		goto out;
	}

	struct rrr_modbus_client_transaction *transaction = &client->transactions[transaction_write_pos];

	transaction->transaction_id = client->transaction_id_pos++;
	transaction->req = *req;
	transaction->req_size = req_size;
	transaction->transmit_time = 0;

	RRR_DBG_3("Pushed transaction %d function code %d to position %d\n",
			transaction->transaction_id, transaction->req.function_code, transaction_write_pos);

	out:
	return ret;
}

int rrr_modbus_client_req_01_read_coils (
		struct rrr_modbus_client *client,
		uint16_t starting_address,
		uint16_t quantity_of_coils
) {
	struct rrr_modbus_req req;

	__rrr_modbus_req_init (&req, RRR_MODBUS_FUNCTION_CODE_01_READ_COILS);

	req.req_01_read_coils.starting_address = rrr_htobe16(starting_address);
	req.req_01_read_coils.quantity_of_coils = rrr_htobe16(quantity_of_coils);

	return __rrr_modbus_client_req_push(client, &req, RRR_MODBUS_REQ_SIZE(req.req_01_read_coils));
}

int rrr_modbus_server_new (struct rrr_modbus_server **target) {
	int ret = 0;

	struct rrr_modbus_server *server;

	*target = NULL;

	if ((server = rrr_allocate_zero(sizeof(*server)) == NULL)) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*target = server;

	out:
	return ret;
}

void rrr_modbus_server_destroy (struct rrr_modbus_server *target) {
	rrr_free(target);
}

