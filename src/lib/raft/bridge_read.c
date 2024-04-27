/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "bridge.h"
#include "bridge_read.h"
#include "bridge_enc.h"
#include "bridge_ack.h"

#include "../log.h"
#include "../rrr_types.h"
#include "../util/rrr_endian.h"
#include "../util/rrr_time.h"

static ssize_t __rrr_raft_bridge_read_process_header (
		uint8_t *type,
		uint8_t *version,
		size_t *header_pos,
		size_t *payload_pos,
		size_t *end_pos,
		struct rrr_raft_bridge *bridge,
		const char *data,
		size_t data_size
) {
	ssize_t bytes = 0;

	uint64_t preamble0, preamble1_header_size;
	uint64_t target_size, payload_size;

	if (data_size < sizeof(uint64_t) * 2) {
		goto out;
	}

	preamble0 = rrr_le64toh(* (uint64_t *) (data));
	preamble1_header_size = rrr_le64toh(* (uint64_t *) (data + sizeof(uint64_t)));

	printf("Header size is %" PRIrrrbl "\n", preamble1_header_size);

	if (preamble1_header_size == 0) {
		RRR_RAFT_BRIDGE_ERR("RPC had zero header size\n");
		bytes = -RRR_RAFT_READ_SOFT_ERROR;
		goto out;
	}

	target_size = sizeof(uint64_t) * 2;
	*header_pos = rrr_size_from_biglength_bug_const(target_size);

	target_size += preamble1_header_size;
	*payload_pos = rrr_size_from_biglength_bug_const(target_size);

	if (target_size < preamble1_header_size) {
		RRR_RAFT_BRIDGE_ERR("Target size overflow in preamble of RPC\n");
		bytes = -RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (target_size > data_size) {
		goto out;
	}

	/* For backwards compatibility in C-raft, the second
	 * byte for the type is currently not used. */
	*type = (uint8_t) preamble0;           /* Byte 0 */
	*version = (uint8_t)(preamble0 >> 16); /* Byte 2 */

	printf("Type is %u version is %u\n", *type, *version);

	switch (*type) {
		case RAFT_REQUEST_VOTE:
		case RAFT_REQUEST_VOTE_RESULT:
		case RAFT_APPEND_ENTRIES_RESULT:
		case RAFT_TIMEOUT_NOW:
			payload_size = 0;
			break;
		case RAFT_APPEND_ENTRIES:
		case RAFT_INSTALL_SNAPSHOT:
			assert(0 && "RPC with payload not implemented");
			payload_size = 0;
			break;
		default:
			RRR_RAFT_BRIDGE_ERR_ARGS("RPC had unknown type %u\n", *type);
			bytes = -RRR_RAFT_READ_SOFT_ERROR;
			goto out;
	};

	target_size += payload_size;
	*end_pos = rrr_size_from_biglength_bug_const(target_size);

	if (target_size < payload_size || target_size > SSIZE_MAX) {
		RRR_RAFT_BRIDGE_ERR("Target size overflow in RPC\n");
		bytes = -RRR_READ_SOFT_ERROR;
		goto out;
	}

	bytes = target_size;

	out:
	return bytes;
}

ssize_t rrr_raft_bridge_read (
		struct rrr_raft_bridge *bridge,
		raft_id server_id,
		const char *server_address,
		const char *data,
		size_t data_size
) {
	ssize_t bytes = 0;

	uint8_t type, version;
	size_t header_pos, payload_pos, end_pos;
	struct raft_message message;
	struct raft_event event;

	if ((bytes = __rrr_raft_bridge_read_process_header (
			&type,
			&version,
			&header_pos,
			&payload_pos,
			&end_pos,
			bridge,
			data,
			data_size
	)) <= 0) {
		goto out;
	}

	switch (type) {
		case RAFT_APPEND_ENTRIES:
			assert(0 && "Append entries not implemented\n");
			break;
		case RAFT_APPEND_ENTRIES_RESULT:
			assert(0 && "Append entries result not implemented\n");
			break;
		case RAFT_REQUEST_VOTE:
			if (!rrr_raft_bridge_decode_request_vote_size_ok (
					version,
					payload_pos - header_pos
			)) {
				RRR_RAFT_BRIDGE_ERR("Incorrect version or size for request vote RPC\n");
				bytes = -RRR_READ_SOFT_ERROR;
				goto out;
			}

			if (rrr_raft_bridge_decode_request_vote (
					&message.request_vote,
					data + header_pos,
					payload_pos - header_pos
			) != 0) {
				RRR_RAFT_BRIDGE_ERR("Incorrect data for request vote RPC\n");
				bytes = -RRR_READ_SOFT_ERROR;
				goto out;
			}

			break;
		case RAFT_REQUEST_VOTE_RESULT:
			assert(0 && "Request vote result not implemented\n");
			break;
		case RAFT_INSTALL_SNAPSHOT:
			assert(0 && "Install snapshot not implemented\n");
			break;
		case RAFT_TIMEOUT_NOW:
			assert(0 && "Timeout now not implemented\n");
			break;
		default:
			RRR_BUG("BUG: Type %u not implemented in %s\n", type, __func__);
	};

	message.type = type;
	message.server_id = server_id;
	message.server_address = server_address;

	event.type = RAFT_RECEIVE;
	event.time = RRR_RAFT_TIME_MS();
	event.receive.message = &message;

	if (rrr_raft_bridge_ack_step(bridge, &event) != 0) {
		bytes = -RRR_READ_HARD_ERROR;
		goto out;
	}

	out:
	return bytes;
}
