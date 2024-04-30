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
#include "../allocator.h"
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
	int ret_tmp;

	/* Initialize due to scan build warnings */
	*header_pos = 0;
	*payload_pos = 0;
	*end_pos = 0;

	if (data_size < sizeof(uint64_t) * 2) {
		goto out;
	}

	preamble0 = rrr_le64toh(* (uint64_t *) (data));
	preamble1_header_size = rrr_le64toh(* (uint64_t *) (data + sizeof(uint64_t)));

	RRR_RAFT_BRIDGE_DBG_ARGS("Processing header of size is %" PRIrrrbl, preamble1_header_size);

	if (preamble1_header_size == 0) {
		RRR_RAFT_BRIDGE_ERR("RPC had zero header size");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	if (preamble1_header_size > SIZE_MAX) {
		RRR_RAFT_BRIDGE_ERR("RPC had too big header size");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	target_size = sizeof(uint64_t) * 2;
	*header_pos = rrr_size_from_biglength_bug_const(target_size);

	target_size += preamble1_header_size;
	*payload_pos = rrr_size_from_biglength_bug_const(target_size);

	if (target_size < preamble1_header_size) {
		RRR_RAFT_BRIDGE_ERR("Target size overflow in preamble of RPC");
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

	RRR_RAFT_BRIDGE_DBG_ARGS("Processing header of type %u version is %u", *type, *version);

	switch (*type) {
		case RAFT_REQUEST_VOTE:
			if ((ret_tmp = rrr_raft_bridge_decode_request_vote_size_check (
					*version,
					*payload_pos - *header_pos
			)) != 0) {
				bytes = -ret_tmp;
				goto out;
			}
			payload_size = 0;
			break;
		case RAFT_REQUEST_VOTE_RESULT:
			if ((ret_tmp = rrr_raft_bridge_decode_request_vote_result_size_check (
					*version,
					*payload_pos - *header_pos
			)) != 0) {
				bytes = -ret_tmp;
				goto out;
			}
			payload_size = 0;
			break;
		case RAFT_TIMEOUT_NOW:
			assert(0 && "Timeout now not implemented");
			break;
		case RAFT_APPEND_ENTRIES:
			if ((ret_tmp = rrr_raft_bridge_decode_append_entries_size_check (
					*version,
					&payload_size,
					data + *header_pos,
					*payload_pos - *header_pos
			)) != 0) {
				bytes = -ret_tmp;
				goto out;
			}
			break;
		case RAFT_APPEND_ENTRIES_RESULT:
			if ((ret_tmp = rrr_raft_bridge_decode_append_entries_result_size_check (
					*version,
					*payload_pos - *header_pos
			)) != 0) {
				bytes = -ret_tmp;
				goto out;
			}
			payload_size = 0;
			break;
		case RAFT_INSTALL_SNAPSHOT:
			assert(0 && "install snapshot not implemented");
			payload_size = 0;
			break;
		default:
			RRR_RAFT_BRIDGE_ERR_ARGS("RPC had unknown type %u", *type);
			bytes = -RRR_RAFT_SOFT_ERROR;
			goto out;
	};

	target_size += payload_size;
	*end_pos = rrr_size_from_biglength_bug_const(target_size);

	if (data_size < *end_pos) {
		goto out;
	}

	if (target_size < payload_size || target_size > SSIZE_MAX) {
		RRR_RAFT_BRIDGE_ERR("Target size overflow in RPC");
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

	RRR_RAFT_BRIDGE_DBG_ARGS("Positions: header %llu payload %llu end %llu. Data size: %llu",
		(unsigned long long) header_pos,
		(unsigned long long) payload_pos,
		(unsigned long long) end_pos,
		(unsigned long long) data_size
	);

	switch (type) {
		case RAFT_APPEND_ENTRIES:
			if (rrr_raft_bridge_decode_append_entries (
					&message.append_entries,
					data + header_pos,
					payload_pos - header_pos,
					end_pos - payload_pos
			) != 0) {
				RRR_RAFT_BRIDGE_ERR("Incorrect data for append entries RPC");
				bytes = -RRR_READ_SOFT_ERROR;
				goto out;
			}

			RRR_RAFT_BRIDGE_DBG_ARGS("AE[%llu] t %llu pli %llu plt %llu lc %llu ne %llu",
				(unsigned long long) server_id,
				(unsigned long long) message.append_entries.term,
				(unsigned long long) message.append_entries.prev_log_index,
				(unsigned long long) message.append_entries.prev_log_term,
				(unsigned long long) message.append_entries.leader_commit,
				(unsigned long long) message.append_entries.n_entries
			);

			assert(message.append_entries.n_entries == 0 && "Entries >0 not implemented");

			break;
		case RAFT_APPEND_ENTRIES_RESULT:
			if (rrr_raft_bridge_decode_append_entries_result (
					&message.append_entries_result,
					data + header_pos,
					payload_pos - header_pos
			) != 0) {
				RRR_RAFT_BRIDGE_ERR("Incorrect data for append entries result RPC");
				bytes = -RRR_READ_SOFT_ERROR;
				goto out;
			}

			RRR_RAFT_BRIDGE_DBG_ARGS("AER[%llu] t %llu r %llu lli %llu f %llu c %llu",
				(unsigned long long) server_id,
				(unsigned long long) message.append_entries_result.term,
				(unsigned long long) message.append_entries_result.rejected,
				(unsigned long long) message.append_entries_result.last_log_index,
				(unsigned long long) message.append_entries_result.features,
				(unsigned long long) message.append_entries_result.capacity
			);

			break;
		case RAFT_REQUEST_VOTE:
			if (rrr_raft_bridge_decode_request_vote (
					&message.request_vote,
					data + header_pos,
					payload_pos - header_pos
			) != 0) {
				RRR_RAFT_BRIDGE_ERR("Incorrect data for request vote RPC");
				bytes = -RRR_READ_SOFT_ERROR;
				goto out;
			}

			RRR_RAFT_BRIDGE_DBG_ARGS("RV[%llu] t %llu ci %llu lli %llu llt %llu dl %i pv %i",
				(unsigned long long) server_id,
				(unsigned long long) message.request_vote.term,
				(unsigned long long) message.request_vote.candidate_id,
				(unsigned long long) message.request_vote.last_log_index,
				(unsigned long long) message.request_vote.last_log_term,
				message.request_vote.disrupt_leader,
				message.request_vote.pre_vote
			);

			break;
		case RAFT_REQUEST_VOTE_RESULT:
			if (rrr_raft_bridge_decode_request_vote_result (
					&message.request_vote_result,
					data + header_pos,
					payload_pos - header_pos
			) != 0) {
				RRR_RAFT_BRIDGE_ERR("Incorrect data for request vote result RPC");
				bytes = -RRR_READ_SOFT_ERROR;
				goto out;
			}

			RRR_RAFT_BRIDGE_DBG_ARGS("RVR[%llu] t %llu vg %i pv %i f %u c %u",
				(unsigned long long) server_id,
				(unsigned long long) message.request_vote_result.term,
				message.request_vote_result.vote_granted,
				message.request_vote_result.pre_vote,
				message.request_vote_result.features,
				message.request_vote_result.capacity
			);

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
	event.capacity = 1; /* TODO : Not implemented */
	event.receive.message = &message;

	if (rrr_raft_bridge_ack_step(bridge, &event) != 0) {
		bytes = -RRR_RAFT_HARD_ERROR;
		goto out;
	}

	out:
	return bytes;
}
