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
#include "bridge_handshake.h"

#include "../log.h"
#include "../allocator.h"
#include "../util/rrr_endian.h"

static ssize_t __rrr_raft_bridge_handshake_decode (
		uint64_t *protocol,
		uint64_t *server_id,
		uint64_t *address_size,
		const char *handshake,
		size_t handshake_size
) {
	uint64_t preamble[3];

	if (handshake_size < sizeof(preamble)) {
		return 0;
	}

	preamble[0] = rrr_le64toh(* (uint64_t *) (handshake + sizeof(uint64_t) * 0));
	preamble[1] = rrr_le64toh(* (uint64_t *) (handshake + sizeof(uint64_t) * 1));
	preamble[2] = rrr_le64toh(* (uint64_t *) (handshake + sizeof(uint64_t) * 2));

	*protocol = preamble[0];
	*server_id = preamble[1];
	*address_size = preamble[2];

	return sizeof(preamble);
}

ssize_t rrr_raft_bridge_handshake_read (
		raft_id *server_id_result,
		char **server_address,
		size_t *server_address_length,
		struct rrr_raft_bridge *bridge,
		const char *data,
		size_t data_size
) {
	ssize_t bytes = 0;

	uint64_t protocol, address_size, server_id;
	size_t bytes_u;

	if ((bytes = __rrr_raft_bridge_handshake_decode (
			&protocol,
			&server_id,
			&address_size,
			data,
			data_size
	)) <= 0) {
		goto out;
	}

	if (protocol != RRR_RAFT_RPC_PROTOCOL) {
		RRR_RAFT_BRIDGE_ERR_ARGS("Unsupported protocol version %" PRIu64 " in handshake\n", protocol);
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	if (server_id == 0) {
		RRR_RAFT_BRIDGE_ERR("Server ID was 0 in handshake\n");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	if (address_size == 0) {
		RRR_RAFT_BRIDGE_ERR("Address size was 0 in handshake\n");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	if (address_size > SIZE_MAX) {
		RRR_RAFT_BRIDGE_ERR("Address size overflow in handshake\n");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	if (data_size < bytes + address_size) {
		bytes = 0;
		goto out;
	}

	if ((*server_address = rrr_allocate(rrr_size_from_biglength_bug_const(address_size))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		bytes = -RRR_RAFT_HARD_ERROR;
		goto out;
	}

	memcpy(*server_address, data + bytes, address_size);

	bytes_u = bytes + address_size;

	if (bytes_u < address_size || bytes_u > SSIZE_MAX) {
		RRR_RAFT_BRIDGE_ERR("Size overflow in handshake\n");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	bytes = (ssize_t) bytes_u;

	if ((*server_id_result = server_id) != server_id) {
		RRR_RAFT_BRIDGE_ERR("Server ID overflow in handshake\n");
		bytes = -RRR_RAFT_SOFT_ERROR;
		goto out;
	}

	*server_address_length = (size_t) address_size;

	out:
	return bytes;
}

int rrr_raft_handshake_write (
		char **handshake,
		size_t *handshake_size,
		struct rrr_raft_bridge *bridge
) {
	int ret = 0;

	char *buf;
	size_t total_size;
	const char *server_address;
	size_t server_address_length;

	assert(bridge->server_id > 0);
	server_address = rrr_raft_bridge_configuration_server_name_get(bridge, bridge->server_id);
	assert(server_address != NULL);
	server_address_length = strlen(server_address);

	if ((total_size = sizeof(uint64_t) * 3 + server_address_length) < server_address_length) {
		RRR_RAFT_BRIDGE_ERR("Overflow while writing handshake\n");
		ret = 1;
		goto out;
	}

	if ((buf = rrr_allocate(total_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	* (uint64_t *) (buf + sizeof(uint64_t) * 0) = rrr_htole64(RRR_RAFT_RPC_PROTOCOL);
	* (uint64_t *) (buf + sizeof(uint64_t) * 1) = rrr_htole64(bridge->server_id);
	* (uint64_t *) (buf + sizeof(uint64_t) * 2) = rrr_htole64(server_address_length);

	memcpy(buf + sizeof(uint64_t) * 3, server_address, server_address_length);

	*handshake = buf;
	*handshake_size = total_size;

	out:
	return ret;
}
