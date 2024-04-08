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

#include "message_store.h"
#include "common.h"

#include "../array.h"
#include "../allocator.h"
#include "../util/rrr_endian.h"

const char *rrr_raft_reasons[] = {
	"OK",
	"ERROR",
	"NOT LEADER",
	"NOT FOUND"
};

const char *rrr_raft_reason_to_str (
		enum rrr_raft_code code
) {
	assert(code < sizeof(rrr_raft_reasons)/sizeof(*rrr_raft_reasons));
	return rrr_raft_reasons[code];
}

int rrr_raft_opt_array_field_server_get (
		struct rrr_raft_server **result,
		const struct rrr_array *array
) {
	int ret = 0;

	struct rrr_raft_server *servers, *server;
	int servers_count, i;
	const struct rrr_type_value *value;

	*result = NULL;

	if ((servers_count = rrr_array_value_count_tag(array, RRR_RAFT_FIELD_SERVER)) > 0) {
		if ((servers = rrr_allocate_zero(sizeof(*servers) * (servers_count + 1))) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}

		for (i = 0; i < servers_count; i++) {
			server = &servers[i];

			value = rrr_array_value_get_by_tag_and_index_const (
					array,
					RRR_RAFT_FIELD_SERVER,
					i
			);

			assert(value != NULL);
			assert(value->total_stored_length == sizeof(*server));

			memcpy(server, value->data, sizeof(*server));

			* (uint64_t *) &servers[i].id       = rrr_be64toh(* (uint64_t *) &servers[i].id);
			* (uint64_t *) &servers[i].catch_up = rrr_be64toh(* (uint64_t *) &servers[i].catch_up);

			assert(server->address[0] != '\0');
		}

		*result = servers;
	}

	out:
	return ret;
}

int rrr_raft_opt_array_field_server_push (
		struct rrr_array *array,
		const struct rrr_raft_server *server
) {
	int ret = 0;

	struct rrr_raft_server server_tmp = *server;
	void *data = &server_tmp;
	size_t data_size = sizeof(server_tmp);

	* (uint64_t *) &server_tmp.id       = rrr_htobe64(* (uint64_t *) &server_tmp.id);
	* (uint64_t *) &server_tmp.catch_up = rrr_htobe64(* (uint64_t *) &server_tmp.catch_up);

	if ((ret = rrr_array_push_value_blob_with_tag_with_size (
			array,
			RRR_RAFT_FIELD_SERVER,
			data,
			data_size
	)) != 0) {
		goto out;
	}

	out:
	return ret;
}
