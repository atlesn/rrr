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

#ifndef RRR_RAFT_BRIDGE_ENC_H
#define RRR_RAFT_BRIDGE_ENC_H

/*
 * ENCODING FUNCTIONS
 */
int rrr_raft_bridge_encode_configuration (
		char **data,
		size_t *data_size,
		const struct raft_configuration *conf
);
void rrr_raft_bridge_encode_metadata (
		uint64_t data[4],
		const struct rrr_raft_bridge_metadata *metadata
);
int rrr_raft_bridge_encode_entries (
		char **data,
		size_t *data_size,
		size_t preamble_size,
		const struct raft_entry *entries,
		unsigned entry_count
);
int rrr_raft_bridge_encode_closed_segment (
		char **data,
		size_t *data_size,
		const char *conf,
		size_t conf_size,
		raft_term conf_term
);
size_t rrr_raft_bridge_encode_message_get_size (
		enum raft_message_type type
);
void rrr_raft_bridge_encode_message_request_vote (
		void *data,
		size_t data_size,
		const struct raft_request_vote *msg
);

/*
 * DECODING FUNCTIONS
 */
int rrr_raft_bridge_decode_metadata_size_ok (
		size_t data_size
);
void rrr_raft_bridge_decode_metadata (
		int *ok,
		struct rrr_raft_bridge_metadata *metadata,
		const char *data,
		size_t data_size
);

#endif /* RRR_RAFT_BRIDGE_ENC_H */
