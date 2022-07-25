/*

Read Route Record

Copyright (C) 2020-2022 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_STREAM_H
#define RRR_HTTP_STREAM_H

#include <stdlib.h>
#include "../map.h"
#include "http_header_fields.h"

// Blocks of 64, maximum number of concurrent streams
#define RRR_HTTP_STREAM_BLOCKS 3
#define RRR_HTTP_STREAM_MAX (RRR_HTTP_STREAM_BLOCKS * 64)

struct rrr_http_stream {
	struct rrr_http_header_field_collection headers;
	void *data;
	size_t data_size;
	size_t data_wpos;
	void *application_data;

	// Submit data frame on next before_frame_send_callback
	int data_submission_requested;

	void (*application_data_destroy_function)(void *);
	struct rrr_map headers_to_send;

	uint64_t creation_time;
};

struct rrr_http_stream_collection {
	struct rrr_http_stream streams[RRR_HTTP_STREAM_BLOCKS * 64];
	int64_t stream_ids[RRR_HTTP_STREAM_BLOCKS * 64];
	uint64_t active_flags[RRR_HTTP_STREAM_BLOCKS];
	uint64_t delete_me_flags[RRR_HTTP_STREAM_BLOCKS];
	uint64_t stream_count;
};

void rrr_http_stream_collection_destroy (
		struct rrr_http_stream_collection *collection
);
void rrr_http_stream_collection_maintain (
		unsigned int *closed_stream_count,
		struct rrr_http_stream_collection *collection
);
void rrr_http_stream_collection_delete_me_set (
		struct rrr_http_stream_collection *collection,
		int64_t stream_id
);
struct rrr_http_stream *rrr_http_stream_collection_find (
		struct rrr_http_stream_collection *collection,
		int64_t stream_id
);
struct rrr_http_stream *rrr_http_stream_collection_find_or_create (
		struct rrr_http_stream_collection *collection,
		int64_t stream_id
);
int rrr_http_stream_data_push (
		struct rrr_http_stream *target,
		const char *data,
		size_t data_size
);
int rrr_http_stream_collection_iterate (
		struct rrr_http_stream_collection *collection,
		int (*callback)(int64_t stream_id, void *application_data, void *arg),
		void *callback_arg
);

#endif /* RRR_HTTP_STREAM_H */
