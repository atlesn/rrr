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

#include "http_stream.h"

#include "../allocator.h"
#include "../util/rrr_time.h"

#define RRR_HTTP_STREAM_GROUP(idx) \
	((idx & 0xffffffffffffffc0) >> 6)

#define RRR_HTTP_STREAM_MASK(idx) \
	((uint64_t) 1 << idx)

#define RRR_HTTP_STREAMS_ITERATE_BEGIN()                                         \
	do { for (uint64_t i = 0; i < RRR_HTTP_STREAM_BLOCKS * 64; i++) {        \
		uint64_t group = RRR_HTTP_STREAM_GROUP(i);                       \
		uint64_t mask = RRR_HTTP_STREAM_MASK(i);                         \
		struct rrr_http_stream *node = &collection->streams[i];          \
		(void)(group); (void)(mask); (void)(node)

#define RRR_HTTP_STREAMS_ITERATE_DELETE_ME_BEGIN()                               \
	RRR_HTTP_STREAMS_ITERATE_BEGIN();                                        \
		if ((collection->delete_me_flags[group] & mask) != 0) {          \

#define RRR_HTTP_STREAMS_ITERATE_ACTIVE_BEGIN()                                  \
	RRR_HTTP_STREAMS_ITERATE_BEGIN();                                        \
		if ((collection->active_flags[group] & mask) != 0) {             \

#define RRR_HTTP_STREAMS_ITERATE_INACTIVE_BEGIN()                                \
	RRR_HTTP_STREAMS_ITERATE_BEGIN();                                        \
		if ((collection->active_flags[group] & mask) == 0) {             \

#define RRR_HTTP_STREAMS_ITERATE_END() \
	}}} while(0)

static int __rrr_http_stream_reset (
		struct rrr_http_stream_collection *collection,
		uint64_t index
) {
	struct rrr_http_stream *stream = &collection->streams[index];
	rrr_http_header_field_collection_clear(&stream->headers);
	if (stream->application_data != NULL) {
		stream->application_data_destroy_function(stream->application_data);
	}
	RRR_FREE_IF_NOT_NULL(stream->data);
	rrr_map_clear(&stream->headers_to_send);
	memset(stream, '\0', sizeof(*stream));

	collection->active_flags[RRR_HTTP_STREAM_GROUP(index)] &= ~RRR_HTTP_STREAM_MASK(index);
	collection->delete_me_flags[RRR_HTTP_STREAM_GROUP(index)] &= ~RRR_HTTP_STREAM_MASK(index);
	collection->stream_ids[index] = 0;
	collection->stream_count--;

	return 0;
}

void rrr_http_stream_collection_destroy (
		struct rrr_http_stream_collection *collection
) {
	if (RRR_DEBUGLEVEL_3) {
		// This is useful to detect usage of invalid stream IDs. There
		// is no checks when for instance header fields are pushed if a
		// stream ID is correct and will actually be sent.
		RRR_HTTP_STREAMS_ITERATE_ACTIVE_BEGIN();
			uint64_t age_ms = (rrr_time_get_64() - node->creation_time) / 1000;
			RRR_DBG_3("http stream id %i late destroy (upon collection destruction), age is %" PRIu64 "ms\n",
					collection->stream_ids[i], age_ms);
		RRR_HTTP_STREAMS_ITERATE_END();
	}
	RRR_HTTP_STREAMS_ITERATE_ACTIVE_BEGIN();
		__rrr_http_stream_reset(collection, i);
	RRR_HTTP_STREAMS_ITERATE_END();
}

void rrr_http_stream_collection_maintain (
		unsigned int *closed_stream_count,
		struct rrr_http_stream_collection *collection
) {
	*closed_stream_count = 0;

	RRR_HTTP_STREAMS_ITERATE_DELETE_ME_BEGIN();
		(*closed_stream_count)++;
		__rrr_http_stream_reset(collection, i);
	RRR_HTTP_STREAMS_ITERATE_END();
}

void rrr_http_stream_collection_delete_me_set (
		struct rrr_http_stream_collection *collection,
		int64_t stream_id
) {
	RRR_HTTP_STREAMS_ITERATE_ACTIVE_BEGIN();
		if (collection->stream_ids[i] == stream_id) {
			collection->delete_me_flags[RRR_HTTP_STREAM_GROUP(i)] |= RRR_HTTP_STREAM_MASK(i);
			break;
		}
	RRR_HTTP_STREAMS_ITERATE_END();
}

struct rrr_http_stream *rrr_http_stream_collection_find (
		struct rrr_http_stream_collection *collection,
		int64_t stream_id
) {

	RRR_HTTP_STREAMS_ITERATE_ACTIVE_BEGIN();
		if (collection->stream_ids[i] == stream_id) {
			return &collection->streams[i];
		}
	RRR_HTTP_STREAMS_ITERATE_END();

	return NULL;
}

struct rrr_http_stream *rrr_http_stream_collection_find_or_create (
		struct rrr_http_stream_collection *collection,
		int64_t stream_id
) {
	struct rrr_http_stream *old_stream = rrr_http_stream_collection_find (collection, stream_id);
	if (old_stream != NULL) {
		return old_stream;
	}

	int all_set = 1;
	for (uint64_t i = 0; i < RRR_HTTP_STREAM_BLOCKS; i++) {
		if (collection->active_flags[i] != UINT64_MAX) {
			all_set = 0;
			break;
		}
	}

	if (all_set) {
		return NULL;
	}

	RRR_HTTP_STREAMS_ITERATE_INACTIVE_BEGIN();
		node->creation_time = rrr_time_get_64();

		collection->active_flags[group] |= mask;
		collection->stream_ids[i] = stream_id;
		collection->stream_count++;

		return node;
	RRR_HTTP_STREAMS_ITERATE_END();

	RRR_BUG("BUG: Flag error in %s\n", __func__);

	return NULL;;
}

int rrr_http_stream_data_push (
		struct rrr_http_stream *target,
		const char *data,
		size_t data_size
) {
	int ret = 0;

	if (data_size == 0) {
		goto out;
	}

	if (target->data_wpos + data_size > target->data_size) {
		size_t new_size = target->data_size + data_size + 65536;
		void *data_new = rrr_reallocate(target->data, new_size);
		if (data_new == NULL) {
			RRR_MSG_0("Could not allocate memory for data in %s\n", __func__);
			ret = 1;
			goto out;
		}
		target->data_size = new_size;
		target->data = data_new;
	}

	memcpy(target->data + target->data_wpos, data, data_size);
	target->data_wpos += data_size;

	out:
	return ret;
}

int rrr_http_stream_collection_iterate (
		struct rrr_http_stream_collection *collection,
		int (*callback)(int64_t stream_id, void *application_data, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_HTTP_STREAMS_ITERATE_ACTIVE_BEGIN();
		if ((ret = callback(collection->stream_ids[i], node->application_data, callback_arg)) != 0) {
			goto out;
		}
	RRR_HTTP_STREAMS_ITERATE_END();

	out:
	return ret;
}
