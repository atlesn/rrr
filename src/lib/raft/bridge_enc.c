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
#include "log.h"

#include "../allocator.h"
#include "../util/rrr_endian.h"
#include "../util/crc32.h"

#include <string.h>

/*
 * BASIC WRITE MACROS
 */

#define WRITE(buf)                          \
    char *wpos = (char *) (buf); if (1)     \

#define WRITE_U8(n)                         \
    * (uint8_t *) wpos = n;                 \
    wpos += sizeof(uint8_t)

#define WRITE_U16(n)                        \
    * (uint16_t *) wpos = n;                \
    wpos += sizeof(uint16_t)

#define WRITE_U32(n)                        \
    * (uint32_t *) wpos = rrr_htole64(n);   \
    wpos += sizeof(uint32_t)

#define WRITE_U64(n)                        \
    * (uint64_t *) wpos = rrr_htole64(n);   \
    wpos += sizeof(uint64_t)

#define WRITE_STR(str)                      \
    do {size_t len = strlen(str);           \
        memcpy(wpos, str, len + 1);         \
	wpos += len + 1;                    \
    } while(0)

#define WRITE_POS()                         \
    wpos

#define WRITE_INC(n)                        \
   wpos += n

#define WRITE_REM(len)                      \
   ((size_t) ((uintptr_t) len - (uintptr_t) wpos))

#define WRITE_VERIFY(buf,len)               \
    assert((uintptr_t) wpos - (uintptr_t) (buf) == (uintptr_t) len)

/*
 * COMPOSITE WRITE MACROS
 */

#define GET_BATCH_HEADER_SIZE(n) (                    \
        sizeof(uint64_t) +       /* Entry count */    \
        sizeof(uint64_t) * 2 * n /* Entry headers */  \
    )

#define PUT_BATCH_HEADER(fetch, entry_count, crc)                                             \
    do {char *wpos_begin = wpos; WRITE_U64(entry_count);                                      \
        raft_index i;                                                                         \
	const struct raft_entry *entry;                                                       \
        if (entry_count == 0) break;                                                          \
        for (i = 0; i < entry_count; i++) {                                                   \
	    entry = fetch;                                                                    \
	    WRITE_U64(entry->term);                                                           \
	    WRITE_U8(entry->type);                                                            \
	    WRITE_U8(0);                                                                      \
	    WRITE_U8(0);                                                                      \
	    WRITE_U8(0);                                                                      \
            WRITE_U32(entry->buf.len);                                                        \
	}                                                                                     \
        crc = rrr_crc32buf_init(wpos_begin, wpos - wpos_begin, crc);                          \
    } while (0)

#define PUT_BATCH_HEADER_RAW(entries, entry_count, crc)                                       \
    PUT_BATCH_HEADER(entries + i, entry_count, crc)

#define PUT_BATCH_HEADER_LOG(first_index, entry_count, crc)                                   \
    do {                                                                                      \
        raft_index index = first_index;                                                       \
	struct raft_entry raft_entry;                                                         \
	const struct rrr_raft_log_entry *log_entry;                                           \
	PUT_BATCH_HEADER(                                                                     \
		&raft_entry;                                                                  \
		log_entry = rrr_raft_log_get(log, index++);                                   \
		raft_entry.term = log_entry->term;                                            \
		raft_entry.type = log_entry->type;                                            \
		raft_entry.buf.base = log_entry->data;                                        \
		raft_entry.buf.len = log_entry->data_size,                                    \
		entry_count,                                                                  \
		crc                                                                           \
	);                                                                                    \
    } while (0)

#define PUT_BATCH_DATA(fetch, entry_count, crc)                                               \
    do {                                                                                      \
        raft_index i;                                                                         \
	const struct raft_entry *entry;                                                       \
        if (entry_count == 0) break;                                                          \
        for (i = 0; i < entry_count; i++) {                                                   \
            entry = fetch;                                                                    \
	    memcpy(wpos, entry->buf.base, entry->buf.len);                                    \
	    crc = rrr_crc32buf_init(wpos, entry->buf.len, crc);                               \
	    wpos += entry->buf.len;                                                           \
	}                                                                                     \
    } while (0)

#define PUT_BATCH_DATA_RAW(entries, entry_count, crc)                                         \
    PUT_BATCH_DATA(entries + i, entry_count, crc)

#define PUT_BATCH_DATA_LOG(first_index, entry_count, crc)                                     \
    do {                                                                                      \
        raft_index index = first_index;                                                       \
	struct raft_entry raft_entry;                                                         \
	const struct rrr_raft_log_entry *log_entry;                                           \
	PUT_BATCH_DATA(                                                                       \
		&raft_entry;                                                                  \
		log_entry = rrr_raft_log_get(log, index++);                                   \
		raft_entry.term = log_entry->term;                                            \
		raft_entry.type = log_entry->type;                                            \
		raft_entry.buf.base = log_entry->data;                                        \
		raft_entry.buf.len = log_entry->data_size,                                    \
		entry_count,                                                                  \
		crc                                                                           \
	);                                                                                    \
    } while (0)

#define GET_METADATA_SIZE() \
    (sizeof(uint64_t) * 4)

#define GET_MSG_PREAMBLE_SIZE() \
    (sizeof(uint64_t) * 2)

#define GET_MSG_REQUEST_VOTE_SIZE() \
    (sizeof(uint64_t) * 5)

#define GET_MSG_REQUEST_VOTE_RESULT_SIZE() \
    (sizeof(uint64_t) * 3)

#define GET_MSG_APPEND_ENTRIES_HEADER_SIZE(entry_count) \
    (sizeof(uint64_t) * 4 +                             \
     GET_BATCH_HEADER_SIZE(entry_count) +               \
     sizeof(uint64_t))

static inline size_t __rrr_raft_encode_get_msg_append_entries_size (
		const struct rrr_raft_log *log,
		const struct raft_append_entries *msg
) {
	size_t total_size = 0;
	unsigned i;
	raft_index index;
	const struct rrr_raft_log_entry *log_entry;

	total_size += GET_MSG_APPEND_ENTRIES_HEADER_SIZE(msg->n_entries);

	if (msg->n_entries == 0) {
		goto out;
	}

	for (i = 0; i < msg->n_entries; i++) {
		printf("entries %p\n", msg->entries);
		if (1 || msg->entries == NULL) {
			index = msg->prev_log_index + i + 1;
			printf("- index %lu\n", (unsigned long) index);
			log_entry = rrr_raft_log_get(log, index);
			assert(log_entry != NULL);
			total_size += log_entry->data_size;
			printf("- data size %lu\n", log_entry->data_size);
		}
		else {
			printf("- batch %p\n", msg->entries[i].batch);
			printf("- base %p\n", msg->entries[i].buf.base);
			printf("- len %lu\n", msg->entries[i].buf.len);
			total_size += msg->entries[i].buf.len;
			assert(total_size > msg->entries[i].buf.len);
		}
	}

	out:
	return total_size;
}

#define GET_MSG_APPEND_ENTRIES_SIZE(log, msg) \
    (__rrr_raft_encode_get_msg_append_entries_size(log, msg))

#define GET_MSG_APPEND_ENTRIES_RESULT_SIZE() \
    (sizeof(uint64_t) * 4)

#define PUT_MSG_PREAMBLE(type, version, body_size)  \
    do {                                            \
        WRITE_U8(type);                             \
	WRITE_U8(0);                                \
	WRITE_U8(version);                          \
	WRITE_U8(0);                                \
	WRITE_U32(0);                               \
	WRITE_U64(body_size);                       \
    } while(0)

/*
 * READ MACROS
 */

#define READ(buf)                           \
    char *rpos = (char *) buf; if (1)       \

#define READ_U8(n)                         \
    (n) = (* (uint8_t *) rpos);            \
    rpos += sizeof(uint8_t)

#define READ_U16(n)                         \
    (n) = rrr_le16toh(* (uint16_t *) rpos); \
    rpos += sizeof(uint16_t)

#define READ_U32(n)                         \
    (n) = rrr_le32toh(* (uint32_t *) rpos); \
    rpos += sizeof(uint32_t)

#define READ_U64(n)                         \
    (n) = rrr_le64toh(* (uint64_t *) rpos); \
    rpos += sizeof(uint64_t)

#define READ_U64_PEEK(n)                    \
    (n) = rrr_le64toh(* (uint64_t *) rpos)

#define READ_VERIFY(buf,len)                \
    assert((uintptr_t) rpos - (uintptr_t) (buf) == (uintptr_t) len)

#define READ_REM(buf,buf_len)               \
    ((uintptr_t) buf_len - ((uintptr_t) rpos - (uintptr_t) buf))

#define READ_RAW(buf,len)                   \
    memcpy(buf, rpos, len); rpos += len


#define READ_BATCH_HEADER(entry_count, payload_size)         \
    do {(payload_size) = 0;                                  \
    READ_U64_PEEK(entry_count);                              \
    if (READ_REM(header, header_size) < GET_BATCH_HEADER_SIZE(entry_count)) { \
        return RRR_RAFT_INCOMPLETE;                          \
    }                                                        \
    READ_U64(entry_count);                                   \
    for (uint64_t i = 0; i < entry_count; i++) {             \
	uint8_t u8; uint32_t u32; uint64_t u64;              \
	(void)(u8); (void)(u64);                             \
        READ_U64(u64);                                       \
        READ_U8(u8);                                         \
        READ_U8(u8);                                         \
        READ_U8(u8);                                         \
	READ_U8(u8);                                         \
        READ_U32(u32);                                       \
        (payload_size) += u32;                               \
        if ((payload_size) < u32) {                          \
            return RRR_RAFT_SOFT_ERROR;                      \
        }                                                    \
    }} while(0)

/*
 * ENCODING FUNCTIONS
 */

int rrr_raft_bridge_encode_configuration (
		char **data,
		size_t *data_size,
		const struct raft_configuration *conf
) {
	int ret = 0;

	size_t total_size = 0;
	unsigned i;
	struct raft_server *server;
	char *buf = NULL;

	total_size += sizeof(uint8_t);  /* Format */
	total_size += sizeof(uint64_t); /* Server count */

	for (i = 0; i < conf->n; i++) {
		server = conf->servers + i;
		assert(server->address != NULL);
		total_size += sizeof(uint64_t);            /* Server ID */
		total_size += strlen(server->address) + 1; /* Server address */
		total_size += sizeof(uint8_t);             /* Voting flag */
	}

	if ((buf = rrr_allocate(total_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	WRITE(buf) {
		WRITE_U8(RRR_RAFT_DISK_FORMAT);
		WRITE_U64(conf->n);
		for (i = 0; i < conf->n; i++) {
			server = conf->servers + i;
			WRITE_U64(server->id);
			WRITE_STR(server->address);
			WRITE_U8(server->role);
		}
	}
	WRITE_VERIFY(buf,total_size);

	*data = buf;
	*data_size = total_size;
	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

void rrr_raft_bridge_encode_metadata (
		uint64_t data[4],
		const struct rrr_raft_bridge_metadata *metadata
) {
	WRITE(data) {
		WRITE_U64(RRR_RAFT_DISK_FORMAT);
		WRITE_U64(metadata->version);
		WRITE_U64(metadata->term);
		WRITE_U64(metadata->voted_for);
	}
	WRITE_VERIFY(data,sizeof(uint64_t) * 4);
}

int rrr_raft_bridge_encode_entries (
		char **data,
		size_t *data_size,
		size_t preamble_size,
		const struct raft_entry *entries,
		unsigned entry_count
) {
	int ret = 0;

	size_t total_size = 0;
	char *crc1_pos, *crc2_pos, *buf = NULL;
	uint32_t crc1 = 0xffffffff, crc2 = 0xffffffff;
	unsigned i;

	total_size += preamble_size;
	total_size += sizeof(uint32_t) * 2;  /* Checksums */
	total_size += GET_BATCH_HEADER_SIZE(entry_count);
	for (i = 0; i < entry_count; i++) {
		total_size += entries[i].buf.len;
	}

	if ((buf = rrr_allocate(total_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %sn\n", __func__);
		ret = 1;
		goto out;
	}

	WRITE(buf) {
		WRITE_INC(preamble_size);
		crc1_pos = WRITE_POS();
		WRITE_U32(0);
		crc2_pos = WRITE_POS();
		WRITE_U32(0);
		PUT_BATCH_HEADER_RAW(entries, entry_count, crc1);
		PUT_BATCH_DATA_RAW(entries, entry_count, crc2);
	}
	WRITE_VERIFY(buf, total_size);

	* (uint32_t *) crc1_pos = crc1;
	* (uint32_t *) crc2_pos = crc2;

	*data = buf;
	*data_size = total_size;
	buf = NULL;

	out:
	return ret;
}

int rrr_raft_bridge_encode_closed_segment (
		char **data,
		size_t *data_size,
		const char *conf,
		size_t conf_size,
		raft_term conf_term
) {
	int ret = 0;

	struct raft_entry entry = {0};

	entry.term = conf_term;
	entry.type = RAFT_CHANGE;
	entry.buf.base = (void *) conf;
	entry.buf.len = conf_size;

	if ((ret = rrr_raft_bridge_encode_entries (
			data,
			data_size,
			sizeof(uint64_t),
			&entry,
			1
	)) != 0) {
		goto out;
	}

	WRITE(*data) {
		WRITE_U64(RRR_RAFT_DISK_FORMAT);	
	}

	out:
	return ret;
}

size_t rrr_raft_bridge_encode_message_get_size (
		const struct rrr_raft_log *log,
		const struct raft_message *msg
) {
	size_t total_size = 0;

	total_size += GET_MSG_PREAMBLE_SIZE();

	switch (msg->type) {
		case RAFT_REQUEST_VOTE:
			total_size += GET_MSG_REQUEST_VOTE_SIZE();
			break;
		case RAFT_REQUEST_VOTE_RESULT:
			total_size += GET_MSG_REQUEST_VOTE_RESULT_SIZE();
			break;
		case RAFT_APPEND_ENTRIES:
			total_size += GET_MSG_APPEND_ENTRIES_SIZE(log, &msg->append_entries);
			break;
		case RAFT_APPEND_ENTRIES_RESULT:
			total_size += GET_MSG_APPEND_ENTRIES_RESULT_SIZE();
			break;
		case RAFT_INSTALL_SNAPSHOT:
			assert(0 && "Install snapshot message not implemented");
			break;
		case RAFT_TIMEOUT_NOW:
			assert(0 && "Timeout not message not implemented");
			break;
		default:
			RRR_BUG("BUG: Unknown message type %i in %s\n", msg->type, __func__);

	};

	return total_size;
}

void rrr_raft_bridge_encode_message_request_vote (
		void *data,
		size_t data_size,
		const struct raft_request_vote *msg
) {
	uint64_t flags = 0;

	assert(data_size >= GET_MSG_PREAMBLE_SIZE() + GET_MSG_REQUEST_VOTE_SIZE());

	if (msg->disrupt_leader) {
		flags |= 1 << 0;
	}

	if (msg->pre_vote) {
		flags |= 1 << 1;
	}

	WRITE(data) {
		PUT_MSG_PREAMBLE(RAFT_REQUEST_VOTE, RRR_RAFT_RPC_VERSION, GET_MSG_REQUEST_VOTE_SIZE());
		WRITE_U64(msg->term);
		WRITE_U64(msg->candidate_id);
		WRITE_U64(msg->last_log_index);
		WRITE_U64(msg->last_log_term);
		WRITE_U64(flags);
	}
	WRITE_VERIFY(data, GET_MSG_PREAMBLE_SIZE() + GET_MSG_REQUEST_VOTE_SIZE());
}

void rrr_raft_bridge_encode_message_request_vote_result (
		void *data,
		size_t data_size,
		const struct raft_request_vote_result *msg
) {
	uint8_t flags = 0;

	assert(data_size >= GET_MSG_PREAMBLE_SIZE() + GET_MSG_REQUEST_VOTE_RESULT_SIZE());

	if (msg->pre_vote) {
		flags |= 1 << 1;
	}

	WRITE(data) {
		PUT_MSG_PREAMBLE(RAFT_REQUEST_VOTE_RESULT, RRR_RAFT_RPC_VERSION, GET_MSG_REQUEST_VOTE_RESULT_SIZE());
		WRITE_U64(msg->term);
		WRITE_U64(msg->vote_granted);

		WRITE_U8(flags);
		WRITE_U8(0);
		WRITE_U16(msg->features);

		WRITE_U16(msg->capacity);
		WRITE_U16(0);
	}
	WRITE_VERIFY(data, GET_MSG_PREAMBLE_SIZE() + GET_MSG_REQUEST_VOTE_RESULT_SIZE());
}

void rrr_raft_bridge_encode_message_append_entries (
		const struct rrr_raft_log *log,
		void *data,
		size_t data_size,
		const struct raft_append_entries *msg
) {
	// Note : CRCs are not used (yet)
	uint32_t crc1 = 0xffffffff, crc2 = 0xffffffff;
	const size_t msg_size = GET_MSG_APPEND_ENTRIES_SIZE(log, msg);

	assert(data_size >= GET_MSG_PREAMBLE_SIZE() + msg_size);

	WRITE(data) {
		PUT_MSG_PREAMBLE(RAFT_APPEND_ENTRIES, RRR_RAFT_RPC_VERSION, msg_size);
		WRITE_U64(msg->term);
		WRITE_U64(msg->prev_log_index);
		WRITE_U64(msg->prev_log_term);
		WRITE_U64(msg->leader_commit);
		PUT_BATCH_HEADER_LOG(msg->prev_log_index + 1, msg->n_entries, crc1);
		WRITE_U64(0);
		PUT_BATCH_DATA_LOG(msg->prev_log_index + 1, msg->n_entries, crc2);
	}
	printf("pos %lu exp %lu\n", (uintptr_t) wpos - (uintptr_t) data, GET_MSG_PREAMBLE_SIZE() + msg_size);
	WRITE_VERIFY(data, GET_MSG_PREAMBLE_SIZE() + msg_size);
}

void rrr_raft_bridge_encode_message_append_entries_result (
		void *data,
		size_t data_size,
		const struct raft_append_entries_result *msg
) {
	assert(data_size >= GET_MSG_PREAMBLE_SIZE() + GET_MSG_APPEND_ENTRIES_RESULT_SIZE());

	WRITE(data) {
		PUT_MSG_PREAMBLE(RAFT_APPEND_ENTRIES_RESULT, RRR_RAFT_RPC_VERSION, GET_MSG_APPEND_ENTRIES_RESULT_SIZE());
		WRITE_U64(msg->term);
		WRITE_U64(msg->rejected);
		WRITE_U64(msg->last_log_index);
		WRITE_U16(msg->features);
		WRITE_U16(msg->capacity);
		WRITE_U32(0);
	}
	WRITE_VERIFY(data, GET_MSG_PREAMBLE_SIZE() + GET_MSG_APPEND_ENTRIES_RESULT_SIZE());
}

/*
 * DECODING FUNCTIONS
 */
 
int rrr_raft_bridge_decode_metadata_size_ok (
		size_t data_size
) {
	return data_size == GET_METADATA_SIZE();
}

void rrr_raft_bridge_decode_metadata (
		int *ok,
		struct rrr_raft_bridge_metadata *metadata,
		const char *data,
		size_t data_size
) {
	uint64_t format, version, term, voted_for;

	assert(data_size == GET_METADATA_SIZE());

	metadata->version = 0;
	metadata->term = 0;
	metadata->voted_for = 0;

	READ(data) {
		READ_U64(format);
		READ_U64(version);
		READ_U64(term);
		READ_U64(voted_for);
	}
	READ_VERIFY(data, data_size);

	if (format != RRR_RAFT_DISK_FORMAT) {
		RRR_MSG_0("Warning: Incorrect format %llu for metadata file ignoring it\n", (unsigned long long) format);
		*ok = 0;
		return;
	}

	metadata->version = version;
	metadata->term = term;
	metadata->voted_for = voted_for;

	*ok = 1;
}
/*
	switch (message->type) {
		case RAFT_REQUEST_VOTE:
			assert(0 && "Request vote message not implemented");
			break;
		case RAFT_REQUEST_VOTE_RESULT:
			assert(0 && "Request vote result message not implemented");
			break;
		case RAFT_APPEND_ENTRIES:
			assert(0 && "append entries message not implemented");
			break;
		case RAFT_APPEND_ENTRIES_RESULT:
			assert(0 && "Append entries result message not implemented");
			break;
		case RAFT_INSTALL_SNAPSHOT:
			assert(0 && "Install snapshot message not implemented");
			break;
		case RAFT_TIMEOUT_NOW:
			assert(0 && "Timeout not message not implemented");
			break;
		default:
			RRR_BUG("BUG: Unknown message type %i in %s\n", message->type, __func__);

	};
*/

int rrr_raft_bridge_decode_request_vote_size_check (
		uint8_t version,
		size_t header_size
) {
	if (version != RRR_RAFT_RPC_VERSION) {
		RRR_MSG_0("Unsupported version %u in %s\n", version, __func__);
		return RRR_RAFT_SOFT_ERROR;
	}

	if (header_size != GET_MSG_REQUEST_VOTE_SIZE()) {
		RRR_MSG_0("Incorrect header size for request vote\n");
		return RRR_RAFT_SOFT_ERROR;
	}

	return RRR_RAFT_OK;
}

int rrr_raft_bridge_decode_request_vote (
		struct raft_request_vote *p,
		const char *header,
		size_t header_size
) {
	assert (header_size == GET_MSG_REQUEST_VOTE_SIZE());

	uint64_t flags;

	READ(header) {
		READ_U64(p->term);
		READ_U64(p->candidate_id);
		READ_U64(p->last_log_index);
		READ_U64(p->last_log_term);
		READ_U64(flags);
	}
	READ_VERIFY(header, header_size);

	p->disrupt_leader = (flags & 1 << 0) != 0;
	p->pre_vote = (flags & 1 << 1) != 0;

	return 0;
}

int rrr_raft_bridge_decode_request_vote_result_size_check (
		uint8_t version,
		size_t header_size
) {
	if (version != RRR_RAFT_RPC_VERSION) {
		RRR_MSG_0("Unsupported version %u in %s\n", version, __func__);
		return RRR_RAFT_SOFT_ERROR;
	}

	if (header_size != GET_MSG_REQUEST_VOTE_RESULT_SIZE()) {
		RRR_MSG_0("Incorrect header size for request vote result\n");
		return RRR_RAFT_SOFT_ERROR;
	}

	return RRR_RAFT_OK;
}

int rrr_raft_bridge_decode_request_vote_result (
		struct raft_request_vote_result *p,
		const char *header,
		size_t header_size
) {
	assert (header_size == GET_MSG_REQUEST_VOTE_RESULT_SIZE());

	uint8_t flags, dummy;

	READ(header) {
		READ_U64(p->term);
		READ_U64(p->vote_granted);

		READ_U8(flags);
		READ_U8(dummy);
		READ_U16(p->features);

		READ_U16(p->capacity);
		READ_U8(dummy);
		READ_U8(dummy);
	}
	READ_VERIFY(header, header_size);

	p->version = RRR_RAFT_RPC_VERSION;
	p->pre_vote = (flags & (1 << 0));

	(void)(dummy);

	return 0;
}

int rrr_raft_bridge_decode_append_entries_size_check (
		uint8_t version,
		size_t *payload_size,
		const char *header,
		size_t header_size
) {
	uint64_t u64, entry_count;

	if (version != RRR_RAFT_RPC_VERSION) {
		RRR_MSG_0("Unsupported version %u in %s\n", version, __func__);
		return RRR_RAFT_SOFT_ERROR;
	}

	if (header_size < GET_MSG_APPEND_ENTRIES_HEADER_SIZE(0)) {
		return RRR_RAFT_INCOMPLETE;
	}

	READ(header) {
		READ_U64(u64);
		READ_U64(u64);
		READ_U64(u64);
		READ_U64(u64);
		READ_BATCH_HEADER(entry_count, *payload_size);
		if (entry_count > UINT_MAX) {
			RRR_MSG_0("Entry count exceeds maximum in append entries RPC\n");
			return RRR_RAFT_SOFT_ERROR;
		}
		READ_U64(u64);
	}
	READ_VERIFY(header, GET_MSG_APPEND_ENTRIES_HEADER_SIZE(entry_count));

	(void)(u64);

	return RRR_RAFT_OK;
}

int rrr_raft_bridge_decode_append_entries ( 
		struct raft_append_entries *p,
		const char *data,
		size_t header_size,
		size_t payload_size
) {
	int ret = RRR_RAFT_OK;

	uint64_t dummy, entry_count, i, payload_size_check;

	struct raft_entry *entry;

	assert(header_size >= GET_MSG_APPEND_ENTRIES_HEADER_SIZE(0));

	READ(data) {
		READ_U64(p->term);
		READ_U64(p->prev_log_index);
		READ_U64(p->prev_log_term);
		READ_U64(p->leader_commit);
    		READ_U64(entry_count);
		assert(entry_count <= UINT_MAX);
		p->n_entries = entry_count;
		if (entry_count > 0) {
			if ((p->entries = raft_malloc(sizeof(*p->entries) * entry_count)) == NULL) {
				RRR_MSG_0("Failed to allocate memory for entries in %s\n", __func__);
				ret = RRR_RAFT_HARD_ERROR;
				goto out;
			}
			payload_size_check = 0;
			for (i = 0; i < entry_count; i++) {
				entry = p->entries + i;
				READ_U64(entry->term);
				READ_U8(entry->type);
				READ_U8(dummy);
				READ_U8(dummy);
				READ_U8(dummy);
				READ_U32(entry->buf.len);
				payload_size_check += entry->buf.len;
				assert(payload_size_check > entry->buf.len);
			}
			assert(payload_size_check == payload_size);
		}
		else {
			p->entries = NULL;
		}
		READ_U64(dummy);

		READ_VERIFY(data, GET_MSG_APPEND_ENTRIES_HEADER_SIZE(entry_count));

		for (i = 0; i < entry_count; i++) {
			entry = p->entries + i;
			if (entry->buf.len == 0) {
				entry->buf.base = NULL;
				continue;
			}
			if ((entry->buf.base = raft_malloc(entry->buf.len)) == NULL) {
				RRR_MSG_0("Failed to allocate memory for entry base in %s\n", __func__);
				ret = RRR_RAFT_HARD_ERROR;
				goto out_free_entries;
			}
    			READ_RAW(entry->buf.base, entry->buf.len);
		}
	}

	(void)(dummy);

	goto out;
	out_free_entries:
		for (i = i; i != UINT64_MAX; i--) {
			entry = p->entries + i;
			if (entry->buf.base != NULL)
				raft_free(entry->buf.base);
		}
		raft_free(p->entries);
	out:
		return ret;
}

int rrr_raft_bridge_decode_append_entries_result_size_check (
		uint8_t version,
		size_t header_size
) {
	if (version != RRR_RAFT_RPC_VERSION) {
		RRR_MSG_0("Unsupported version %u in %s\n", version, __func__);
		return RRR_RAFT_SOFT_ERROR;
	}

	if (header_size != GET_MSG_APPEND_ENTRIES_RESULT_SIZE()) {
		RRR_MSG_0("Incorrect header size for append entries result\n");
		return RRR_RAFT_SOFT_ERROR;
	}

	return RRR_RAFT_OK;
}

int rrr_raft_bridge_decode_append_entries_result (
		struct raft_append_entries_result *p,
		const char *header,
		size_t header_size
) {
	assert (header_size == GET_MSG_APPEND_ENTRIES_RESULT_SIZE());

	uint32_t dummy;

	READ(header) {
		READ_U64(p->term);
		READ_U64(p->rejected);
		READ_U64(p->last_log_index);
		READ_U16(p->features);
		READ_U16(p->capacity);
		READ_U32(dummy);
	}
	READ_VERIFY(header, header_size);

	(void)(dummy);

	return 0;
}
