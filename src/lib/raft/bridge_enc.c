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

#define WRITE_VERIFY(buf,len)               \
    assert((uintptr_t) wpos - (uintptr_t) (buf) == (uintptr_t) len)

/*
 * COMPOSITE WRITE MACROS
 */

#define GET_BATCH_HEADER_SIZE(n) (                    \
        sizeof(uint64_t) +       /* Entry count */    \
        sizeof(uint64_t) * 2 * n /* Entry headers */  \
    )

#define PUT_BATCH_HEADER(entries, entry_count, crc)                                           \
    do {char *wpos_begin = wpos; WRITE_U64(entry_count);                                      \
        for (const struct raft_entry *entry = entries; entry < entries + entry_count; entry++) { \
	    WRITE_U64(entry->term);                                                           \
	    WRITE_U8(entry->type);                                                            \
	    WRITE_U8(0);                                                                      \
	    WRITE_U8(0);                                                                      \
	    WRITE_U8(0);                                                                      \
            WRITE_U32(entry->buf.len);                                                        \
	}                                                                                     \
        crc = rrr_crc32buf_init(wpos_begin, wpos - wpos_begin, crc);                          \
    } while (0)

#define PUT_BATCH_DATA(entries, entry_count, crc)                                             \
    do {                                                                                      \
        for (const struct raft_entry *entry = entries; entry < entries + entry_count; entry++) { \
	    memcpy(wpos, entry->buf.base, entry->buf.len);                                    \
	    crc = rrr_crc32buf_init(wpos, entry->buf.len, crc);                               \
	    wpos += entry->buf.len;                                                           \
	}                                                                                     \
    } while (0)

#define GET_METADATA_SIZE() \
    (sizeof(uint64_t) * 4)

/*
 * READ MACROS
 */

#define READ(buf)                           \
    char *rpos = (char *) buf; if (1)       \

#define READ_U64(n)                         \
    (n) = rrr_le64toh(* (uint64_t *) rpos); \
    rpos += sizeof(uint64_t)

#define READ_VERIFY(buf,len)                \
    assert((uintptr_t) rpos - (uintptr_t) (buf) == (uintptr_t) len)

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
		PUT_BATCH_HEADER(entries, entry_count, crc1);
		PUT_BATCH_DATA(entries, entry_count, crc2);
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
