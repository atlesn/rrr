/*

Read Route Record

Copyright (C) 2022 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <stdlib.h>

#include "net_transport_connection_id.h"

#include "../log.h"
#include "../allocator.h"

void rrr_net_transport_connection_id_to_str (
		char *buf,
		size_t buf_len,
		const struct rrr_net_transport_connection_id *id
) {
	if (buf_len < id->length * 2 + 1) {
		RRR_BUG("Output buffer too small in %s (%s<%s)\n", __func__, buf_len, id->length);
	}

	*buf = '\0';

	for (size_t i = 0; i < id->length; i++) {
		const uint8_t *ipos = id->data + i;
		char *opos = buf + i * 2;
		sprintf(opos, "%02x", *ipos);
	}
}

static void __rrr_net_transport_connection_id_destroy (
		struct rrr_net_transport_connection_id *cid
) {
	rrr_free(cid);
}

void rrr_net_transport_connection_id_collection_clear (
		struct rrr_net_transport_connection_id_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_net_transport_connection_id, __rrr_net_transport_connection_id_destroy(node));
}

static int __rrr_net_transport_connection_id_equals (
		const struct rrr_net_transport_connection_id *a,
		const struct rrr_net_transport_connection_id *b
) {
	if (a->length != b->length)
		return 0;

	for (size_t i = 0; i < a->length; i++) {
		if (a->data[i] != b->data[i])
			return 0;
	}

	return 1;
}

int rrr_net_transport_connection_id_collection_has (
		const struct rrr_net_transport_connection_id_collection *collection,
		const struct rrr_net_transport_connection_id *cid
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_connection_id);
		if (__rrr_net_transport_connection_id_equals(node, cid))
			return 1;
	RRR_LL_ITERATE_END();

	return 0;
}

void rrr_net_transport_connection_id_collection_remove (
		struct rrr_net_transport_connection_id_collection *collection,
		const struct rrr_net_transport_connection_id *cid
) {
	RRR_LL_ITERATE_BEGIN(collection, struct rrr_net_transport_connection_id);
		if (__rrr_net_transport_connection_id_equals(node, cid))
			RRR_LL_ITERATE_SET_DESTROY();
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; __rrr_net_transport_connection_id_destroy(node));
}

int rrr_net_transport_connection_id_collection_push (
		struct rrr_net_transport_connection_id_collection *collection,
		const struct rrr_net_transport_connection_id *cid
) {
	int ret = 0;

	struct rrr_net_transport_connection_id *cid_new = NULL;

	if ((cid_new = rrr_allocate(sizeof(*cid_new))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	*cid_new = *cid;
	RRR_LL_PUSH(collection, cid_new);

	out:
	return ret;
}
