/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <stdlib.h>
#include <string.h>

#include "../log.h"
#include "http_redirect.h"
#include "http_transaction.h"
#include "../helpers/nullsafe_str.h"
#include "../util/macro_utils.h"
#include "../util/linked_list.h"
#include "../util/rrr_time.h"

#define RRR_HTTP_REDIRECT_TIMEOUT_MS 5000

static void __rrr_http_redirect_collection_entry_destroy (
		struct rrr_http_redirect_collection_entry *entry
) {
	rrr_http_transaction_decref_if_not_null(entry->transaction);
	rrr_nullsafe_str_destroy_if_not_null(&entry->uri);
	free(entry);
}

static int __rrr_http_redirect_collection_entry_new (
		struct rrr_http_redirect_collection_entry **target,
		struct rrr_http_transaction *transaction,
		const struct rrr_nullsafe_str *uri
) {
	int ret = 0;

	*target = NULL;

	char *endpoint_path_tmp = NULL;

	struct rrr_http_redirect_collection_entry *entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_http_redirect_collection_entry_new\n");
		ret = 1;
		goto out;
	}

	memset(entry, '\0', sizeof(*entry));

	if ((ret = rrr_nullsafe_str_dup(&entry->uri, uri)) != 0) {
		RRR_MSG_0("Could not allocate memory for uri in __rrr_http_redirect_collection_entry_new\n");
		ret = 1;
		goto out_free;
	}

	entry->transaction = transaction;

	*target = entry;

	goto out;
	out_free:
		free(entry);
	out:
		RRR_FREE_IF_NOT_NULL(endpoint_path_tmp);
		return ret;
}

void rrr_http_redirect_collection_clear (
		struct rrr_http_redirect_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_http_redirect_collection_entry, __rrr_http_redirect_collection_entry_destroy(node));
}


void rrr_http_redirect_collection_clear_void (
		void *arg
) {
	rrr_http_redirect_collection_clear(arg);
}

int rrr_http_redirect_collection_push (
		struct rrr_http_redirect_collection *collection,
		struct rrr_http_transaction *transaction,
		const struct rrr_nullsafe_str *uri
) {
	int ret = 0;

	struct rrr_http_redirect_collection_entry *entry = NULL;

	if ((ret = __rrr_http_redirect_collection_entry_new(&entry, transaction, uri)) != 0) {
		goto out;
	}

	RRR_LL_PUSH(collection, entry);

	out:
	return ret;
}

int rrr_http_redirect_collection_iterate (
		struct rrr_http_redirect_collection *collection,
		int (*callback)(struct rrr_http_transaction *transaction, const struct rrr_nullsafe_str *uri, void *arg),
		void *callback_arg
) {
	int ret = 0;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_http_redirect_collection_entry);
		if (rrr_http_transaction_lifetime_get(node->transaction) > RRR_HTTP_REDIRECT_TIMEOUT_MS * 1000) {
			char *endpoint_path_tmp = NULL;
			rrr_http_transaction_endpoint_path_get(&endpoint_path_tmp, node->transaction);
			RRR_MSG_0("Redirect timeout after %u ms for HTTP transaction with endpoint %s\n",
					RRR_HTTP_REDIRECT_TIMEOUT_MS, endpoint_path_tmp);
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if ((ret = callback(node->transaction, node->uri, callback_arg)) == RRR_HTTP_BUSY) {
			// OK, busy. Try again later.
			ret = RRR_HTTP_OK;
		}
		else {
			RRR_LL_ITERATE_SET_DESTROY();
			if (ret != 0) {
				goto out;
			}
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection, 0; __rrr_http_redirect_collection_entry_destroy(node));

	out:
	return ret;
}
