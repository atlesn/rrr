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

#ifndef RRR_HTTP_REDIRECT_H
#define RRR_HTTP_REDIRECT_H

#include "../util/linked_list.h"

struct rrr_http_transaction;
struct rrr_nullsafe_str;

struct rrr_http_redirect_collection_entry {
	RRR_LL_NODE(struct rrr_http_redirect_collection_entry);
	struct rrr_http_transaction *transaction;
	struct rrr_nullsafe_str *uri;
};

struct rrr_http_redirect_collection {
	RRR_LL_HEAD(struct rrr_http_redirect_collection_entry);
};

void rrr_http_redirect_collection_clear (
		struct rrr_http_redirect_collection *collection
);
void rrr_http_redirect_collection_clear_void (
		void *arg
);
int rrr_http_redirect_collection_push (
		struct rrr_http_redirect_collection *collection,
		struct rrr_http_transaction *transaction,
		const struct rrr_nullsafe_str *uri
);
int rrr_http_redirect_collection_iterate (
		struct rrr_http_redirect_collection *collection,
		int (*callback)(struct rrr_http_transaction *transaction, const struct rrr_nullsafe_str *uri, void *arg),
		void *callback_arg
);

#endif /* RRR_HTTP_REDIRECT_H */
