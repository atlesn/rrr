/*

Read Route Record

Copyright (C) 2023-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_SERVICE_H
#define RRR_HTTP_SERVICE_H

#include "http_util.h"

struct rrr_http_service {
	RRR_LL_NODE(struct rrr_http_service);
	struct rrr_http_uri uri;
	struct rrr_http_uri_flags uri_flags;
	uint64_t expire_time;
};

struct rrr_http_service_collection {
	RRR_LL_HEAD(struct rrr_http_service);
};

int rrr_http_service_collection_push (
		struct rrr_http_service_collection *collection,
		const struct rrr_http_uri *uri,
		const struct rrr_http_uri_flags *uri_flags
);
void rrr_http_service_collection_clear (
		struct rrr_http_service_collection *collection
);

#endif /* RRR_HTTP_SERVICE_H */
