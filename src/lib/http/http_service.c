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

#include "../log.h"
#include "../allocator.h"

#include "http_service.h"
#include "http_util.h"

#include "../util/linked_list.h"

static void __rrr_http_service_destroy (
		struct rrr_http_service *service
) {
	rrr_free(service->match_string);
	rrr_http_util_uri_clear(&service->uri);
	rrr_free(service);
}

int rrr_http_service_collection_push_unique (
		struct rrr_http_service_collection *collection,
		const char *match_string,
		uint64_t match_number,
		const struct rrr_http_uri *uri
) {
	int ret = 0;

	int existing = 0;
	struct rrr_http_service *service;
	char *match_string_new;

	RRR_LL_ITERATE_BEGIN(collection, struct rrr_http_service);
		if (match_number != node->match_number)
			RRR_LL_ITERATE_NEXT();
		if (strcmp(match_string, match_string) != 0)
			RRR_LL_ITERATE_NEXT();
		if (uri->transport != node->uri.transport)
			RRR_LL_ITERATE_NEXT();
		if (uri->application_type != node->uri.application_type)
			RRR_LL_ITERATE_NEXT();

		service = node;

		existing = 1;

		RRR_LL_ITERATE_BREAK();
	RRR_LL_ITERATE_END();

	if (existing) {
		rrr_free(service->match_string);
	}
	else {
		if ((service = rrr_allocate_zero(sizeof(*service))) == NULL) {
			RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if ((ret = rrr_http_util_uri_dup (&service->uri, uri)) != 0) {
		RRR_MSG_0("Failed to duplicate URI in %s\n", __func__);
		goto out_free;
	}

	if ((match_string_new = rrr_strdup(match_string)) == NULL) {
		RRR_MSG_0("Failed to duplicate match_string in %s\n", __func__);
		ret = 1;
		goto out_clear_uri;
	}

	service->match_string = match_string_new;
	service->match_number = match_number;

	if (!existing) {
		RRR_LL_APPEND(collection, service);
	}

	goto out;
	// out_free_match_string:
	//	rrr_free(service->match_string);
	out_clear_uri:
		rrr_http_util_uri_clear(&service->uri);
	out_free:
		rrr_free(service);
	out:
		return ret;
}

void rrr_http_service_collection_clear (
		struct rrr_http_service_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_http_service, __rrr_http_service_destroy(node));
}
