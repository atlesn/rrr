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
	rrr_free(service->match_server);
	rrr_http_util_uri_clear(&service->uri);
	rrr_free(service);
}

int rrr_http_service_collection_push (
		struct rrr_http_service_collection *collection,
		const char *match_server,
		uint16_t match_port,
		const struct rrr_http_uri *uri,
		const struct rrr_http_uri_flags *uri_flags,
		enum rrr_http_transport transport,
		enum rrr_http_application_type application_type
) {
	int ret = 0;

	struct rrr_http_service *service;

	if ((service = rrr_allocate_zero(sizeof(*service))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_http_util_uri_dup (&service->uri, uri)) != 0) {
		RRR_MSG_0("Failed to duplicate URI in %s\n", __func__);
		goto out_free;
	}

	if ((service->match_server = rrr_strdup(match_server)) == NULL) {
		RRR_MSG_0("Failed to duplicate match_server in %s\n", __func__);
		ret = 1;
		goto out_clear_uri;
	}

	service->match_port = match_port;
	service->uri_flags = *uri_flags;
	service->transport = transport;
	service->application_type = application_type;

	RRR_LL_APPEND(collection, service);

	goto out;
	// out_free_match_server:
	//	rrr_free(service->match_server);
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
