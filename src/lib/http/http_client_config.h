/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_HTTP_CLIENT_CONFIG_H
#define RRR_HTTP_CLIENT_CONFIG_H

#include <inttypes.h>

#include "http_common.h"
#include "../settings.h"
#include "../map.h"

struct rrr_instance_config_data;

struct rrr_http_client_config {
	char *server;
	char *endpoint;

	char *method_str;
	enum rrr_http_method method;
	int do_plain_http2;

	char *body_format_str;
	enum rrr_http_body_format body_format;

	rrr_setting_uint server_port;
	rrr_setting_uint concurrent_connections;

	struct rrr_map tags;
	struct rrr_map fixed_tags;
	struct rrr_map fields;
	struct rrr_map fixed_fields;
};

void rrr_http_client_config_cleanup (
		struct rrr_http_client_config *data
);
int rrr_http_client_config_parse (
		struct rrr_http_client_config *data,
		struct rrr_instance_config_data *config,
		const char *prefix,
		const char *default_server,
		uint16_t default_port,
		uint16_t default_concurrent_connections,
		int enable_fixed,
		int enable_endpoint,
		int enable_body_format
);

#endif /* RRR_HTTP_CLIENT_CONFIG_H */
