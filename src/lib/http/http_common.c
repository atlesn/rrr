/*

Read Route Record

Copyright (C) 2020-2021 Atle Solbakken atle@goliathdns.no

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

#include "http_common.h"

const char *rrr_http_upgrade_mode_str_none = "none";
const char *rrr_http_upgrade_mode_str_websocket = "WebSocket";
const char *rrr_http_upgrade_mode_str_http2 = "HTTP2";

const char *rrr_http_application_str_http1 = "HTTP1";
const char *rrr_http_application_str_http2 = "HTTP2";

const char *rrr_http_version_str_10 = "HTTP/1.0";
const char *rrr_http_version_str_11 = "HTTP/1.1";

const char *rrr_http_transport_str_any = "ANY";
const char *rrr_http_transport_str_http = "HTTP";
const char *rrr_http_transport_str_https = "HTTPS";

const char *rrr_http_method_str_get = "GET";
const char *rrr_http_method_str_head = "HEAD";
const char *rrr_http_method_str_put = "PUT";
const char *rrr_http_method_str_patch = "PATCH";
const char *rrr_http_method_str_delete = "DELETE";
const char *rrr_http_method_str_post = "POST";

const char *rrr_http_body_format_str_multipart_form_data = "MULTIPART_FORM_DATA";
const char *rrr_http_body_format_str_urlencoded = "URLENCODED";
const char *rrr_http_body_format_str_urlencoded_no_quoting = "URLENCODED_NO_QUOTING";
const char *rrr_http_body_format_str_json = "JSON";
const char *rrr_http_body_format_str_raw = "RAW";
