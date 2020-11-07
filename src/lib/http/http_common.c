/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

const char *rrr_http_transport_str_any = "ANY";
const char *rrr_http_transport_str_http = "HTTP";
const char *rrr_http_transport_str_https = "HTTPS";

const char *rrr_http_method_str_get = "GET";
const char *rrr_http_method_str_head = "HEAD";
const char *rrr_http_method_str_put = "PUT";
const char *rrr_http_method_str_delete = "DELETE";
const char *rrr_http_method_str_post_multipart_form_data = "POST_MULTIPART_FORM_DATA";
const char *rrr_http_method_str_post_urlencoded = "POST_URLENCODED";
const char *rrr_http_method_str_post_urlencoded_no_quoting = "POST_URLENCODED_NO_QUOTING";
const char *rrr_http_method_str_post_application_octet_stream = "POST_APPLICATION_OCTET_STREAM";
const char *rrr_http_method_str_post_application_text_plain = "POST_TEXT_PLAIN";
const char *rrr_http_method_str_post = "POST";
