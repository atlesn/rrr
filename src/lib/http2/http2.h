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

#ifndef RRR_HTTP2_H

struct rrr_http2_session {
	char dummy;
};

int rrr_http2_session_new_or_reset (
		struct rrr_http2_session **target
);
void rrr_http2_session_destroy_if_not_null (
		struct rrr_http2_session **target
);
int rrr_http2_pack_upgrade_request_settings(
		char **target
);

#endif /* RRR_HTTP2_H */
