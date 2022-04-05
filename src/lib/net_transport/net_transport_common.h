/*

Read Route Record

Copyright (C) 2020-2022 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_NET_TRANSPORT_COMMON_H
#define RRR_NET_TRANSPORT_COMMON_H

struct rrr_read_session;

int rrr_net_transport_common_read_get_target_size (
		struct rrr_read_session *read_session,
		void *private_arg
);
void rrr_net_transport_common_read_get_target_size_error_callback (
		struct rrr_read_session *read_session,
		int is_hard_err,
		void *private_arg
);
int rrr_net_transport_common_read_complete_callback (
		struct rrr_read_session *read_session,
		void *private_arg
);

#endif /* RRR_NET_TRANSPORT_COMMON_H */
