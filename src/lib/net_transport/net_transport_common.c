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

#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_common.h"

int rrr_net_transport_common_read_get_target_size (
		struct rrr_read_session *read_session,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

void rrr_net_transport_common_read_get_target_size_error_callback (
		struct rrr_read_session *read_session,
		int is_hard_err,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;

	if (callback_data->get_target_size_error == NULL)
		return;

	callback_data->get_target_size_error(read_session, is_hard_err, callback_data->get_target_size_error_arg);
}

int rrr_net_transport_common_read_complete_callback (
		struct rrr_read_session *read_session,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}
