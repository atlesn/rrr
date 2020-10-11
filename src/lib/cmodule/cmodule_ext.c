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

#include "../log.h"

#include "cmodule_defines.h"
#include "cmodule_ext.h"
#include "cmodule_channel.h"
#include "cmodule_worker.h"

int rrr_cmodule_ext_send_message_to_parent (
		struct rrr_cmodule_worker *worker,
		const struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
) {
	return rrr_cmodule_worker_send_message_and_address_to_parent(worker, message, message_addr);
}
