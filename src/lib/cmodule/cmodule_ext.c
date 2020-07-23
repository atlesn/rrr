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
#include "cmodule_main.h"

// Will always free the message also upon errors
int rrr_cmodule_ext_send_message_to_parent (
		struct rrr_cmodule_worker *worker,
		struct rrr_message *message,
		const struct rrr_message_addr *message_addr
) {
	int sent_total = 0;
	int retries = 0;

	// Will always free the message also upon errors
	int ret = rrr_cmodule_channel_send_message (
			&sent_total,
			&retries,
			worker->channel_to_parent,
			&worker->deferred_to_parent,
			message,
			message_addr,
			RRR_CMODULE_CHANNEL_WAIT_TIME_US
	);

	worker->total_msg_processed += 1;
	worker->total_msg_mmap_to_parent += sent_total;
	worker->to_parent_write_retry_counter += retries;

	return ret;
}
