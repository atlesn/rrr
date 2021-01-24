/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../lib/log.h"
#include "../lib/msgdb/msgdb_client.h"
#include "../lib/util/rrr_time.h"
#include "../lib/util/macro_utils.h"
#include "../lib/messages/msg_msg.h"

int rrr_test_msgdb(void) {
	int ret = 0;

	struct rrr_msg_msg *msg = NULL;

	const char msg_topic[] = "a/b/c";

	if ((ret = rrr_msg_msg_new_empty (
		&msg,
		MSG_TYPE_MSG,
		MSG_CLASS_DATA,
		rrr_time_get_64(),
		sizeof(msg_topic) - 1,
		0
	)) != 0) {
		goto out;
	}

	memcpy(MSG_TOPIC_PTR(msg), msg_topic, sizeof(msg_topic) - 1);

	if ((ret = rrr_msgdb_client_put(msg)) != 0) {
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(msg);
	return ret;
}
