
/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "../lib/log.h"

#include "../lib/artnet/rrr_artnet.h"

int rrr_test_artnet (void) {
	int ret = 0;

	struct rrr_artnet_node *node;

	if ((ret = rrr_artnet_node_new(&node)) != 0) {
		RRR_MSG_0("Failed to create artnet node in %s\n", __func__);
		goto out;
	}

	rrr_artnet_node_destroy(node);
	out:
	return ret;
}
