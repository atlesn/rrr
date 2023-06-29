/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#include "../allocator.h"
#include "../log.h"
#include "./rrr_artnet.h"

#include <artnet/artnet.h>

struct rrr_artnet_node {
	artnet_node node;
};

int rrr_artnet_node_new (struct rrr_artnet_node **result) {
	int ret = 0;

	struct rrr_artnet_node *node;

	*result = NULL;

	if ((node = rrr_allocate_zero(sizeof(*node))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((node->node = artnet_new("0.0.0.0", 1 /* Verbose */)) == NULL) {
		RRR_MSG_0("Failed to create artnet node in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	*result = node;

	goto out;
	out_free:
		rrr_free(node);
	out:
		return ret;
}

void rrr_artnet_node_destroy (struct rrr_artnet_node *node) {
	artnet_destroy(node->node);
	rrr_free(node);
}
