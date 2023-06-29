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
#include "../socket/rrr_socket.h"
#include "./rrr_artnet.h"

#include <assert.h>
#include <artnet/artnet.h>

struct rrr_artnet_node {
	artnet_node node;
	artnet_socket_t fd;
};

int rrr_artnet_node_new (struct rrr_artnet_node **result) {
	int ret = 0;

	struct rrr_artnet_node *node;
	int domain, type, protocol;

	*result = NULL;

	if ((node = rrr_allocate_zero(sizeof(*node))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((node->node = artnet_new(NULL, 1 /* Verbose */)) == NULL) {
		RRR_MSG_0("Failed to create artnet node in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	if (artnet_start(node->node) != ARTNET_EOK) {
		RRR_MSG_0("Failed to start artnet in %s: %s\n", __func__, artnet_strerror());
		ret = 1;
		goto out_destroy;
	}

	if ((node->fd = artnet_get_sd(node->node)) < 0) {
		switch (node->fd) {
			case ARTNET_EACTION:
				RRR_MSG_0("Got ARTNET_EACTION while retrieving artnet socket number in %s\n", __func__);
				break;
			case -1:
				RRR_MSG_0("Socket error -1 while retrieving artnet socket number in %s\n", __func__);
				break;
			default:
				RRR_MSG_0("Unknown error %i while retrieving artnet socket number in %s\n", node->fd, __func__);
				break;
		};
		ret = 1;
		goto out_stop;
	}

	artnet_get_sockopt(&domain, &type, &protocol);

	if ((ret = rrr_socket_add (node->fd, domain, type, protocol, __func__)) != 0) {
		RRR_MSG_0("Failed to register socket in %s\n", __func__);
		goto out_destroy;
	}

	*result = node;

	goto out;
	out_stop:
		artnet_stop(node->node);
	out_destroy:
		artnet_destroy(node->node);
	out_free:
		rrr_free(node);
	out:
		return ret;
}

void rrr_artnet_node_destroy (struct rrr_artnet_node *node) {
	artnet_stop(node->node);
	artnet_destroy(node->node);
	rrr_socket_remove(node->fd);
	rrr_free(node);
}
