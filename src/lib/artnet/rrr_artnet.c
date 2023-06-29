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
#include "../socket/rrr_socket.h"
#include "../event/event.h"
#include "../event/event_collection.h"
#include "../event/event_collection_struct.h"
#include "../event/event_handle_struct.h"

#include <assert.h>
#include <artnet/artnet.h>

struct rrr_artnet_node {
	artnet_node node;
	artnet_socket_t fd;

	struct rrr_event_queue *event_queue;
	struct rrr_event_collection events;
	rrr_event_handle event_periodic_poll;
	rrr_event_handle event_read;

	void (*failure_callback)(void *arg);
	void *callback_arg;
};

int rrr_artnet_node_new (
		struct rrr_artnet_node **result,
		struct rrr_event_queue *event_queue
) {
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

	rrr_event_collection_init(&node->events, event_queue);

	node->event_queue = event_queue;

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

#define FAIL() \
	node->failure_callback(node->callback_arg)

void __rrr_artnet_event_periodic_poll (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_artnet_node *node = arg;

	(void)(fd);
	(void)(flags);

	if (artnet_send_poll(node->node, NULL, ARTNET_TTM_DEFAULT) != ARTNET_EOK) {
		RRR_MSG_0("Failed to send artnet poll in %s\n", __func__);
		FAIL();
	}
}

void __rrr_artnet_event_read (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_artnet_node *node = arg;

	(void)(fd);
	(void)(flags);

	printf("Read\n");

	if (artnet_read(node->node, 0) != ARTNET_EOK) {
		RRR_MSG_0("Failed to read artnet data in %s\n", __func__);
		FAIL();
	}
}

static int __rrr_artnet_handler_reply (
		artnet_node _node,
		void *pp,
		void *d
) {
	struct rrr_artnet_node *node = d;

	printf("Reply\n");

	return 0;
}

int rrr_artnet_events_register (
		struct rrr_artnet_node *node,
		void (*failure_callback)(void *arg),
		void *callback_arg
) {
	int ret = 0;

	if ((ret = rrr_event_collection_push_periodic (
			&node->event_periodic_poll,
			&node->events,
			__rrr_artnet_event_periodic_poll,
			node,
			1 * 1000 * 1000 // 1s
	)) != 0) {
		RRR_MSG_0("Failed to create periodic poll event in %s\n", __func__);
		goto out_cleanup;
	}

	EVENT_ACTIVATE(node->event_periodic_poll);
	EVENT_ADD(node->event_periodic_poll);

	if ((ret = rrr_event_collection_push_read (
			&node->event_read,
			&node->events,
			node->fd,
			__rrr_artnet_event_read,
			node,
			1 * 1000 * 1000 // 1s
	)) != 0) {
		RRR_MSG_0("Failed to create read event in %s\n", __func__);
		goto out_cleanup;
	}

	EVENT_ADD(node->event_read);

	assert (artnet_set_handler(node->node, ARTNET_REPLY_HANDLER, __rrr_artnet_handler_reply, node) == ARTNET_EOK);

	node->failure_callback = failure_callback;
	node->callback_arg = callback_arg;

	goto out;
	out_cleanup:
		rrr_event_collection_clear(&node->events);
	out:
		return ret;
}

void rrr_artnet_node_destroy (
		struct rrr_artnet_node *node
) {
	rrr_event_collection_clear(&node->events);
	artnet_stop(node->node);
	artnet_destroy(node->node);
	rrr_socket_remove(node->fd);
	rrr_free(node);
}
