/*

Read Route Record

Copyright (C) 2023-2024 Atle Solbakken atle@goliathdns.no

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
#include "../lib/util/rrr_time.h"

#include <artnet/common.h>
#include <assert.h>
#include <artnet/artnet.h>

#define RRR_ARTNET_UNIVERSE_MAX 16
#define RRR_ARTNET_CHANNEL_MAX 512
#define RRR_ARTNET_PORT_MAX 4
#define RRR_ARTNET_PORT_TIMEOUT_S 5
#define RRR_ARTNET_BCAST_LIMIT 8

#define SET_UNIVERSE()                                                   \
    assert(universe_i < RRR_ARTNET_UNIVERSE_MAX);                        \
    struct rrr_artnet_universe *universe = &node->universes[universe_i]

struct rrr_artnet_universe {
	uint8_t net;
	uint8_t subnet;
	uint8_t index;

	rrr_artnet_dmx_t *dmx;
	rrr_artnet_dmx_t *dmx_fade_target;
	rrr_artnet_dmx_t *dmx_fade_speed;

	uint16_t dmx_count;
	size_t dmx_size;

	enum rrr_artnet_mode mode;
	uint16_t animation_pos;

	void *private_data;
	void (*private_data_destroy)(void *data);
};

struct rrr_artnet_node {
	artnet_node node;
	artnet_socket_t fd;

	enum rrr_artnet_node_type node_type;

	struct rrr_artnet_universe universes[RRR_ARTNET_UNIVERSE_MAX];

	struct rrr_event_queue *event_queue;
	struct rrr_event_collection events;
	rrr_event_handle event_periodic_poll;
	rrr_event_handle event_periodic_update;
	rrr_event_handle event_read;

	uint8_t fade_speed;

	void (*failure_callback)(void *arg);
	void (*incorrect_mode_callback)(struct rrr_artnet_node *node, uint8_t universe_i, enum rrr_artnet_mode active_mode, enum rrr_artnet_mode required_mode);
	void *callback_arg;

	char problem[128];
};

#define RRR_ARTNET_UNIVERSE_ITERATE_BEGIN()                         \
  do { for (uint8_t i_ = 0; i_ < RRR_ARTNET_UNIVERSE_MAX; i_++) {   \
    struct rrr_artnet_universe *universe = &(node->universes[i_]); (void)(universe)

#define RRR_ARTNET_UNIVERSE_ITERATE_END()                        \
  }} while(0)

static int __rrr_artnet_universe_init (
		struct rrr_artnet_universe *universe,
		uint8_t index,
		uint16_t dmx_count,
		uint8_t fade_speed
) {
	int ret = 0;

	assert(universe->dmx == NULL);

	if ((universe->dmx = rrr_allocate_zero(sizeof(*(universe->dmx)) * dmx_count)) == NULL) {
		RRR_MSG_0("Failed to allocate DMX channels in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((universe->dmx_fade_target = rrr_allocate_zero(sizeof(*(universe->dmx_fade_target)) * dmx_count)) == NULL) {
		RRR_MSG_0("Failed to allocate DMX channels in %s\n", __func__);
		ret = 1;
		goto out_free_dmx;
	}

	if ((universe->dmx_fade_speed = rrr_allocate_zero(sizeof(*(universe->dmx_fade_speed)) * dmx_count)) == NULL) {
		RRR_MSG_0("Failed to allocate DMX channels in %s\n", __func__);
		ret = 1;
		goto out_free_fade_target;
	}

	universe->net = 0;
	universe->subnet = 0;
	universe->index = index;
	universe->dmx_count = dmx_count;
	universe->dmx_size = sizeof(*(universe->dmx)) * dmx_count;
	universe->mode = RRR_ARTNET_MODE_IDLE;
	memset(universe->dmx_fade_speed, fade_speed, sizeof(*(universe->dmx_fade_speed)) * dmx_count);

	goto out;
//	out_free_fade_speed:
//		rrr_free(universe->dmx_fade_speed);
	out_free_fade_target:
		rrr_free(universe->dmx_fade_target);
	out_free_dmx:
		rrr_free(universe->dmx);
	out:
		return ret;
}

static void __rrr_artnet_universe_private_data_cleanup (
		struct rrr_artnet_universe *universe
) {
	if (universe->private_data != NULL) {
		universe->private_data_destroy(universe->private_data);
		universe->private_data = NULL;
		universe->private_data_destroy = NULL;
	}
}

static void __rrr_artnet_universe_cleanup (
		struct rrr_artnet_universe *universe
) {
	RRR_FREE_IF_NOT_NULL(universe->dmx);
	RRR_FREE_IF_NOT_NULL(universe->dmx_fade_target);
	RRR_FREE_IF_NOT_NULL(universe->dmx_fade_speed);
	__rrr_artnet_universe_private_data_cleanup(universe);
	memset(universe, '\0', sizeof(*universe));
}

int rrr_artnet_node_new (
		struct rrr_artnet_node **result,
		enum rrr_artnet_node_type node_type
) {
	int ret = 0;

	struct rrr_artnet_node *node;
	int domain, type, protocol, ret_tmp;

	*result = NULL;

	if ((node = rrr_allocate_zero(sizeof(*node))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((node->node = artnet_new(NULL)) == NULL) {
		RRR_MSG_0("Failed to create artnet node in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	switch (node->node_type = node_type) {
		case RRR_ARTNET_NODE_TYPE_CONTROLLER:
			artnet_set_node_type(node->node, ARTNET_RAW);
			break;
		case RRR_ARTNET_NODE_TYPE_DEVICE:
			artnet_set_node_type(node->node, ARTNET_NODE);
			break;
		default:
			RRR_BUG("BUG: Unknown node type %i in %s\n", node_type, __func__);
	};

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
		goto out_stop;
	}

	RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
		if ((ret = __rrr_artnet_universe_init (
				universe, 
				i_,
				RRR_ARTNET_CHANNEL_MAX,
				1 /* Default fade speed */
		)) != 0) {
			RRR_MSG_0("Failed to init universe in %s\n", __func__);
			goto out_cleanup_universes;
		}

		if (node->node_type == RRR_ARTNET_NODE_TYPE_DEVICE) {
			int port_index = universe->index % 4;
			int bind_index = universe->index / 4;

			if ((ret_tmp = artnet_set_port_type (
					node->node,
					bind_index,
					port_index,
					ARTNET_ENABLE_OUTPUT,
					ARTNET_PORT_DMX
			)) != ARTNET_EOK) {
				RRR_MSG_0("Failed to set ArtNet port type in %s: %s\n", __func__, artnet_strerror());
				ret = 1;
				goto out_cleanup_universes;
			}

			if ((ret_tmp = artnet_set_port_addr (
					node->node,
					bind_index,
					port_index,
					ARTNET_OUTPUT_PORT,
					universe->index, /* Universe / address */
					0  /* No subnet */
			)) != ARTNET_EOK) {
				RRR_MSG_0("Failed to set ArtNet port address in %s: %s\n", __func__, artnet_strerror());
				ret = 1;
				goto out_cleanup_universes;
			}
		}
	RRR_ARTNET_UNIVERSE_ITERATE_END();

	*result = node;

	goto out;
	out_cleanup_universes:
		RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
			__rrr_artnet_universe_cleanup(universe);
		RRR_ARTNET_UNIVERSE_ITERATE_END();
	//out_remove_socket:
		rrr_socket_remove(node->fd);
	out_stop:
		artnet_stop(node->node);
	out_destroy:
		artnet_destroy(node->node);
	out_free:
		rrr_free(node);
	out:
		return ret;
}

void rrr_artnet_node_destroy (
		struct rrr_artnet_node *node
) {
	for (uint8_t i = 0; i < RRR_ARTNET_UNIVERSE_MAX; i++) {
		__rrr_artnet_universe_cleanup (&node->universes[i]);
	}
	if (node->event_queue != NULL) {
		rrr_event_collection_clear(&node->events);
	}
	artnet_stop(node->node);
	artnet_destroy(node->node);
	rrr_socket_remove(node->fd);
	rrr_free(node);
}

void rrr_artnet_node_dump (
		struct rrr_artnet_node *node
) {
	artnet_dump_config(node->node);
}

static uint16_t __rrr_artnet_make_addr (
		uint8_t net, uint8_t sub, uint8_t addr
) {
	return ((uint16_t) net << 8) | ((uint16_t) sub << 4) | ((uint16_t) (addr & 0x0f));
}

static void __rrr_artnet_process_node_entry (
		struct rrr_artnet_node *node,
		artnet_node_entry ne,
		uint8_t page_index
) {
	uint8_t bind_index = ne->page_bindindexes[page_index];
	artnet_node_data_t *d = &ne->pages[page_index];

	if (d->net_switch != 0 || d->sub_switch != 0) {
		RRR_DBG_3("Ignoring node entry with non-zero net switch %i and/or sub switch %i\n",
			d->net_switch, d->sub_switch);
		return;
	}

	// Ignore NumPorts parameter, just check if whether or not type
	// is set to DMX for each port.
	for (int j = 0; j < ARTNET_MAX_PORTS; j++) {
		if (d->porttypes[j] != 0x80) {
			// Ignore non-DMX or unused ports
			continue;
		}
	}

	if (RRR_DEBUGLEVEL_3) {
		RRR_MSG_3("--------- %d.%d.%d.%d page %d ------\n", ne->ip[0], ne->ip[1], ne->ip[2], ne->ip[3], page_index);
		RRR_MSG_3("   Bind index:    %d\n", bind_index);
		RRR_MSG_3("   Short Name:    %s\n", d->shortname);
		RRR_MSG_3("   Long Name:     %s\n", d->longname);
		RRR_MSG_3("   Node Report:   %s\n", d->nodereport);
		RRR_MSG_3("   Net:           0x%02x\n", d->net_switch);
		RRR_MSG_3("   Subnet:        0x%02x\n", d->sub_switch);
		RRR_MSG_3("   Port count:    %d\n", d->numbports);
		RRR_MSG_3("   Types:         0x%02x, 0x%02x, 0x%02x, 0x%02x\n", d->porttypes[0], d->porttypes[1], d->porttypes[2], d->porttypes[3] );
		RRR_MSG_3("   Input Status:  0x%02x, 0x%02x, 0x%02x, 0x%02x\n", d->goodinput[0], d->goodinput[1], d->goodinput[2], d->goodinput[3] );
		RRR_MSG_3("   Output Status: 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", d->goodoutput[0], d->goodoutput[1], d->goodoutput[2], d->goodoutput[3] );
		RRR_MSG_3("   Input Addrs:   0x%02x, 0x%02x, 0x%02x, 0x%02x\n", d->swin[0], d->swin[1], d->swin[2], d->swin[3] );
		RRR_MSG_3("   Output Addrs:  0x%02x, 0x%02x, 0x%02x, 0x%02x\n", d->swout[0], d->swout[1], d->swout[2], d->swout[3] );
		RRR_MSG_3("   Output Addrs:  %d, %d, %d, %d\n",
			__rrr_artnet_make_addr(d->net_switch, d->sub_switch, d->swout[0]),
			__rrr_artnet_make_addr(d->net_switch, d->sub_switch, d->swout[1]),
			__rrr_artnet_make_addr(d->net_switch, d->sub_switch, d->swout[2]),
			__rrr_artnet_make_addr(d->net_switch, d->sub_switch, d->swout[3])
		);
		RRR_MSG_3("-----------------------------------\n");
	}
}

static void __rrr_artnet_universe_fade_interpolate (
		struct rrr_artnet_universe *universe
) {
	assert(universe->dmx_size % 16 == 0);
	RRR_ASSERT(sizeof(*(universe->dmx) == 1),dmx_size_is_a_byte);
	RRR_ASSERT(sizeof(*(universe->dmx_fade_target) == 1),dmx_size_is_a_byte);

	for (int i = 0; i < universe->dmx_size; i += 1) {
		const rrr_artnet_dmx_t dmx_orig = universe->dmx[i];
		const rrr_artnet_dmx_t dmx_fade_speed = universe->dmx_fade_speed[i];
		const rrr_artnet_dmx_t dmx_target = universe->dmx_fade_target[i];

		if (universe->dmx[i] < dmx_target) {
			rrr_artnet_dmx_t dmx_new = dmx_orig + dmx_fade_speed;
			if (dmx_new < dmx_orig || dmx_new > dmx_target)
				dmx_new = dmx_target;
			universe->dmx[i] = dmx_new;
		}
		else if (universe->dmx[i] > dmx_target) {
			rrr_artnet_dmx_t dmx_new = dmx_orig - dmx_fade_speed;
			if (dmx_new > dmx_orig || dmx_new < dmx_target)
				dmx_new = dmx_target;
			universe->dmx[i] = dmx_new;
		}
	}
}

static void __rrr_artnet_universe_update (
		struct rrr_artnet_universe *universe
) {
	switch (universe->mode) {
		case RRR_ARTNET_MODE_IDLE:
		case RRR_ARTNET_MODE_STOPPED:
			break;
		case RRR_ARTNET_MODE_DEMO:
			memset(universe->dmx, (universe->animation_pos += 5) % 256, universe->dmx_size);
			break;
		default:
			__rrr_artnet_universe_fade_interpolate(universe);
			break;
	};
}

#define FAIL() \
	node->failure_callback(node->callback_arg)

static void __rrr_artnet_event_periodic_poll (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_artnet_node *node = arg;

	(void)(fd);
	(void)(flags);

	if (node->node_type != RRR_ARTNET_NODE_TYPE_CONTROLLER)
		return;

	if (*node->problem != '\0') {
		RRR_MSG_0("Warning: %s\n", node->problem);
		*node->problem = '\0';
	}

	if (artnet_send_poll(node->node, NULL, ARTNET_TTM_DEFAULT) != ARTNET_EOK) {
		RRR_MSG_0("Failed to send artnet poll in %s\n", __func__);
		FAIL();
	}
}

static void __rrr_artnet_event_periodic_update (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_artnet_node *node = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp;

	if (node->node_type != RRR_ARTNET_NODE_TYPE_CONTROLLER)
		return;

	RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
		__rrr_artnet_universe_update(universe);

		if (universe->mode == RRR_ARTNET_MODE_IDLE || universe->mode == RRR_ARTNET_MODE_STOPPED) {
			continue;
		}

		assert(universe->dmx_count <= 512);

		RRR_DBG_7("artnet dmx unicast to subscribers of universe %u\n", universe->index);

		if ((ret_tmp = artnet_send_dmx_remote(node->node, universe->index, (uint16_t) universe->dmx_count, universe->dmx)) < 0) {
			RRR_MSG_0("Failed to send unicast DMX data in %s: %s\n", __func__, artnet_strerror());
			FAIL();
			return;
		}

		if (ret_tmp == 0) {
			sprintf(node->problem, "No subscribers for universe %u", universe->index);
		}
		else {
			RRR_DBG_7("artnet universe %u had %i subscribers while sending\n", universe->index, ret_tmp);
		}
	RRR_ARTNET_UNIVERSE_ITERATE_END();
}

static void __rrr_artnet_event_read (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_artnet_node *node = arg;

	(void)(fd);
	(void)(flags);

	int ret_tmp;

	if ((ret_tmp = artnet_read(node->node, 0)) != ARTNET_EOK) {
		if (ret_tmp == ARTNET_EREMOTE) {
			RRR_MSG_0("Warning: Failed to process artnet data from remote: %s\n",
				artnet_strerror());
		}
		else {
			RRR_MSG_0("Failed to read artnet data in %s\n", __func__);
		}
		FAIL();
	}
}

static int __rrr_artnet_handler_poll (
		artnet_node n,
		void *pp,
		void *d
) {
	struct rrr_artnet_node *node = d;

	(void)(node);
	(void)(n);
	(void)(pp);

	int ret_tmp;

	// Poll

	if (node->node_type != RRR_ARTNET_NODE_TYPE_DEVICE)
		return ARTNET_EOK;

	RRR_ASSERT(RRR_ARTNET_UNIVERSE_MAX % 4 == 0,universe_max_must_be_divisible_by_four);
	for (uint8_t i = 0; i < RRR_ARTNET_UNIVERSE_MAX / 4; i++) {
		if ((ret_tmp = artnet_send_poll_reply(node->node, i)) != ARTNET_EOK) {
			RRR_MSG_0("Failed to send poll reply in %s: %s\n", artnet_strerror());
			FAIL();
			return ret_tmp;
		}
	}

	return ARTNET_EOK;
}

static int __rrr_artnet_handler_reply (
		artnet_node n,
		void *pp,
		void *d
) {
	struct rrr_artnet_node *node = d;

	(void)(node);
	(void)(n);
	(void)(pp);

	// Poll reply

	if (node->node_type != RRR_ARTNET_NODE_TYPE_CONTROLLER)
		return ARTNET_EOK;

	return ARTNET_EOK;
}

static int __rrr_artnet_hook_reply_node (
		artnet_node_entry ne,
		uint8_t page_index,
		void *data
) {
	struct rrr_artnet_node *node = data;

	// Node entry found in poll reply

	if (node->node_type != RRR_ARTNET_NODE_TYPE_CONTROLLER)
		return ARTNET_EOK;

	__rrr_artnet_process_node_entry(node, ne, page_index);

	return ARTNET_EOK;
}

void rrr_artnet_universe_set_mode (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		enum rrr_artnet_mode mode
) {
	SET_UNIVERSE();
	assert (mode <= RRR_ARTNET_MODE_MANAGED);

	RRR_DBG_3("artnet universe %u set mode to %i\n",
			universe_i, mode);

	universe->mode = mode;
}

enum rrr_artnet_mode rrr_artnet_universe_get_mode (
		struct rrr_artnet_node *node,
		uint8_t universe_i
) {
	SET_UNIVERSE();
	return universe->mode;
}

void rrr_artnet_set_private_data (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		void *data,
		void (*destroy)(void *data)
) {
	SET_UNIVERSE();
	__rrr_artnet_universe_private_data_cleanup(universe);
	universe->private_data = data;
	universe->private_data_destroy = destroy;
}

void rrr_artnet_set_fade_speed (
		struct rrr_artnet_node *node,
		uint8_t fade_speed
) {
	assert(fade_speed > 0);
	assert(node->node_type == RRR_ARTNET_NODE_TYPE_CONTROLLER);

	RRR_DBG_3("artnet set fade speed %u all universes\n", fade_speed);

	RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
		memset(universe->dmx_fade_speed, fade_speed, sizeof(*(universe->dmx_fade_speed)));
	RRR_ARTNET_UNIVERSE_ITERATE_END();
}

int rrr_artnet_universe_iterate (
		struct rrr_artnet_node *node,
		int (*cb)(uint8_t universe_i, enum rrr_artnet_mode mode, void *private_data, void *private_arg),
		void *private_arg
) {
	int ret = 0;

	RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
		if ((ret = cb (i_, universe->mode, universe->private_data, private_arg)) != 0) {
			goto out;
		}
	RRR_ARTNET_UNIVERSE_ITERATE_END();

	out:
	return ret;
}

int rrr_artnet_events_register (
		struct rrr_artnet_node *node,
		struct rrr_event_queue *event_queue,
		void (*failure_callback)(void *arg),
		void (*incorrect_mode_callback)(struct rrr_artnet_node *node, uint8_t universe_i, enum rrr_artnet_mode active_mode, enum rrr_artnet_mode required_mode),
		void *callback_arg
) {
	int ret = 0;

	node->event_queue = event_queue;

	rrr_event_collection_init(&node->events, node->event_queue);

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

	if ((ret = rrr_event_collection_push_periodic (
			&node->event_periodic_update,
			&node->events,
			__rrr_artnet_event_periodic_update,
			node,
			20 * 1000 // 20ms
	)) != 0) {
		RRR_MSG_0("Failed to create periodic update event in %s\n", __func__);
		goto out_cleanup;
	}

	EVENT_ACTIVATE(node->event_periodic_update);
	EVENT_ADD(node->event_periodic_update);

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

	assert(artnet_set_handler(node->node, ARTNET_POLL_HANDLER, __rrr_artnet_handler_poll, node) == ARTNET_EOK);
	assert(artnet_set_reply_node_hook (node->node, __rrr_artnet_hook_reply_node, node) == ARTNET_EOK);
	assert(artnet_set_handler(node->node, ARTNET_REPLY_HANDLER, __rrr_artnet_handler_reply, node) == ARTNET_EOK);
	assert(artnet_set_bcast_limit(node->node, RRR_ARTNET_BCAST_LIMIT) == ARTNET_EOK);

	node->failure_callback = failure_callback;
	node->incorrect_mode_callback = incorrect_mode_callback;
	node->callback_arg = callback_arg;

	goto out;
	out_cleanup:
		rrr_event_collection_clear(&node->events);
	out:
		return ret;
}

#define CHECK_DMX_POS()                                  \
    assert(dmx_pos < universe->dmx_size);                \
    assert(dmx_count <= universe->dmx_size);             \
    assert(dmx_pos + dmx_count <= universe->dmx_size);

#define CHECK_NODE_TYPE(type)                                                    \
    assert(node->node_type == type)

#define CHECK_MODE(_mode)                                                        \
    do { if (universe->mode != _mode) {                                          \
        node->incorrect_mode_callback(node, universe_i, universe->mode, _mode);  \
    }} while(0)

void rrr_artnet_universe_get_private_data (
		void **private_data,
		struct rrr_artnet_node *node,
		uint8_t universe_i
) {
	SET_UNIVERSE();
	*private_data = universe->private_data;
}

void rrr_artnet_universe_set_dmx_abs (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		uint8_t value
) {
	SET_UNIVERSE();
	CHECK_DMX_POS();
	CHECK_MODE(RRR_ARTNET_MODE_MANAGED);
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	RRR_DBG_3("artnet universe %u set absolute value for channel %u through %u to %u\n",
			universe_i, dmx_pos, dmx_count + dmx_pos, value);

	memset(universe->dmx + dmx_pos, value, dmx_count);
	memset(universe->dmx_fade_target + dmx_pos, value, dmx_count);
}

void rrr_artnet_universe_set_dmx_fade (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		uint8_t fade_speed,
		uint8_t value
) {
	SET_UNIVERSE();
	CHECK_DMX_POS();
	CHECK_MODE(RRR_ARTNET_MODE_MANAGED);
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	RRR_DBG_3("artnet universe %u set fade target for channel %u through %u to %u speed %u\n",
			universe_i, dmx_pos, dmx_count + dmx_pos, value, fade_speed);

	memset(universe->dmx_fade_target + dmx_pos, value, dmx_count);
	memset(universe->dmx_fade_speed + dmx_pos, fade_speed, dmx_count);
}

void rrr_artnet_universe_set_dmx_abs_raw (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		const rrr_artnet_dmx_t *dmx
) {
	SET_UNIVERSE();
	CHECK_DMX_POS();
	CHECK_MODE(RRR_ARTNET_MODE_MANAGED);
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	RRR_DBG_3("artnet universe %u set absolute value for channel %u through %u\n",
			universe_i, dmx_pos, dmx_count + dmx_pos);

	memcpy(universe->dmx + dmx_pos, dmx, dmx_count);
	memcpy(universe->dmx_fade_target + dmx_pos, dmx, dmx_count);
}

void rrr_artnet_universe_set_dmx_fade_raw (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		uint8_t fade_speed,
		const rrr_artnet_dmx_t *dmx
) {
	SET_UNIVERSE();
	CHECK_DMX_POS();
	CHECK_MODE(RRR_ARTNET_MODE_MANAGED);
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	RRR_DBG_3("artnet universe %u set fade value for channel %u through %u speed %u\n",
			universe_i, dmx_pos, dmx_count + dmx_pos, fade_speed);

	memcpy(universe->dmx_fade_target + dmx_pos, dmx, dmx_count);
	memset(universe->dmx_fade_speed + dmx_pos, fade_speed, dmx_count);
}

void rrr_artnet_universe_get_dmx (
		const rrr_artnet_dmx_t **dmx,
		uint16_t *dmx_count,
		struct rrr_artnet_node *node,
		uint8_t universe_i
) {
	SET_UNIVERSE();
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	*dmx = universe->dmx;
	*dmx_count = universe->dmx_count;
}

void rrr_artnet_universe_update (
		struct rrr_artnet_node *node,
		uint8_t universe_i
) {
	SET_UNIVERSE();
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	__rrr_artnet_universe_update(universe);
}

int rrr_artnet_universe_check_range (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint64_t dmx_pos,
		uint64_t dmx_count
) {
	int ret = 0;

	SET_UNIVERSE();
	CHECK_NODE_TYPE(RRR_ARTNET_NODE_TYPE_CONTROLLER);

	if (!(dmx_pos < universe->dmx_size)) {
		RRR_MSG_0("artnet universe %u DMX position %" PRIu64 " exceeds maximum of %u\n",
				universe_i, dmx_pos, universe->dmx_size - 1);
		ret = 1;
	}

	if (!(dmx_count <= universe->dmx_size)) {
		RRR_MSG_0("artnet universe %u DMX count %" PRIu64 " exceeds maximum of %u\n",
				universe_i, dmx_count, universe->dmx_size);
		ret = 1;
	}

	if (!(dmx_pos + dmx_count <= universe->dmx_size)) {
		RRR_MSG_0("artnet universe %u DMX pos+count %" PRIu64 "+%" PRIu64 " exceeds maximum of %u\n",
				universe_i, dmx_pos, dmx_count, universe->dmx_size);
		ret = 1;
	}

	return ret;
}
