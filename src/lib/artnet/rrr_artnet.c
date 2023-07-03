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

#ifdef RRR_HAVE_SIMD_128
#include <immintrin.h>
#endif

#define RRR_ARTNET_UNIVERSE_MAX 16
#define RRR_ARTNET_CHANNEL_MAX 512

#define SET_UNIVERSE()                                                   \
    assert(universe_i < RRR_ARTNET_UNIVERSE_MAX);                        \
    struct rrr_artnet_universe *universe = &node->universes[universe_i]


struct rrr_artnet_universe {
	uint8_t index;

	rrr_artnet_dmx_t *dmx;
	rrr_artnet_dmx_t *dmx_fade_target;
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

	struct rrr_artnet_universe universes[RRR_ARTNET_UNIVERSE_MAX];

	struct rrr_event_queue *event_queue;
	struct rrr_event_collection events;
	rrr_event_handle event_periodic_poll;
	rrr_event_handle event_periodic_update;
	rrr_event_handle event_read;

	void (*failure_callback)(void *arg);
	void *callback_arg;
};

#define RRR_ARTNET_UNIVERSE_ITERATE_BEGIN()                      \
  do { for (uint8_t i = 0; i < RRR_ARTNET_UNIVERSE_MAX; i++) {   \
    struct rrr_artnet_universe *universe = &(node->universes[i])

#define RRR_ARTNET_UNIVERSE_ITERATE_END()                        \
  }} while(0)

static int __rrr_artnet_universe_init (
		struct rrr_artnet_universe *universe,
		uint8_t index,
		uint16_t dmx_count
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

	universe->index = index;
	universe->dmx_count = dmx_count;
	universe->dmx_size = sizeof(*(universe->dmx)) * dmx_count;
	universe->mode = RRR_ARTNET_MODE_IDLE;

	goto out;
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
	__rrr_artnet_universe_private_data_cleanup(universe);
	memset(universe, '\0', sizeof(*universe));
}

int rrr_artnet_node_new (
		struct rrr_artnet_node **result
) {
	int ret = 0;

	struct rrr_artnet_node *node;
	int domain, type, protocol;

	const int verbose = 0;

	*result = NULL;

	if ((node = rrr_allocate_zero(sizeof(*node))) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if ((node->node = artnet_new(NULL, verbose)) == NULL) {
		RRR_MSG_0("Failed to create artnet node in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	artnet_set_node_type(node->node, ARTNET_RAW);

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
		if ((ret = __rrr_artnet_universe_init (universe, i, RRR_ARTNET_CHANNEL_MAX)) != 0) {
			RRR_MSG_0("Failed to init universe in %s\n", __func__);
			goto out_cleanup_universes;
		}
	RRR_ARTNET_UNIVERSE_ITERATE_END();

	*result = node;

	goto out;
	out_cleanup_universes:
		RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
			__rrr_artnet_universe_cleanup (&node->universes[i]);
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

static void __rrr_artnet_dump_nodes (
		struct rrr_artnet_node *node
) {
	if (!RRR_DEBUGLEVEL_3) {
		return;
	}

	artnet_node_list nl = artnet_get_nl(node->node);

	for (artnet_node_entry ne = artnet_nl_first(nl); ne != NULL; ne = artnet_nl_next(nl)) {
		RRR_MSG_3("--------- %d.%d.%d.%d -------------\n", ne->ip[0], ne->ip[1], ne->ip[2], ne->ip[3]);
		RRR_MSG_3("Short Name:   %s\n", ne->shortname);
		RRR_MSG_3("Long Name:    %s\n", ne->longname);
		RRR_MSG_3("Node Report:  %s\n", ne->nodereport);
		RRR_MSG_3("Subnet:       0x%02x\n", ne->sub);
		RRR_MSG_3("Numb Ports:   %d\n", ne->numbports);
		RRR_MSG_3("Input Addrs:  0x%02x, 0x%02x, 0x%02x, 0x%02x\n", ne->swin[0], ne->swin[1], ne->swin[2], ne->swin[3] );
		RRR_MSG_3("Output Addrs: 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", ne->swout[0], ne->swout[1], ne->swout[2], ne->swout[3] );
		RRR_MSG_3("----------------------------------\n");
	}
}

static void __rrr_artnet_universe_fade_interpolate (
		struct rrr_artnet_universe *universe
) {
	const __m128i step_size_vec = _mm_set1_epi8(1);

	assert(universe->dmx_size % 16 == 0);
	RRR_ASSERT(sizeof(*(universe->dmx) == 1),dmx_size_is_a_byte);
	RRR_ASSERT(sizeof(*(universe->dmx_fade_target) == 1),dmx_size_is_a_byte);

#ifdef RRR_HAVE_SIMD_128
	for (int i = 0; i < universe->dmx_size; i += 16) {
		__m128i current_vec = _mm_loadu_si128((__m128i*) (universe->dmx + i));
		__m128i target_vec = _mm_loadu_si128((__m128i*) (universe->dmx_fade_target + i));

		__m128i cmp_less = _mm_cmplt_epi8(target_vec, current_vec);
		__m128i cmp_greater = _mm_cmpgt_epi8(target_vec, current_vec);

		__m128i inc_vec = _mm_and_si128(cmp_less, step_size_vec);
		__m128i dec_vec = _mm_and_si128(cmp_greater, step_size_vec);

		current_vec = _mm_add_epi8(current_vec, inc_vec);
		current_vec = _mm_sub_epi8(current_vec, dec_vec);

		_mm_storeu_si128((__m128i*) (universe->dmx + i), current_vec);
	}
#else
    for (int i = 0; i < universe->dmx_size; i += 1) {
	    if (universe->dmx[i] < universe->dmx_fade_target[i])
		    universe->dmx[i] += 1;
	    else if (universe->dmx[i] > universe->dmx_fade_target[i])
		    universe->dmx[i] -= 1;
    }
#endif
}

static void __rrr_artnet_universe_update (
		struct rrr_artnet_universe *universe
) {
	switch (universe->mode) {
		case RRR_ARTNET_MODE_IDLE:
			break;
		case RRR_ARTNET_MODE_DEMO:
			memset(universe->dmx, (universe->animation_pos += 5) % 256, universe->dmx_size);
			break;
		default:
			// TODO : Set managed data
		//	memset(universe->dmx, 0, universe->dmx_size);
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

	if (artnet_send_poll(node->node, NULL, ARTNET_TTM_DEFAULT) != ARTNET_EOK) {
		RRR_MSG_0("Failed to send artnet poll in %s\n", __func__);
		FAIL();
	}

	__rrr_artnet_dump_nodes(node);
}

static void __rrr_artnet_event_periodic_update (
		evutil_socket_t fd,
		short flags,
		void *arg
) {
	struct rrr_artnet_node *node = arg;

	(void)(fd);
	(void)(flags);

	uint8_t dmx_tmp = 0;

	RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
		__rrr_artnet_universe_update(universe);

		if (universe->mode == RRR_ARTNET_MODE_IDLE) {
			RRR_LL_ITERATE_NEXT();
		}

		if (artnet_raw_send_dmx(node->node, universe->index, universe->dmx_count, universe->dmx) != ARTNET_EOK) {
			RRR_MSG_0("Failed to send DMX data in %s: %s\n", __func__, artnet_strerror());
			FAIL();
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

	if (artnet_read(node->node, 0) != ARTNET_EOK) {
		RRR_MSG_0("Failed to read artnet data in %s\n", __func__);
		FAIL();
	}
}

static int __rrr_artnet_handler_reply (
		artnet_node n,
		void *pp,
		void *d
) {
	struct rrr_artnet_node *node = d;

	(void)(node);

	// Poll reply

	return 0;
}

void rrr_artnet_universe_set_mode (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		enum rrr_artnet_mode mode
) {
	SET_UNIVERSE();
	assert (mode <= RRR_ARTNET_MODE_MANAGED);
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

int rrr_artnet_universe_iterate (
		struct rrr_artnet_node *node,
		int (*cb)(uint8_t universe_i, enum rrr_artnet_mode mode, void *private_data, void *private_arg),
		void *private_arg
) {
	int ret = 0;

	RRR_ARTNET_UNIVERSE_ITERATE_BEGIN();
		if ((ret = cb (i, universe->mode, universe->private_data, private_arg)) != 0) {
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
			20 * 1000 // 20 ms
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

	assert (artnet_set_handler(node->node, ARTNET_REPLY_HANDLER, __rrr_artnet_handler_reply, node) == ARTNET_EOK);

	node->failure_callback = failure_callback;
	node->callback_arg = callback_arg;

	goto out;
	out_cleanup:
		rrr_event_collection_clear(&node->events);
	out:
		return ret;
}

void rrr_artnet_universe_set_dmx_fade (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		rrr_artnet_dmx_t *dmx,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		uint8_t value
) {
	SET_UNIVERSE();
	assert(dmx_pos < universe->dmx_size);
	assert(dmx_count <= universe->dmx_size);
	assert(dmx_pos + dmx_count <= universe->dmx_size);

	RRR_DBG_3("artnet universe %u set fade target for channel %u through %u to %u\n",
			universe_i, dmx_pos, dmx_count + dmx_pos, value);

	memset(universe->dmx_fade_target + dmx_pos, value, dmx_count);
}

void rrr_artnet_universe_get_dmx (
		const rrr_artnet_dmx_t **dmx,
		uint16_t *dmx_count,
		struct rrr_artnet_node *node,
		uint8_t universe_i
) {
	SET_UNIVERSE();
	*dmx = universe->dmx;
	*dmx_count = universe->dmx_count;
}

void rrr_artnet_universe_update (
		struct rrr_artnet_node *node,
		uint8_t universe_i
) {
	SET_UNIVERSE();
	__rrr_artnet_universe_update(universe);
}
