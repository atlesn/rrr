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

#ifndef RRR_ARTNET_H
#define RRR_ARTNET_H

struct rrr_artnet_node;
struct rrr_event_queue;

typedef uint8_t rrr_artnet_dmx_t;

enum rrr_artnet_mode {
	RRR_ARTNET_MODE_IDLE,
	RRR_ARTNET_MODE_DEMO,
	RRR_ARTNET_MODE_MANAGED
};

int rrr_artnet_node_new (
		struct rrr_artnet_node **result
);
void rrr_artnet_node_destroy (
		struct rrr_artnet_node *node
);
void rrr_artnet_universe_set_mode (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		enum rrr_artnet_mode mode
);
enum rrr_artnet_mode rrr_artnet_universe_get_mode (
		struct rrr_artnet_node *node,
		uint8_t universe_i
);
void rrr_artnet_set_private_data (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		void *data,
		void (*destroy)(void *data)
);
int rrr_artnet_universe_iterate (
		struct rrr_artnet_node *node,
		int (*cb)(uint8_t universe_i, enum rrr_artnet_mode mode, void *private_data, void *private_arg),
		void *private_arg
);
int rrr_artnet_events_register (
		struct rrr_artnet_node *node,
		struct rrr_event_queue *event_queue,
		uint64_t update_interval_ms,
		void (*failure_callback)(void *arg),
		void (*incorrect_mode_callback)(struct rrr_artnet_node *node, uint8_t universe_i, enum rrr_artnet_mode active_mode, enum rrr_artnet_mode required_mode),
		void *callback_arg
);
void rrr_artnet_universe_get_private_data (
		void **private_data,
		struct rrr_artnet_node *node,
		uint8_t universe_i
);
void rrr_artnet_universe_set_dmx_abs (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		uint8_t value
);
void rrr_artnet_universe_set_dmx_fade (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		uint8_t value
);
void rrr_artnet_universe_set_dmx_abs_raw (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		const rrr_artnet_dmx_t *dmx
);
void rrr_artnet_universe_set_dmx_fade_raw (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint16_t dmx_pos,
		uint16_t dmx_count,
		const rrr_artnet_dmx_t *dmx
);
void rrr_artnet_universe_get_dmx (
		const rrr_artnet_dmx_t **dmx,
		uint16_t *dmx_count,
		struct rrr_artnet_node *node,
		uint8_t universe_i
);
void rrr_artnet_universe_update (
		struct rrr_artnet_node *node,
		uint8_t universe_i
);
int rrr_artnet_universe_check_range (
		struct rrr_artnet_node *node,
		uint8_t universe_i,
		uint64_t dmx_pos,
		uint64_t dmx_count
);

#endif /* RRR_ARTNET_H */
