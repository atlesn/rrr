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

int rrr_artnet_node_new (
		struct rrr_artnet_node **result
);
void rrr_artnet_node_destroy (
		struct rrr_artnet_node *node
);
int rrr_artnet_events_register (
		struct rrr_artnet_node *node,
		struct rrr_event_queue *event_queue,
		void (*failure_callback)(void *arg),
		void *callback_arg
);

#endif /* RRR_ARTNET_H */
