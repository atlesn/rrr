
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

#include "test.h"
#include "../lib/log.h"

#include "../lib/artnet/rrr_artnet.h"

int rrr_test_artnet (void) {
	int ret = 0;

	struct rrr_artnet_node *node;

	if ((ret = rrr_artnet_node_new(&node)) != 0) {
		RRR_MSG_0("Failed to create artnet node in %s\n", __func__);
		goto out;
	}

	const rrr_artnet_dmx_t *dmx;
	uint16_t dmx_count;

	TEST_MSG("Check DMX channel size...\n");
	rrr_artnet_universe_get_dmx(&dmx, &dmx_count, node, 0);
	assert(dmx_count == 512);

	TEST_MSG("Check zero initialized...\n");
	for (uint16_t i = 0; i < dmx_count; i++) {
		assert(*(dmx + i) == 0);
	}

	rrr_artnet_universe_set_mode(node, 0, RRR_ARTNET_MODE_MANAGED);

	TEST_MSG("Check artnet set...\n");
	rrr_artnet_universe_set_dmx_abs(node, 0, 0, 16, 2);
	for (uint16_t i = 0; i < 16; i++) {
		assert(*(dmx + i) == 2);
	}
	for (uint16_t i = 16; i < dmx_count; i++) {
		assert(*(dmx + i) == 0);
	}

	// Run one animation step incrementing first 16 channels by 1
	TEST_MSG("Check artnet fade...\n");
	rrr_artnet_universe_set_mode(node, 0, RRR_ARTNET_MODE_MANAGED);
	rrr_artnet_universe_set_dmx_fade(node, 0, 0, 16, 1, 255);
	rrr_artnet_universe_update(node, 0);
	for (uint16_t i = 0; i < 16; i++) {
		assert(*(dmx + i) == 3);
	}
	for (uint16_t i = 16; i < dmx_count; i++) {
		assert(*(dmx + i) == 0);
	}

	rrr_artnet_node_destroy(node);

	out:
	return ret;
}
