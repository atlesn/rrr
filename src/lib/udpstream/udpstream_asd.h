/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_UDPSTREAM_ASD_H
#define RRR_UDPSTREAM_ASD_H

#include <stdint.h>

#include "udpstream.h"

#define RRR_UDPSTREAM_ASD_OK                    RRR_UDPSTREAM_OK
#define RRR_UDPSTREAM_ASD_HARD_ERR              RRR_UDPSTREAM_HARD_ERR
#define RRR_UDPSTREAM_ASD_NOT_READY             RRR_UDPSTREAM_NOT_READY

struct rrr_msg_holder;
struct rrr_event_queue;
struct rrr_udpstream_asd;

int rrr_udpstream_asd_queue_and_incref_message (
		struct rrr_udpstream_asd *session,
		struct rrr_msg_holder *message
);
void rrr_udpstream_asd_destroy (
		struct rrr_udpstream_asd *session
);
int rrr_udpstream_asd_new (
		struct rrr_udpstream_asd **target,
		struct rrr_event_queue *queue,
		unsigned int local_port,
		const char *remote_host,
		const char *remote_port,
		uint32_t client_id,
		int accept_connections,
		int disallow_ip_swap,
		int v4_only,
		int reset_on_next_connect,
		int (*allocator_callback)(RRR_UDPSTREAM_ALLOCATOR_CALLBACK_ARGS),
		void *allocator_callback_arg,
		int (*receive_callback)(struct rrr_msg_holder *message, void *arg),
		void *receive_callback_arg
);
void rrr_udpstream_asd_get_and_reset_counters (
		unsigned int *sent_count,
		unsigned int *delivered_count,
		struct rrr_udpstream_asd *session
);
#endif /* RRR_UDPSTREAM_ASD_H */
