/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_IP_BUFFER_ENTRY_COLLECTION_H
#define RRR_IP_BUFFER_ENTRY_COLLECTION_H

#include "util/linked_list.h"

struct rrr_ip_buffer_entry;

struct rrr_ip_buffer_entry_collection {
	RRR_LL_HEAD(struct rrr_ip_buffer_entry);
};

void rrr_ip_buffer_entry_collection_clear (
		struct rrr_ip_buffer_entry_collection *collection
);
void rrr_ip_buffer_entry_collection_clear_void (
		void *arg
);
void rrr_ip_buffer_entry_collection_sort (
		struct rrr_ip_buffer_entry_collection *target,
		int (*compare)(void *message_a, void *message_b)
);

#endif /* RRR_IP_BUFFER_ENTRY_COLLECTION_H */
