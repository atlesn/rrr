/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MMAP_STATS_H
#define RRR_MMAP_STATS_H

#include <stdint.h>

struct rrr_mmap_stats {
	uint64_t mmap_total_count;
	uint64_t mmap_total_empty_count;
	uint64_t mmap_total_bad_count;
	uint64_t mmap_total_heap_size;
	uint64_t mmap_total_allocation;
	uint64_t mmap_total_free;
};

#endif /* RRR_MMAP_STATS_H */
