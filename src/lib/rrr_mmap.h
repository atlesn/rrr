/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_MMAP_H
#define RRR_MMAP_H

#include <pthread.h>
#include <inttypes.h>

struct rrr_mmap {
	  pthread_mutex_t mutex;
	  int usercount;
	  uint64_t heap_size;
	  char name[64];
	  void *heap;
};

void rrr_mmap_free(struct rrr_mmap *mmap, void *ptr);
void rrr_mmap_dump_indexes (struct rrr_mmap *mmap);
void *rrr_mmap_allocate(struct rrr_mmap *mmap, uint64_t req_size);
int rrr_mmap_heap_reallocate (struct rrr_mmap *mmap, uint64_t heap_size);
int rrr_mmap_new (struct rrr_mmap **target, uint64_t heap_size, const char *name);
void rrr_mmap_incref (struct rrr_mmap *mmap);
void rrr_mmap_destroy (struct rrr_mmap *mmap);

#endif /* RRR_MMAP_H */
