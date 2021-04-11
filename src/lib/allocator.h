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

#ifndef RRR_ALLOCATOR_H
#define RRR_ALLOCATOR_H

#include <stddef.h>

#define RRR_ALLOCATOR_GROUP_DEFAULT	0
#define RRR_ALLOCATOR_GROUP_MSG		1

#define RRR_ALLOCATOR_FREE_IF_NOT_NULL(arg) do{if((arg) != NULL){rrr_free(arg);(arg)=NULL;}}while(0)

void *rrr_allocate (size_t bytes);
void *rrr_allocate_group (size_t bytes, int group);
void rrr_free (void *ptr);
void *rrr_reallocate (void *ptr_old, size_t bytes_old, size_t bytes_new);
void *rrr_reallocate_group (void *ptr_old, size_t bytes_old, size_t bytes_new, int group);
char *rrr_strdup (const char *str);
void rrr_allocator_cleanup (void);
void rrr_allocator_maintenance (void);

#endif /* RRR_ALLOCATOR_H */
