/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_FIFO_COMMON_H
#define RRR_FIFO_COMMON_H

#define RRR_FIFO_COMMON_OK 		0
#define RRR_FIFO_COMMON_GLOBAL_ERR 	(1<<0)
#define RRR_FIFO_COMMON_CALLBACK_ERR 	(1<<1)

#define RRR_FIFO_COMMON_SEARCH_KEEP     0
#define RRR_FIFO_COMMON_SEARCH_STOP     (1<<3)
#define RRR_FIFO_COMMON_SEARCH_GIVE     (1<<4)
#define RRR_FIFO_COMMON_SEARCH_FREE     (1<<5)
#define RRR_FIFO_COMMON_SEARCH_REPLACE  (1<<6)

#define RRR_FIFO_COMMON_WRITE_AGAIN     (1<<10)
#define RRR_FIFO_COMMON_WRITE_DROP 	(1<<11)
#define RRR_FIFO_COMMON_WRITE_ORDERED   (1<<12)

#define RRR_FIFO_COMMON_READ_CALLBACK_ARGS \
	void *arg, char *data, unsigned long int size

#define RRR_FIFO_COMMON_WRITE_CALLBACK_ARGS \
	char **data, unsigned long int *size, uint64_t *order, void *arg


#endif /* RRR_FIFO_COMMON_H */
