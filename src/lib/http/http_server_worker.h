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

#ifndef RRR_HTTP_SERVER_WORKER_H
#define RRR_HTTP_SERVER_WORKER_H

#include <stdio.h>
#include <pthread.h>

struct rrr_net_transport;
struct rrr_thread;

struct rrr_http_server_worker_preliminary_data {
	// This lock only protects our data members, not what they point to.
	pthread_mutex_t lock;

	// DO NOT put allocated data in this struct, like char *, such data
	// would not have proper memory fencing.

	int error;

	struct rrr_net_transport *transport;
	int transport_handle;

	ssize_t read_max_size;
};

struct rrr_http_server_worker_data {
	struct rrr_net_transport *transport;
	int transport_handle;

	ssize_t read_max_size;

	int receive_complete;

	unsigned int response_code;
};

int rrr_http_server_worker_preliminary_data_new (
		struct rrr_http_server_worker_preliminary_data **result
);
void rrr_http_server_worker_preliminary_data_destroy (
		struct rrr_http_server_worker_preliminary_data *worker_data
);
void rrr_http_server_worker_preliminary_data_destroy_void (
		void *private_data
);
void *rrr_http_server_worker_thread_entry (
		struct rrr_thread *thread
);

#endif /* RRR_HTTP_SERVER_WORKER_H */
