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
#include <sys/socket.h>
#include <sys/types.h>

#include "http_session.h"
#include "http_server_common.h"

struct rrr_net_transport;
struct rrr_thread;
struct rrr_http_part;

struct rrr_http_server_worker_config_data {
	struct rrr_net_transport *transport;
	int transport_handle;

	struct sockaddr_storage addr;
	socklen_t addr_len;
	ssize_t read_max_size;

	int disable_http2;

	struct rrr_http_server_callbacks callbacks;
};

struct rrr_http_server_worker_preliminary_data {
	// Locking is provided by using thread framework lock wrapper.
	// DO NOT access this struct except from in callback of the wrapper.

	// The worker will copy data members to it's own memory. DO NOT
	// add pointers to data which may be modified outside of thread lock
	// wrapper.

	struct rrr_http_server_worker_config_data config_data;
	int error;
};

struct rrr_http_server_worker_data {
	struct rrr_http_server_worker_config_data config_data;
	struct rrr_thread *thread;
	rrr_http_unique_id unique_id;
	int request_complete;
	uint64_t bytes_total;

	// May be set by application in websocket handshake callback, free()
	// will be called on this when the worker exits
	void *websocket_application_data;
};

int rrr_http_server_worker_preliminary_data_new (
		struct rrr_http_server_worker_preliminary_data **result,
		const struct rrr_http_server_callbacks *callbacks,
		int disable_http2
);
void rrr_http_server_worker_preliminary_data_destroy_if_not_null (
		struct rrr_http_server_worker_preliminary_data *worker_data
);
void *rrr_http_server_worker_thread_entry_intermediate (
		struct rrr_thread *thread
);

#endif /* RRR_HTTP_SERVER_WORKER_H */
