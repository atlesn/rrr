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

#ifndef RRR_NET_TRANSPORT_H
#define RRR_NET_TRANSPORT_H

#include <sys/types.h>
#include <pthread.h>

#include "rrr_socket_constants.h"
#include "linked_list.h"

// Use same numbering system as socket subsystem, saves us from translating
// return values in many cases
#define RRR_NET_TRANSPORT_READ_OK				RRR_SOCKET_OK
#define RRR_NET_TRANSPORT_READ_HARD_ERROR		RRR_SOCKET_HARD_ERROR
#define RRR_NET_TRANSPORT_READ_SOFT_ERROR		RRR_SOCKET_SOFT_ERROR
#define RRR_NET_TRANSPORT_READ_INCOMPLETE		RRR_SOCKET_READ_INCOMPLETE
#define RRR_NET_TRANSPORT_READ_READ_EOF			RRR_SOCKET_READ_EOF

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH \
	RRR_SOCKET_READ_COMPLETE_METHOD_TARGET_LENGTH

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE \
	RRR_SOCKET_READ_COMPLETE_METHOD_CONN_CLOSE

enum rrr_net_transport_type {
	RRR_NET_TRANSPORT_PLAIN,
	RRR_NET_TRANSPORT_TLS
};

struct rrr_net_transport_handle {
	RRR_LL_NODE(struct rrr_net_transport_handle);
	int handle;
	void *private_ptr;
};

struct rrr_net_transport_handle_collection {
	RRR_LL_HEAD(struct rrr_net_transport_handle);
	pthread_mutex_t lock;
};

#define RRR_NET_TRANSPORT_HEAD \
	const struct rrr_net_transport_methods *methods; \
	struct rrr_net_transport_handle_collection handles

struct rrr_net_transport {
	RRR_NET_TRANSPORT_HEAD;
};

struct rrr_net_transport_read_session {
	// Populated by transport layer
	const char *buffer;
	ssize_t buffer_size;
	ssize_t wpos;

	// Populated by get_target_size-method
	int read_complete_method;
	ssize_t target_size;

	// Overshoot if we read too many bytes
	const char *overshoot;
	ssize_t overshoot_size;
};

struct rrr_net_transport_methods {
	void (*destroy)(struct rrr_net_transport *transport);
	int (*connect)(int *handle, struct rrr_net_transport *transport, unsigned int port, const char *host);
	int (*close)(struct rrr_net_transport *transport, void *private_ptr, int handle);
	int (*read_message)(
		struct rrr_net_transport *transport,
		int transport_handle,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_net_transport_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_net_transport_read_session *read_session, void *arg),
		void *complete_callback_arg
	);
	int (*send)(
		struct rrr_net_transport *transport,
		int transport_handle,
		void *data,
		ssize_t size
	);
};

#ifdef RRR_NET_TRANSPORT_H_ENABLE_INTERNALS
void *rrr_net_transport_handle_collection_handle_get_private_ptr (
		struct rrr_net_transport_handle_collection *collection,
		int handle
);
int rrr_net_transport_handle_collection_handle_add (
		struct rrr_net_transport_handle_collection *collection,
		int handle,
		void *private_ptr
);
int rrr_net_transport_handle_collection_allocate_and_add_handle (
		int *final_handle,
		struct rrr_net_transport_handle_collection *collection,
		void *private_ptr
);
int rrr_net_transport_handle_collection_handle_remove (
		struct rrr_net_transport_handle_collection *collection,
		int handle,
		int (*destroy_func)(int handle, void *private_ptr, void *arg),
		void *destroy_func_arg
);
void rrr_net_transport_handle_collection_clear (
		struct rrr_net_transport_handle_collection *collection,
		int (*destroy_func)(int handle, void *private_ptr, void *arg),
		void *destroy_func_arg
);
#endif

int rrr_net_transport_new (struct rrr_net_transport **result, enum rrr_net_transport_type transport);
void rrr_net_transport_destroy (struct rrr_net_transport *transport);
int rrr_net_transport_close (
		struct rrr_net_transport *transport,
		int handle
);

static inline int rrr_net_transport_connect (
		int *handle,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {
	return transport->methods->connect(handle, transport, port, host);
}

static inline int rrr_net_transport_read_message (
		struct rrr_net_transport *transport,
		int transport_handle,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_net_transport_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_net_transport_read_session *read_session, void *arg),
		void *complete_callback_arg
) {
	return transport->methods->read_message (
			transport,
			transport_handle,
			read_step_initial,
			read_step_max_size,
			get_target_size,
			get_target_size_arg,
			complete_callback,
			complete_callback_arg
	);
}

static inline int rrr_net_transport_send (
	struct rrr_net_transport *transport,
	int transport_handle,
	void *data,
	ssize_t size
) {
	return transport->methods->send(transport, transport_handle, data, size);
}

#endif /* RRR_NET_TRANSPORT_H */
