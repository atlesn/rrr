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

#include "read.h"
#include "rrr_socket_read.h"
#include "read_constants.h"
#include "linked_list.h"

#define RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY (1<<0)

// Use same numbering system as socket subsystem, saves us from translating
// return values in many cases
#define RRR_NET_TRANSPORT_READ_OK				RRR_READ_OK
#define RRR_NET_TRANSPORT_READ_HARD_ERROR		RRR_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_READ_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_READ_INCOMPLETE		RRR_READ_INCOMPLETE
#define RRR_NET_TRANSPORT_READ_READ_EOF			RRR_READ_EOF

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH \
	RRR_READ_COMPLETE_METHOD_TARGET_LENGTH

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE \
	RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ

enum rrr_net_transport_type {
	RRR_NET_TRANSPORT_PLAIN,
	RRR_NET_TRANSPORT_TLS // TODO : Consider wrapping in RRR_WITH_OPENSSL
};

struct rrr_read_session;
struct rrr_net_transport;

struct rrr_net_transport_handle {
	RRR_LL_NODE(struct rrr_net_transport_handle);
	struct rrr_net_transport *transport;
	int handle;
	struct rrr_read_session_collection read_sessions;
	void *private_ptr;
};

struct rrr_net_transport_handle_collection {
	RRR_LL_HEAD(struct rrr_net_transport_handle);
	pthread_mutex_t lock;
};

#define RRR_NET_TRANSPORT_HEAD \
	const struct rrr_net_transport_methods *methods; 			\
	struct rrr_net_transport_handle_collection handles

struct rrr_net_transport {
	RRR_NET_TRANSPORT_HEAD;
};

#define RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD								\
	struct rrr_net_transport_handle *handle;									\
	int (*get_target_size)(struct rrr_read_session *read_session, void *arg);	\
	void *get_target_size_arg;													\
	int (*complete_callback)(struct rrr_read_session *read_session, void *arg);	\
	void *complete_callback_arg;												\


struct rrr_net_transport_read_callback_data {
	RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD;
};

struct rrr_net_transport_methods {
	void (*destroy)(
			struct rrr_net_transport *transport
	);
	int (*connect)(
			int *handle,
			struct rrr_net_transport *transport,
			unsigned int port,
			const char *host
	);
	int (*bind_and_listen)(
			int *listen_handle,
			struct rrr_net_transport *transport,
			unsigned int port
	);
	int (*accept)(
			int *handle,
			struct sockaddr *sockaddr,
			socklen_t *socklen,
			struct rrr_net_transport_handle *listen_handle
	);
	int (*close)(
			struct rrr_net_transport_handle *handle
	);
	int (*read_message)(
			struct rrr_net_transport_handle *handle,
			int read_attempts,
			ssize_t read_step_initial,
			ssize_t read_step_max_size,
			int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
			void *get_target_size_arg,
			int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
			void *complete_callback_arg
	);
	int (*send)(
			struct rrr_net_transport_handle *handle,
			void *data,
			ssize_t size
	);
};

#ifdef RRR_NET_TRANSPORT_H_ENABLE_INTERNALS
struct rrr_net_transport_handle *rrr_net_transport_handle_get (
		struct rrr_net_transport *transport,
		int handle
);
int rrr_net_transport_handle_add (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		int handle,
		void *private_ptr
);
int rrr_net_transport_handle_allocate_and_add (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		void *private_ptr
);
int rrr_net_transport_handle_remove (
		struct rrr_net_transport *transport,
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
);
#endif

int rrr_net_transport_new (
		struct rrr_net_transport **result,
		enum rrr_net_transport_type transport,
		int flags,
		const char *certificate_file,
		const char *private_key_file
);
void rrr_net_transport_destroy (struct rrr_net_transport *transport);
int rrr_net_transport_close (
		struct rrr_net_transport *transport,
		int handle
);
int rrr_net_transport_connect (
		int *handle,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
);
int rrr_net_transport_read_message (
		struct rrr_net_transport *transport,
		int transport_handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
);
int rrr_net_transport_send (
		struct rrr_net_transport *transport,
		int transport_handle,
		void *data,
		ssize_t size
);
int rrr_net_transport_bind_and_listen (
		int *new_handle,
		struct rrr_net_transport *transport,
		unsigned int port
);
int rrr_net_transport_accept (
		int *new_handle,
		struct sockaddr *sockaddr,
		socklen_t *socklen,
		struct rrr_net_transport *transport,
		int transport_handle
);

#endif /* RRR_NET_TRANSPORT_H */
