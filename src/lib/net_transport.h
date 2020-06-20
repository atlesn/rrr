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

#define RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY	(1<<0)
#define RRR_NET_TRANSPORT_F_MIN_VERSION_TLS_1_1	(1<<1)

// Use same numbering system as socket subsystem, saves us from translating
// return values in many cases
#define RRR_NET_TRANSPORT_READ_OK				RRR_READ_OK
#define RRR_NET_TRANSPORT_READ_HARD_ERROR		RRR_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_READ_SOFT_ERROR		RRR_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_READ_INCOMPLETE		RRR_READ_INCOMPLETE
#define RRR_NET_TRANSPORT_READ_READ_EOF			RRR_READ_EOF

#define RRR_NET_TRANSPORT_SEND_OK				RRR_NET_TRANSPORT_READ_OK
#define RRR_NET_TRANSPORT_SEND_HARD_ERROR		RRR_NET_TRANSPORT_READ_HARD_ERROR
#define RRR_NET_TRANSPORT_SEND_SOFT_ERROR		RRR_NET_TRANSPORT_READ_SOFT_ERROR
#define RRR_NET_TRANSPORT_SEND_INCOMPLETE		RRR_NET_TRANSPORT_READ_INCOMPLETE


#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_TARGET_LENGTH \
	RRR_READ_COMPLETE_METHOD_TARGET_LENGTH

#define RRR_NET_TRANSPORT_READ_COMPLETE_METHOD_CONN_CLOSE \
	RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ

enum rrr_net_transport_type {
	RRR_NET_TRANSPORT_PLAIN,
	RRR_NET_TRANSPORT_TLS // TODO : Consider wrapping in RRR_WITH_OPENSSL
};

enum rrr_net_transport_socket_mode {
	RRR_NET_TRANSPORT_SOCKET_MODE_ANY,
	RRR_NET_TRANSPORT_SOCKET_MODE_LISTEN,
	RRR_NET_TRANSPORT_SOCKET_MODE_CONNECTION
};

struct rrr_read_session;
struct rrr_net_transport;

struct rrr_net_transport_handle {
	RRR_LL_NODE(struct rrr_net_transport_handle);
	pthread_mutex_t lock;
	struct rrr_net_transport *transport;
	int handle;
	enum rrr_net_transport_socket_mode mode;
	struct rrr_read_session_collection read_sessions;

	// Like SSL data or plain FD
	void *submodule_private_ptr;
	int submodule_private_fd;

	// Like HTTP session
	void *application_private_ptr;
	void (*application_ptr_destroy)(void *ptr);

	// Called first when we try to destroy. When it returns 0,
	// we go ahead with destruction and call ptr_destroy. Only
	// used from within the iterator function.
	int (*application_ptr_iterator_pre_destroy)(struct rrr_net_transport_handle *handle, void *ptr);
};

struct rrr_net_transport_handle_collection {
	RRR_LL_HEAD(struct rrr_net_transport_handle);
	int next_handle_position;
	pthread_mutex_t lock;
};

#define RRR_NET_TRANSPORT_HEAD(type)							\
	RRR_LL_NODE(type);											\
	const struct rrr_net_transport_methods *methods; 			\
	struct rrr_net_transport_handle_collection handles

struct rrr_net_transport {
	RRR_NET_TRANSPORT_HEAD(struct rrr_net_transport);
};

struct rrr_net_transport_collection {
	RRR_LL_HEAD(struct rrr_net_transport);
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
			struct rrr_net_transport_handle **handle,
			struct sockaddr *addr,
			socklen_t *socklen,
			struct rrr_net_transport *transport,
			unsigned int port,
			const char *host
	);
	int (*bind_and_listen)(
			struct rrr_net_transport *transport,
			unsigned int port,
			void (*callback)(struct rrr_net_transport_handle *handle, void *arg),
			void *callback_arg
	);
	int (*accept)(
			struct rrr_net_transport_handle *listen_handle,
			void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
			void *callback_arg
	);
	// Only call close() from parent mode destroy function
	int (*close)(
			struct rrr_net_transport_handle *handle
	);
	int (*read_message)(
			struct rrr_net_transport_handle *handle,
			int read_attempts,
			ssize_t read_step_initial,
			ssize_t read_step_max_size,
			int read_flags,
			int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
			void *get_target_size_arg,
			int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
			void *complete_callback_arg
	);
	int (*send)(
			ssize_t *sent_bytes,
			struct rrr_net_transport_handle *handle,
			const void *data,
			ssize_t size
	);
};

#ifdef RRR_NET_TRANSPORT_H_ENABLE_INTERNALS
int rrr_net_transport_handle_allocate_and_add_return_locked (
		struct rrr_net_transport_handle **handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		void *submodule_private_ptr,
		int submodule_private_fd
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
		const char *private_key_file,
		const char *ca_path
);
void rrr_net_transport_destroy (struct rrr_net_transport *transport);
void rrr_net_transport_collection_destroy (struct rrr_net_transport_collection *collection);
void rrr_net_transport_ctx_handle_close (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_handle_close (
		struct rrr_net_transport *transport,
		int transport_handle
);
int rrr_net_transport_connect_and_close_after_callback (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);
int rrr_net_transport_connect (
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);
int rrr_net_transport_ctx_read_message (
		struct rrr_net_transport_handle *handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		int read_flags,
		int (*get_target_size)(struct rrr_read_session *read_session, void *arg),
		void *get_target_size_arg,
		int (*complete_callback)(struct rrr_read_session *read_session, void *arg),
		void *complete_callback_arg
);
int rrr_net_transport_ctx_send_nonblock (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
);
int rrr_net_transport_ctx_send_blocking (
		struct rrr_net_transport_handle *handle,
		const void *data,
		ssize_t size
);
void rrr_net_transport_ctx_handle_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
);
int rrr_net_transport_handle_with_transport_ctx_do (
		struct rrr_net_transport *transport,
		int transport_handle,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_iterate_with_callback (
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_send_blocking (
		struct rrr_net_transport *transport,
		int transport_handle,
		const void *data,
		ssize_t size
);
int rrr_net_transport_bind_and_listen (
		struct rrr_net_transport *transport,
		unsigned int port,
		void (*callback)(struct rrr_net_transport_handle *handle, void *arg),
		void *arg
);
int rrr_net_transport_accept (
		struct rrr_net_transport *transport,
		int transport_handle,
		void (*callback)(struct rrr_net_transport_handle *handle, const struct sockaddr *sockaddr, socklen_t socklen, void *arg),
		void *callback_arg
);

#endif /* RRR_NET_TRANSPORT_H */
