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

#include "net_transport_defines.h"

#include "../read.h"
#include "../read_constants.h"
#include "../util/linked_list.h"

struct rrr_read_session;
struct rrr_net_transport;
struct rrr_net_transport_config;

struct rrr_net_transport_handle {
	RRR_LL_NODE(struct rrr_net_transport_handle);
	pthread_mutex_t lock_;
	int lock_count;
	struct rrr_net_transport *transport;
	int handle;
	enum rrr_net_transport_socket_mode mode;
	struct rrr_read_session_collection read_sessions;

	uint64_t bytes_read_total;
	uint64_t bytes_written_total;

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

struct rrr_net_transport_handle_close_tag_node {
	RRR_LL_NODE(struct rrr_net_transport_handle_close_tag_node);
	int transport_handle;
};

struct rrr_net_transport_handle_close_tag_list {
	RRR_LL_HEAD(struct rrr_net_transport_handle_close_tag_node);
};

struct rrr_net_transport_handle_collection {
	RRR_LL_HEAD(struct rrr_net_transport_handle);
	int next_handle_position;
	pthread_mutex_t lock;
	pthread_t owner;
	struct rrr_net_transport_handle_close_tag_list close_tags;
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

#define RRR_NET_TRANSPORT_CONNECT_ARGS											\
	int *handle,																\
	struct sockaddr *addr,														\
	socklen_t *socklen,															\
	struct rrr_net_transport *transport,										\
	unsigned int port,															\
	const char *host

#define RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD								\
	struct rrr_net_transport_handle *handle;									\
	int (*get_target_size)(struct rrr_read_session *read_session, void *arg);	\
	void *get_target_size_arg;													\
	int (*complete_callback)(struct rrr_read_session *read_session, void *arg);	\
	void *complete_callback_arg;												\

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS					\
	struct rrr_net_transport_handle *handle,									\
	void *arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS					\
	struct rrr_net_transport *transport,												\
	int transport_handle,																\
	void (*final_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),		\
	void *final_callback_arg,															\
	void *arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS											\
	struct rrr_net_transport *transport,												\
	unsigned int port,																	\
	int (*callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_INTERMEDIATE_ARGS),		\
	void *callback_arg,																	\
	void (*callback_final)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_FINAL_ARGS),		\
	void *callback_final_arg

#define RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS							\
	void **submodule_private_ptr, int *submodule_private_fd, void *arg

#define RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS							\
	struct rrr_net_transport_handle *handle,									\
	const struct sockaddr *sockaddr,											\
	socklen_t socklen,															\
	void *arg

#define RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS						\
	struct rrr_net_transport *transport,										\
	int transport_handle, 														\
	const struct sockaddr *sockaddr,											\
	socklen_t socklen,															\
	void (*final_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),		\
	void *final_callback_arg,													\
	void *arg

#define RRR_NET_TRANSPORT_ACCEPT_ARGS											\
	struct rrr_net_transport_handle *listen_handle,								\
	int (*callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_INTERMEDIATE_ARGS),		\
	void *callback_arg,															\
	void (*final_callback)(RRR_NET_TRANSPORT_ACCEPT_CALLBACK_FINAL_ARGS),		\
	void *final_callback_arg

#define RRR_NET_TRANSPORT_READ_ARGS												\
	uint64_t *bytes_read,														\
	struct rrr_net_transport_handle *handle,									\
	int read_attempts,															\
	ssize_t read_step_initial,													\
	ssize_t read_step_max_size,													\
	ssize_t read_max_size,														\
	int (*get_target_size)(struct rrr_read_session *read_session, void *arg),	\
	void *get_target_size_arg,													\
	int (*complete_callback)(struct rrr_read_session *read_session, void *arg),	\
	void *complete_callback_arg

struct rrr_net_transport_read_callback_data {
	RRR_NET_TRANSPORT_READ_CALLBACK_DATA_HEAD;
};

struct rrr_net_transport_methods {
	void (*destroy)(
			struct rrr_net_transport *transport
	);
	int (*connect)(RRR_NET_TRANSPORT_CONNECT_ARGS);
	int (*bind_and_listen)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_ARGS);
	int (*accept)(RRR_NET_TRANSPORT_ACCEPT_ARGS);
	// Only call close() from parent mode destroy function
	int (*close)(
			struct rrr_net_transport_handle *handle
	);
	int (*read_message)(RRR_NET_TRANSPORT_READ_ARGS);
	int (*send)(
			uint64_t *bytes_written,
			struct rrr_net_transport_handle *handle,
			const void *data,
			ssize_t size
	);
	int (*poll)(
			struct rrr_net_transport_handle *handle
	);
};

#ifdef RRR_NET_TRANSPORT_H_ENABLE_INTERNALS
int rrr_net_transport_handle_allocate_and_add (
		int *handle_final,
		struct rrr_net_transport *transport,
		enum rrr_net_transport_socket_mode mode,
		int (*submodule_callback)(RRR_NET_TRANSPORT_BIND_AND_LISTEN_CALLBACK_ARGS),
		void *submodule_callback_arg
);
#endif

void rrr_net_transport_common_cleanup (
		struct rrr_net_transport *transport
);
int rrr_net_transport_handle_close_tag_list_push (
		struct rrr_net_transport *transport,
		int handle
);
int rrr_net_transport_new (
		struct rrr_net_transport **result,
		const struct rrr_net_transport_config *config,
		int flags
);
void rrr_net_transport_destroy (struct rrr_net_transport *transport);
void rrr_net_transport_destroy_void (void *arg);
void rrr_net_transport_collection_destroy (struct rrr_net_transport_collection *collection);
void rrr_net_transport_collection_cleanup (struct rrr_net_transport_collection *collection);
void rrr_net_transport_ctx_handle_close_while_locked (
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
int rrr_net_transport_ctx_check_alive (
		struct rrr_net_transport_handle *handle
);
int rrr_net_transport_ctx_read_message (
		struct rrr_net_transport_handle *handle,
		int read_attempts,
		ssize_t read_step_initial,
		ssize_t read_step_max_size,
		ssize_t read_max_size,
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
int rrr_net_transport_ctx_handle_has_application_data (
		struct rrr_net_transport_handle *handle
);
void rrr_net_transport_ctx_handle_application_data_bind (
		struct rrr_net_transport_handle *handle,
		void *application_data,
		void (*application_data_destroy)(void *ptr)
);
void rrr_net_transport_ctx_get_socket_stats (
		uint64_t *bytes_read_total,
		uint64_t *bytes_written_total,
		uint64_t *bytes_total,
		struct rrr_net_transport_handle *handle
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
