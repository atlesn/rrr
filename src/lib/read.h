/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_READ_SESSION_H
#define RRR_READ_SESSION_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "util/linked_list.h"
#include "rrr_types.h"

//struct rrr_socket_client;

#define RRR_READ_COMMON_GET_TARGET_LENGTH_FROM_MSG_RAW_ARGS    \
        rrr_biglength *result,                                        \
        void *data,                                            \
        rrr_biglength data_size,                                      \
        void *arg

struct rrr_read_session_collection {
	RRR_LL_HEAD(struct rrr_read_session);
};

struct rrr_read_session {
	/* A packet read action might be temporarily paused if the payload
	 * is large (exceeds step_size_limit is < 0). It will resume in the next process tick.
	 *
	 * When rx_buf_wpos reaches target_size, the retrieval is complete and the processing
	 * of the packet may begin. */

	RRR_LL_NODE(struct rrr_read_session);

	// These are set on every read before calling complete callback. client will be NULL
	// if client collection is not being used.
	int fd;
//	struct rrr_socket_client *client;
	uint64_t last_read_time;

	// Ratelimit working values. If more than bytes_max has been read within the interval,
	// no reading is performed. When interval has passed, the byte counter and time is reset.
	uint64_t ratelimit_time;
	rrr_biglength ratelimit_bytes;

	// This is set if get socket options callback is used
	int socket_options;

	// Used to distinguish clients from each other
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len;

	/* Read untill target size is reached (default) or set to read until
	 * connection is closed. */
	int read_complete_method;
	rrr_biglength target_size;

	// Populated by socket read function (contain all read data)
	char *rx_buf_ptr;
	rrr_biglength rx_buf_size;
	rrr_biglength rx_buf_wpos;

	// Populated by get target length-function if bytes are to be skipped at beginning of buffer
	rrr_biglength rx_buf_skip;

	// May be used by freely by application layer to keep track of any parsing
	rrr_biglength parse_pos;

	// Complete callback may set this to indicate that parsing of a block has completed successfully
	// and that if an EOF or connection close occurs in the next read, this should not produce a soft error.
	// If EOF does not occur during the next read, the flag is reset to zero.
	int eof_ok_now;

	// Remaining buffer contents are moved to overshoot if bytes read exceed target size.
	// At the next iteration, no read will be performed and the overshoot is moved to
	// rx_buf_ptr before get target size is called.
	char *rx_overshoot;
	rrr_biglength rx_overshoot_size;

	// Set to 1 before read complete callback and 0 after the callback unless it fails. If the
	// final callback fails, the read session must be clear or a bugtrap will be triggered the
	// next read.
	int read_complete;
};

void rrr_read_session_collection_init (
		struct rrr_read_session_collection *collection
);
void rrr_read_session_collection_clear (
		struct rrr_read_session_collection *collection
);
struct rrr_read_session *rrr_read_session_collection_maintain_and_find_or_create (
		int *is_new,
		struct rrr_read_session_collection *collection,
		struct sockaddr *src_addr,
		socklen_t src_addr_len
);
struct rrr_read_session *rrr_read_session_collection_get_session_with_overshoot (
		struct rrr_read_session_collection *collection
);
int rrr_read_session_collection_has_unprocessed_data (
		const struct rrr_read_session_collection *collection
);
void rrr_read_session_collection_remove_session (
		struct rrr_read_session_collection *collection,
		struct rrr_read_session *read_session
);
int rrr_read_session_cleanup (
		struct rrr_read_session *read_session
);
int rrr_read_session_destroy (
		struct rrr_read_session *read_session
);
int rrr_read_message_using_callbacks (
		uint64_t *bytes_read,
		rrr_biglength read_step_initial,
		rrr_biglength read_step_max_size,
		rrr_biglength read_max_size,
		int flags,
		struct rrr_read_session *read_session_ratelimit,
		uint64_t ratelimit_interval_us,
		rrr_biglength ratelimit_max_bytes,
		int (*function_get_target_size) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		void (*function_get_target_size_error_callback) (
				struct rrr_read_session *read_session,
				int is_hard_error,
				void *private_arg
		),
		int (*function_complete_callback) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		int (*function_read) (
				char *buf,
				rrr_biglength *read_bytes,
				rrr_biglength read_step_max_size,
				void *private_arg
		),
		struct rrr_read_session*(*function_get_read_session_with_overshoot) (
				void *private_arg
		),
		struct rrr_read_session*(*function_get_read_session) (
				void *private_arg
		),
		void (*function_read_session_remove) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		int (*function_get_socket_options) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		void *functions_callback_arg
);
int rrr_read_message_using_callbacks_flush (
		rrr_biglength read_step_initial,
		rrr_biglength read_step_max_size,
		rrr_biglength read_max_size,
		int (*function_get_target_size) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		void (*function_get_target_size_error_callback) (
				struct rrr_read_session *read_session,
				int is_hard_error,
				void *private_arg
		),
		int (*function_complete_callback) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		struct rrr_read_session*(*function_get_read_session_with_overshoot) (
				void *private_arg
		),
		void (*function_read_session_remove) (
				struct rrr_read_session *read_session,
				void *private_arg
		),
		void *functions_callback_arg
);

struct rrr_array;
struct rrr_array_tree;

int rrr_read_common_get_session_target_length_from_message_and_checksum_raw (
		RRR_READ_COMMON_GET_TARGET_LENGTH_FROM_MSG_RAW_ARGS
);
int rrr_read_common_get_session_target_length_from_message_and_checksum (
		struct rrr_read_session *read_session,
		void *arg
);
struct rrr_read_common_get_session_target_length_from_array_tree_data {
	const struct rrr_array_tree *tree;
	struct rrr_array *array_final;
	int do_byte_by_byte_sync;
	rrr_length message_max_size;
};
int rrr_read_common_get_session_target_length_from_array_tree (
		struct rrr_read_session *read_session,
		void *arg
);

#endif /* RRR_READ_SESSION_H */
