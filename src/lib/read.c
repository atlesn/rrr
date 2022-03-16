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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "read.h"
#include "read_constants.h"
#include "allocator.h"
#include "messages/msg_msg.h"
#include "messages/msg_addr.h"
#include "messages/msg_log.h"
#include "array.h"
#include "array_tree.h"
#include "util/posix.h"
#include "util/linked_list.h"
#include "util/rrr_time.h"

#define RRR_READ_COLLECTION_CLIENT_TIMEOUT_S 30

#define RRR_READ_BIGALLOC_TARGET_SIZE_THRESHOLD  2 * 1024 * 1024
#define RRR_READ_BIGALLOC_STEP                   1 * 1024 * 1024

struct rrr_read_session *rrr_read_session_new (
		struct sockaddr *src_addr,
		socklen_t src_addr_len
) {
	struct rrr_read_session *read_session = rrr_allocate(sizeof(*read_session));
	if (read_session == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_socket_read_session_new\n");
		return NULL;
	}
	memset(read_session, '\0', sizeof(*read_session));

	if (src_addr_len > sizeof(read_session->src_addr)) {
		RRR_BUG("BUG: Address too long (%u>%llu) in rrr_read_session_new\n",
			src_addr_len, (long long unsigned) sizeof(read_session->src_addr));
	}

	read_session->last_read_time = rrr_time_get_64();
	memcpy(&read_session->src_addr, src_addr, src_addr_len);
	read_session->src_addr_len = src_addr_len;

	return read_session;
}

int rrr_read_session_cleanup (
		struct rrr_read_session *read_session
) {
	RRR_ALLOCATOR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
	RRR_ALLOCATOR_FREE_IF_NOT_NULL(read_session->rx_overshoot);
	return 0;
}

int rrr_read_session_destroy (
		struct rrr_read_session *read_session
) {
	rrr_read_session_cleanup(read_session);
	rrr_free(read_session);
	return 0;
}

void rrr_read_session_collection_init (
		struct rrr_read_session_collection *collection
) {
	memset(collection, '\0', sizeof(*collection));
}

void rrr_read_session_collection_clear (
		struct rrr_read_session_collection *collection
) {
	RRR_LL_DESTROY(collection,struct rrr_read_session,rrr_read_session_destroy(node));
}

struct rrr_read_session *rrr_read_session_collection_get_session_with_overshoot (
		struct rrr_read_session_collection *collection
) {
	RRR_LL_ITERATE_BEGIN(collection,struct rrr_read_session);
		if (node->rx_overshoot != NULL) {
			return node;
		}
	RRR_LL_ITERATE_END();
	return NULL;
}

int rrr_read_session_collection_has_unprocessed_data (
		const struct rrr_read_session_collection *collection
) {
	RRR_LL_ITERATE_BEGIN(collection,struct rrr_read_session);
		if (node->rx_overshoot != NULL || (node->rx_buf_wpos > 0 && node->rx_buf_ptr != NULL)) {
			return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

struct rrr_read_session *rrr_read_session_collection_maintain_and_find_or_create (
		int *is_new,
		struct rrr_read_session_collection *collection,
		struct sockaddr *src_addr,
		socklen_t src_addr_len
) {
	struct rrr_read_session *res = NULL;

	*is_new = 0;

	uint64_t time_now = rrr_time_get_64();
	uint64_t time_limit = time_now - RRR_READ_COLLECTION_CLIENT_TIMEOUT_S * 1000 * 1000;

	RRR_LL_ITERATE_BEGIN(collection,struct rrr_read_session);
		if (node->last_read_time < time_limit) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
		else if (	node->src_addr_len == src_addr_len &&
				memcmp(src_addr, &node->src_addr, src_addr_len) == 0
		) {
			if (res != NULL) {
				RRR_BUG("Two equal src_addr in rrr_socket_read_session_collection_maintain_and_find\n");
			}
			res = node;
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(collection,rrr_read_session_destroy(node));

	if (res == NULL) {
		res = rrr_read_session_new(src_addr, src_addr_len);
		if (res == NULL) {
			RRR_MSG_0("Could not allocate memory for read session in rrr_socket_read_message\n");
			goto out;
		}

		RRR_LL_UNSHIFT(collection,res);

		*is_new = 1;
	}

	out:
	return res;
}

void rrr_read_session_collection_remove_session (
		struct rrr_read_session_collection *collection,
		struct rrr_read_session *read_session
) {
	RRR_LL_REMOVE_NODE_IF_EXISTS(
			collection,
			struct rrr_read_session,
			read_session,
			rrr_read_session_destroy(node)
	);
}

static int __rrr_read_message_using_callbacks (
		uint64_t *bytes_read,
		rrr_biglength read_step_initial,
		rrr_biglength read_step_max_size,
		rrr_biglength read_max_size,
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
) {
	int ret = RRR_READ_OK;
	int ret_from_read = RRR_READ_OK;

	rrr_biglength bytes = 0;
	char buf[read_step_max_size];
	struct rrr_read_session *read_session = NULL;

	if ((read_session = function_get_read_session_with_overshoot(functions_callback_arg)) == NULL) {
		if (function_read == NULL) {
			// Flush mode
			ret = RRR_READ_INCOMPLETE;
			goto out;
		}
	}
	else {
		goto process_overshoot;
	}

	*bytes_read = 0;

	/* Check ratelimit. It is not possible to distinguish different read sessions when ratelimiting e.g.
	 * when there are multiple read sessions for an UDP socket. */
	if (read_session_ratelimit != NULL) {
		if (ratelimit_max_bytes > 0) {
			const uint64_t time_now = rrr_time_get_64();
			if (time_now - read_session_ratelimit->ratelimit_time > ratelimit_interval_us) {
				read_session_ratelimit->ratelimit_time = time_now;
				read_session_ratelimit->ratelimit_bytes = 0;
			}
			else if (read_session_ratelimit->ratelimit_bytes > ratelimit_max_bytes) {
				RRR_DBG_7("Read ratelimited %llu > %llu within %" PRIu64 " us\n",
					(long long unsigned) read_session_ratelimit->ratelimit_bytes,
					(long long unsigned) ratelimit_max_bytes,
					ratelimit_interval_us
				);
				ret = RRR_READ_RATELIMIT;
				goto out;
			}
		}
		else {
			read_session_ratelimit->ratelimit_bytes = 0;
			read_session_ratelimit->ratelimit_time = 0;
		}
	}

	/* Read */
	ret_from_read = ret = function_read (buf, &bytes, read_step_max_size, functions_callback_arg);

	// We don't quit on soft error yet, downstream must be able to retrieve the correct read session to
	// handle errors, which might include to remove the read_session from the collection
	if (ret & (RRR_READ_HARD_ERROR)) {
		RRR_MSG_0("Hard error from read callback in rrr_read_message_using_callbacks\n");
		goto out;
	}
	if (ret & RRR_READ_INCOMPLETE) {
		RRR_BUG("BUG: READ_INCOMPLETE returned from read callback in rrr_read_message_using_callbacks, this is not allowed\n");
	}
	if ((ret & RRR_READ_EOF) && bytes != 0) {
		RRR_BUG("BUG: READ_EOF returned from read callback while bytes was non-zero in rrr_read_message_using_callbacks, this is not allowed\n");
	}

	/* Check for new read session, this must be done after read */
	if ((read_session = function_get_read_session(functions_callback_arg)) == NULL) {
		ret = RRR_READ_HARD_ERROR;
		goto out;
	}

	/* Check for socket_options */
	if (function_get_socket_options != NULL && read_session->socket_options == 0) {
		if ((ret = function_get_socket_options(read_session, functions_callback_arg)) != 0) {
			RRR_MSG_0("Error while getting socket options in rrr_read_message_using_callbacks\n");
			goto out;
		}
	}

	/* Check for EOF / connection close */
	if (bytes == 0 || ret_from_read != 0) {
		// In situations where zero bytes are read, the downstream framework should
		// return something else than OK. If not, we will always exit here.
		if (read_session->read_complete_method == RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ) {
			if (read_session->target_size > 0) {
				RRR_BUG("Target size was set in rrr_read_message while complete method was connection closed\n");
			}
			RRR_DBG_7("Read returned 0, set target size to bytes read as instructed.\n");
			read_session->target_size = read_session->rx_buf_wpos;
			ret = RRR_READ_OK;
			// Don't goto out, call complete handler after storing buffer
		}
		else if (ret_from_read & RRR_READ_EOF) {
			if (read_session->eof_ok_now && read_session->rx_buf_ptr == NULL && read_session->rx_overshoot == NULL) {
				// Complete callback says that EOF is OK now
				RRR_DBG_7("Read returned 0, possible close of connection or EOF. EOF was expected.\n");
				ret = RRR_READ_EOF;
			}
			else {
				// Unexpected EOF
				RRR_DBG_7("Read returned 0, possible close of connection or EOF. EOF was NOT expected.\n");
				ret = RRR_READ_SOFT_ERROR;
			}
			goto out;
		}
		else if (ret_from_read != 0) {
			ret = ret_from_read;
			goto out;
		}
		else {
			ret = RRR_READ_INCOMPLETE;
			goto out;
		}
	}

	read_session->ratelimit_bytes += bytes;
	read_session->eof_ok_now = 0;

	process_overshoot:

	if (read_session->rx_buf_ptr == NULL) {
		if (read_session->rx_overshoot != NULL) {
			read_session->rx_buf_ptr = read_session->rx_overshoot;
			read_session->rx_buf_size = read_session->rx_overshoot_size;
			read_session->rx_buf_wpos = read_session->rx_overshoot_size;

			read_session->rx_overshoot = NULL;
			read_session->rx_overshoot_size = 0;
		}
		else {
			RRR_SIZE_CHECK(bytes,"Read buffer too big A",ret = RRR_READ_SOFT_ERROR; goto out);
			read_session->rx_buf_ptr = rrr_allocate_group((size_t) (bytes > read_step_max_size ? bytes : read_step_max_size), RRR_ALLOCATOR_GROUP_MSG);
			if (read_session->rx_buf_ptr == NULL) {
				RRR_MSG_0("Could not allocate memory in rrr_socket_read_message\n");
				ret = RRR_READ_HARD_ERROR;
				goto out;
			}
			read_session->rx_buf_size = read_step_max_size;
			read_session->rx_buf_wpos = 0;
		}

		read_session->target_size = 0;
	}

	if (read_session->read_complete != 0) {
		RRR_BUG("Read complete was non-zero in rrr_read_message_using_callbacks, read session must be cleared prior to reading more data\n");
	}

	/* Check for expansion of buffer */
	if (bytes > 0) {
		*bytes_read = (uint64_t) bytes;
		if (bytes + read_session->rx_buf_wpos > read_session->rx_buf_size) {
			rrr_biglength expansion_max = read_session->target_size > RRR_READ_BIGALLOC_TARGET_SIZE_THRESHOLD && read_step_max_size < RRR_READ_BIGALLOC_STEP
				? RRR_READ_BIGALLOC_STEP
				: read_step_max_size;

			if (read_session->rx_buf_size + expansion_max > read_session->target_size) {
				expansion_max = 0;
			}

			rrr_biglength new_size = read_session->rx_buf_size + (bytes > expansion_max ? bytes : expansion_max);

			RRR_SIZE_CHECK(new_size,"Read buffer too big B",ret = RRR_READ_SOFT_ERROR; goto out);
			char *new_buf = rrr_reallocate_group(read_session->rx_buf_ptr, (size_t) read_session->rx_buf_size, (size_t) new_size, RRR_ALLOCATOR_GROUP_MSG);

			if (new_buf == NULL) {
				RRR_MSG_0("Could not re-allocate memory (%llu->%llu) in rrr_read_message_using_callbacks\n",
					(long long unsigned) read_session->rx_buf_size,
					(long long unsigned) new_size
				);
				ret = RRR_READ_HARD_ERROR;
				goto out;
			}
			read_session->rx_buf_ptr = new_buf;
			read_session->rx_buf_size = new_size;
		}

		rrr_memcpy (read_session->rx_buf_ptr + read_session->rx_buf_wpos, buf, bytes);
		read_session->rx_buf_wpos += bytes;
		read_session->last_read_time = rrr_time_get_64();
	}

	/* Check for max bytes read */
	if (read_max_size > 0 && read_session->rx_buf_wpos > read_max_size) {
		RRR_MSG_0("Too many bytes read in rrr_read_message_using_callbacks (%" PRIrrrbl ">%" PRIrrrbl ")\n",
				read_session->rx_buf_wpos, read_max_size);
		ret = RRR_READ_SOFT_ERROR;
		goto out;
	}

	if (function_get_target_size == NULL) {
		read_session->target_size = read_step_initial;
	}
	else if (read_session->target_size == 0 &&
			read_session->read_complete_method == RRR_READ_COMPLETE_METHOD_TARGET_LENGTH
	) {
		read_session->rx_buf_skip = 0;

		// In the first read, we take a sneak peak at the first bytes to find a length field
		// if it is present. If there is not target size function, the target size becomes
		// the initial bytes parameter (set at the top of the function). The target size function
		// may change the read complete method. This function may called multiple times if it does
		// not return OK the first time. In that case, we will read more data repeatedly time until
		// OK is returned.
		ret = function_get_target_size(read_session, functions_callback_arg);
		if (ret != RRR_READ_OK && ret != RRR_READ_INCOMPLETE) {
			if (function_get_target_size_error_callback != NULL) {
				function_get_target_size_error_callback(read_session, ret == RRR_READ_HARD_ERROR, functions_callback_arg);
			}
			goto out;
		}

		// The function may choose to skip bytes in the buffer. If it does, we must align the data here (costly).
		if (read_session->rx_buf_skip != 0) {
			RRR_DBG_7("Aligning buffer, skipping %" PRIrrrbl " bytes while reading from socket\n",
				read_session->rx_buf_skip);

			RRR_SIZE_CHECK(read_session->rx_buf_size,"Read buffer too big C",ret = RRR_READ_SOFT_ERROR; goto out);
			char *new_buf = rrr_allocate_group(read_session->rx_buf_size, RRR_ALLOCATOR_GROUP_MSG);
			if (new_buf == NULL) {
				RRR_MSG_0("Could not allocate memory while aligning buffer in rrr_read_message_using_callbacks\n");
				ret = RRR_READ_HARD_ERROR;
				goto out;
			}
			rrr_memcpy(new_buf, read_session->rx_buf_ptr + read_session->rx_buf_skip, read_session->rx_buf_wpos - read_session->rx_buf_skip);

			// Put new buffer into overshoot so that it is picked up again
			// in the next read loop
			read_session->rx_overshoot = new_buf;
			read_session->rx_overshoot_size = read_session->rx_buf_wpos - read_session->rx_buf_skip;

			rrr_free(read_session->rx_buf_ptr);
			read_session->rx_buf_ptr = NULL;
			read_session->rx_buf_skip = 0;

			ret = RRR_READ_INCOMPLETE;
		}

		if (ret != RRR_READ_OK) {
			goto out;
		}

		if (read_session->target_size == 0 &&
				read_session->read_complete_method == RRR_READ_COMPLETE_METHOD_TARGET_LENGTH
		) {
			RRR_BUG("target_size was still zero after get_target_size in rrr_read_message_using_callbacks\n");
		}
	}

	if (read_session->rx_buf_wpos > read_session->target_size &&
			read_session->read_complete_method != RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ
	) {
		if (read_session->rx_overshoot != NULL) {
			RRR_BUG("overshoot was not NULL in rrr_socket_read_message\n");
		}

		read_session->rx_overshoot_size = read_session->rx_buf_wpos - read_session->target_size;
		read_session->rx_buf_wpos -= read_session->rx_overshoot_size;

		RRR_SIZE_CHECK(read_session->rx_overshoot_size,"Read buffer too big D",ret = RRR_READ_SOFT_ERROR; goto out);
		read_session->rx_overshoot = rrr_allocate_group(read_session->rx_overshoot_size, RRR_ALLOCATOR_GROUP_MSG);
		if (read_session->rx_overshoot == NULL) {
			RRR_MSG_0("Could not allocate memory for overshoot in rrr_read_message_using_callbacks\n");
			ret = RRR_READ_HARD_ERROR;
			goto out;
		}

		rrr_memcpy(read_session->rx_overshoot, read_session->rx_buf_ptr + read_session->rx_buf_wpos, read_session->rx_overshoot_size);
	}

	if (read_session->rx_buf_wpos == read_session->target_size && read_session->target_size > 0) {
		read_session->read_complete = 1;
		if (function_complete_callback != NULL) {
			ret = function_complete_callback (read_session, functions_callback_arg);
			if (ret != 0) {
				RRR_DBG_3("Note: Return %i from complete callback in rrr_read_message_using_callbacks\n", ret);
				goto out;
			}

			RRR_ALLOCATOR_FREE_IF_NOT_NULL(read_session->rx_buf_ptr);
			read_session->read_complete = 0;
			read_session->target_size = 0;
			read_session->read_complete_method = 0;
		}
	}
	else if (read_session->read_complete_method == RRR_READ_COMPLETE_METHOD_ZERO_BYTES_READ ||
			read_session->read_complete_method == RRR_READ_COMPLETE_METHOD_TARGET_LENGTH
	) {
		ret = RRR_READ_INCOMPLETE;
		goto out;
	}
	else {
		RRR_BUG("Some sort of invalid read complete method state at end of rrr_socket_read_message_using_callbacks");
	}

	out:
	if (ret != RRR_READ_OK && ret != RRR_READ_INCOMPLETE && read_session != NULL) {
		function_read_session_remove(read_session, functions_callback_arg);
	}
	return ret;
}

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
) {
	int ret = 0;

	int read_count = 0;

	if ((ret = __rrr_read_message_using_callbacks (
			bytes_read,
			read_step_initial,
			read_step_max_size,
			read_max_size,
			read_session_ratelimit,
			ratelimit_interval_us,
			ratelimit_max_bytes,
			function_get_target_size,
			function_get_target_size_error_callback,
			function_complete_callback,
			function_read,
			function_get_read_session_with_overshoot,
			function_get_read_session,
			function_read_session_remove,
			function_get_socket_options,
			functions_callback_arg
	)) == 0) {
		read_count++;
	}
	else {
		goto out;
	}

	if (flags & RRR_READ_MESSAGE_FLUSH_OVERSHOOT) {
		again:
		if ((ret = rrr_read_message_using_callbacks_flush (
				read_step_initial,
				read_step_max_size,
				read_max_size,
				function_get_target_size,
				function_get_target_size_error_callback,
				function_complete_callback,
				function_get_read_session_with_overshoot,
				function_read_session_remove,
				functions_callback_arg
		)) == 0) {
			read_count++;
			goto again;
		}
	}

	RRR_DBG_7("%i messages read in read framework\n", read_count);

	ret &= ~(RRR_READ_INCOMPLETE);

	out:
	return ret;
}

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
) {
	return __rrr_read_message_using_callbacks (
			NULL,
			read_step_initial,
			read_step_max_size,
			read_max_size,
			NULL,
			0,
			0,
			function_get_target_size,
			function_get_target_size_error_callback,
			function_complete_callback,
			NULL,
			function_get_read_session_with_overshoot,
			NULL,
			function_read_session_remove,
			NULL,
			functions_callback_arg
	);
}

int rrr_read_common_get_session_target_length_from_message_and_checksum_raw (
		rrr_biglength *result,
		void *data,
		rrr_biglength data_size,
		void *arg
) {
	if (arg != NULL) {
		RRR_BUG("arg was not NULL in rrr_socket_common_get_session_target_length_from_message_and_checksum_raw\n");
	}

	*result = 0;

	if (data_size > RRR_LENGTH_MAX) {
		RRR_MSG_0("Message target length too long in rrr_read_common_get_session_target_length_from_message_and_checksum_raw (%llu>%llu)\n",
			(unsigned long long) data_size,
			(unsigned long long) RRR_LENGTH_MAX
		);
	}

	rrr_length target_size = 0;
	int ret = rrr_msg_get_target_size_and_check_checksum(
			&target_size,
			(struct rrr_msg *) data,
			(rrr_length) data_size
	);

	if (ret != 0) {
		if (ret != RRR_READ_INCOMPLETE) {
			RRR_MSG_0("Warning: Header checksum of message failed in rrr_socket_common_get_session_target_length_from_message_and_checksum_raw\n");
		}
		goto out;
	}

	*result = target_size;

	out:
	return ret;
}

int rrr_read_common_get_session_target_length_from_message_and_checksum (
		struct rrr_read_session *read_session,
		void *arg
) {
	int ret = rrr_read_common_get_session_target_length_from_message_and_checksum_raw (
			&read_session->target_size,
			read_session->rx_buf_ptr,
			read_session->rx_buf_wpos,
			arg
	);

	if (ret != 0) {
		if (ret != RRR_READ_INCOMPLETE) {
			RRR_MSG_0("Warning: Header checksum of message failed in rrr_socket_common_get_session_target_length_from_message_and_checksum\n");
		}
		goto out;
	}

	out:
	return ret;
}

static int __rrr_read_common_get_session_target_length_from_array_tree_callback (
		struct rrr_array *array, void *arg
) {
	struct rrr_read_common_get_session_target_length_from_array_tree_data *data = arg;

	rrr_array_clear(data->array_final);
	RRR_LL_MERGE_AND_CLEAR_SOURCE_HEAD(data->array_final, array);

	return 0;
}

int rrr_read_common_get_session_target_length_from_array_tree (
		struct rrr_read_session *read_session,
		void *arg
) {
	struct rrr_read_common_get_session_target_length_from_array_tree_data *data = arg;

	const char *pos_max = (data->message_max_size != 0 ? read_session->rx_buf_ptr + data->message_max_size : NULL);
	char *pos = read_session->rx_buf_ptr;

	if (read_session->rx_buf_wpos > RRR_LENGTH_MAX) {
		RRR_MSG_0("Array data too long in rrr_read_common_get_session_target_length_from_array_tree (%llu>%llu)\n",
			(unsigned long long) read_session->rx_buf_wpos,
			(unsigned long long) RRR_LENGTH_MAX
		);
	}

	const rrr_length wpos = (rrr_length) read_session->rx_buf_wpos;
	rrr_length import_length = 0;

	while (wpos > 0) {
		if (pos_max != NULL && pos > pos_max) {
			RRR_DBG_1("Received array data exceeds maximum size, is a delimeter missing? (%" PRIrrrl ">%u)\n",
					wpos, data->message_max_size);
			return RRR_READ_SOFT_ERROR;
		}

		int ret = rrr_array_tree_import_from_buffer (
				&import_length,
				pos,
				wpos,
				data->tree,
				__rrr_read_common_get_session_target_length_from_array_tree_callback,
				data
		);

		if (ret == 0) {
			if (import_length == 0) {
				RRR_MSG_0("Warning: Array definition produced a length of zero, possible configuration error. Check REWIND usage.\n");
				return RRR_READ_SOFT_ERROR;
			}
			break;
		}
		else {
			if (ret == RRR_TYPE_PARSE_SOFT_ERR && data->do_byte_by_byte_sync != 0) {
				read_session->rx_buf_skip += 1;
				return RRR_READ_INCOMPLETE;
			}
			return ret;
		}
	}

	if (wpos <= 0) {
		return RRR_READ_SOFT_ERROR;
	}

	// Raw size to read for socket framework
	read_session->target_size = import_length;

	if (read_session->target_size == read_session->rx_buf_wpos) {
		read_session->eof_ok_now = 1;
	}

	return RRR_READ_OK;
}
