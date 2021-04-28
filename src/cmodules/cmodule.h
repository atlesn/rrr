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

#ifndef RRR_CMODULE_H
#define RRR_CMODULE_H

#ifndef RRR_CMODULE_NATIVE_CTX
#	include <stdlib.h>
#	include "log.h"
#	include "allocator.h"
#	include "array.h"
#	include "type.h"
#	include "messages/msg_msg.h"
#	include "messages/msg_addr.h"
#	include "instance_config.h"
#	include "cmodule/cmodule_ext.h"
#endif

#define RRR_CONFIG_ARGS \
	struct rrr_cmodule_ctx *ctx, struct rrr_instance_config_data *config
#define RRR_SOURCE_ARGS \
	struct rrr_cmodule_ctx *ctx, struct rrr_msg_msg *message, const struct rrr_msg_addr *message_addr
#define RRR_PROCESS_ARGS \
	RRR_SOURCE_ARGS
#define RRR_CLEANUP_ARGS \
	struct rrr_cmodule_ctx *ctx

struct rrr_cmodule_worker;

struct rrr_cmodule_ctx {
	struct rrr_cmodule_worker *worker;

	// Used by cmodule only
	void *application_ptr;
};

#ifndef RRR_CMODULE_NATIVE_CTX

static inline int rrr_send_and_free (
		struct rrr_cmodule_ctx *ctx,
		struct rrr_msg_msg *message,
		const struct rrr_msg_addr *message_addr
) {
	int ret = rrr_cmodule_ext_send_message_to_parent (
			ctx->worker, message, message_addr
	);
	rrr_free(message);
	return ret;
}

#endif /* RRR_CMODULE_NATIVE_CTX */


#endif /* RRR_CMODULE_H */
