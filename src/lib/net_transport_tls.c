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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "../global.h"
#include "net_transport_tls.h"

static void __rrr_net_transport_tls_destroy (struct rrr_net_transport *transport) {
	struct rrr_net_transport_tls *tls = (struct rrr_net_transport_tls *) transport;

	free(tls);
}

static int __rrr_net_transport_tls_connect (
		int *handle,
		struct rrr_net_transport *transport,
		unsigned int port,
		const char *host
) {
	(void)(handle);
	(void)(transport);
	(void)(port);
	(void)(host);
	RRR_BUG("Not implemented\n");
	return 1;
}

static int __rrr_net_transport_tls_close (struct rrr_net_transport *transport, int handle) {
	(void)(transport);
	(void)(handle);
	RRR_BUG("Not implemented\n");
	return 1;
}

static int __rrr_net_transport_tls_read_message (
	struct rrr_net_transport *transport,
	int transport_handle,
	ssize_t read_step_initial,
	ssize_t read_step_max_size,
	int (*get_target_size)(struct rrr_net_transport_read_session *read_session, void *arg),
	void *get_target_size_arg,
	int (*complete_callback)(struct rrr_net_transport_read_session *read_session, void *arg),
	void *complete_callback_arg
) {
	(void)(transport);
	(void)(transport_handle);
	(void)(read_step_initial);
	(void)(read_step_max_size);
	(void)(get_target_size);
	(void)(get_target_size_arg);
	(void)(complete_callback);
	(void)(complete_callback_arg);
	RRR_BUG("Not implemented\n");
	return 1;
}

static int __rrr_net_transport_tls_send (
	struct rrr_net_transport *transport,
	int transport_handle,
	void *data,
	ssize_t size
) {
	(void)(transport);
	(void)(transport_handle);
	(void)(data);
	(void)(size);
	RRR_BUG("Not implemented\n");
	return 1;
}

static const struct rrr_net_transport_methods tls_methods = {
	__rrr_net_transport_tls_destroy,
	__rrr_net_transport_tls_connect,
	__rrr_net_transport_tls_close,
	__rrr_net_transport_tls_read_message,
	__rrr_net_transport_tls_send
};

int rrr_net_transport_tls_new (struct rrr_net_transport_tls **target) {
	struct rrr_net_transport_tls *result = NULL;

	*target = NULL;

	int ret = 0;

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_net_transport_tls_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	result->methods = &tls_methods;

	*target = result;

	out:
	return ret;
}
