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

#include <stdlib.h>
#include <string.h>

#define RRR_NET_TRANSPORT_H_ENABLE_INTERNALS

#include "../log.h"
#include "../util/macro_utils.h"
#include "net_transport.h"
#include "net_transport_tls_common.h"

#define CHECK_FLAG(flag)				\
	do {if ((flags & flag) != 0) {		\
		flags_checked |= flag;			\
		flags &= ~(flag);				\
	}} while(0)

int rrr_net_transport_tls_common_new (
		struct rrr_net_transport_tls **target,
		int flags,
		const char *certificate_file,
		const char *private_key_file,
		const char *ca_file,
		const char *ca_path,
		const char *alpn_protos,
		unsigned int alpn_protos_length
) {
	struct rrr_net_transport_tls *result = NULL;

	*target = NULL;

	int ret = 0;

	int flags_checked = 0;
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY);
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_VERSION_MIN_1_1);
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_NO_ALPN);
/*
 *
					(flags & RRR_NET_TRANSPORT_F_TLS_NO_ALPN ? NULL : alpn_protos),
					(flags & RRR_NET_TRANSPORT_F_TLS_NO_ALPN ? 0 : alpn_protos_length)
 */

	if (flags != 0) {
		RRR_BUG("BUG: Unknown flags %i given to rrr_net_transport_tls_new\n", flags);
	}

	if ((result = malloc(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_net_transport_tls_new\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	if (certificate_file != NULL && *certificate_file != '\0') {
		if ((result->certificate_file = strdup(certificate_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for certificate file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (private_key_file != NULL && *private_key_file != '\0') {
		if ((result->private_key_file = strdup(private_key_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for private key file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (ca_file != NULL && *ca_file != '\0') {
		if ((result->ca_file = strdup(ca_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for CA file file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (ca_path != NULL && *ca_path != '\0') {
		if ((result->ca_path = strdup(ca_path)) == NULL) {
			RRR_MSG_0("Could not allocate memory for CA path file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
	}

	if (alpn_protos != NULL && *alpn_protos != '\0') {
		if ((result->alpn.protos = malloc(alpn_protos_length)) == NULL) {
			RRR_MSG_0("Could not allocate memory for ALPN protos in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free;
		}
		memcpy(result->alpn.protos, alpn_protos, alpn_protos_length);
		result->alpn.length = alpn_protos_length;
	}

	result->flags = flags_checked;

	*target = result;

	goto out;
	out_free:
		RRR_FREE_IF_NOT_NULL(result->alpn.protos);
		RRR_FREE_IF_NOT_NULL(result->ca_path);
		RRR_FREE_IF_NOT_NULL(result->ca_file);
		RRR_FREE_IF_NOT_NULL(result->certificate_file);
		RRR_FREE_IF_NOT_NULL(result->private_key_file);
		free(result);
	out:
		return ret;
}

int rrr_net_transport_tls_common_destroy (
		struct rrr_net_transport_tls *tls
) {
	RRR_FREE_IF_NOT_NULL(tls->alpn.protos);
	RRR_FREE_IF_NOT_NULL(tls->ca_path);
	RRR_FREE_IF_NOT_NULL(tls->ca_file);
	RRR_FREE_IF_NOT_NULL(tls->certificate_file);
	RRR_FREE_IF_NOT_NULL(tls->private_key_file);

	free(tls);

	return 0;
}

struct rrr_read_session *rrr_net_transport_tls_common_read_get_read_session(void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	struct rrr_net_transport_tls_data *ssl_data = callback_data->handle->submodule_private_ptr;

	return rrr_read_session_collection_maintain_and_find_or_create (
			&callback_data->handle->read_sessions,
			(struct sockaddr *) &ssl_data->sockaddr,
			ssl_data->socklen
	);
}

struct rrr_read_session *rrr_net_transport_tls_common_read_get_read_session_with_overshoot (
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;

	return rrr_read_session_collection_get_session_with_overshoot (
			&callback_data->handle->read_sessions
	);
}

void rrr_net_transport_tls_common_read_remove_read_session (
		struct rrr_read_session *read_session,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	rrr_read_session_collection_remove_session(&callback_data->handle->read_sessions, read_session);
}

int rrr_net_transport_tls_common_read_get_target_size (
		struct rrr_read_session *read_session,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	return callback_data->get_target_size(read_session, callback_data->get_target_size_arg);
}

int rrr_net_transport_tls_common_read_complete_callback (
		struct rrr_read_session *read_session,
		void *private_arg
) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	return callback_data->complete_callback(read_session, callback_data->complete_callback_arg);
}

// Caller must allocate size of ALPN vector + 1 byte. If to little is
// allocated, empty string is returned. No that even though a vector with
// one element is the exact size of the resulting output string, we must
// still allocate +1 to fit the comma temporarily.
void rrr_net_transport_tls_common_alpn_protos_to_str_comma_separated (
		unsigned char *out_buf,
		unsigned int out_size,
		const unsigned char *in,
		unsigned int in_size
) {
	unsigned int wpos = 0;
	for (unsigned int i = 0; i < in_size;/* increment at loop end */) {
		const unsigned char *text = in + i + 1;
		unsigned char text_length = in[i];

		if (i + text_length >= in_size) {
			RRR_MSG_0("Warning: Invalid size in vector from input in rrr_net_transport_tls_common_alpn_protos_to_str\n");
			wpos = 0;
			break;
		}

		// Fit comma and \0
		if (wpos + text_length + 2 > out_size) {
			break;
		}

		memcpy(out_buf + wpos, text, text_length);
		wpos += text_length;
		out_buf[wpos] = ',';
		wpos++;

		i += text_length + 1;
	}

	// PS ! Don't subtract 1 from 0 (please)
	out_buf[wpos > 0 ? wpos - 1 : 0] = '\0'; // Overwrites last ,
}
