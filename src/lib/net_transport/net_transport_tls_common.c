/*

Read Route Record

Copyright (C) 2020-2022 Atle Solbakken atle@goliathdns.no

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
#include "../allocator.h"
#include "../util/macro_utils.h"
#include "../socket/rrr_socket_graylist.h"
#include "net_transport.h"
#include "net_transport_struct.h"
#include "net_transport_tls_common.h"

#define CHECK_FLAG(flag)                                       \
    do {if ((flags_tls & flag) != 0) {                         \
        flags_tls_checked |= flag;                             \
        flags_tls &= ~(flag);                                  \
    }} while(0)

int rrr_net_transport_tls_common_new (
		struct rrr_net_transport_tls **target,
		int flags_tls,
		int flags_submodule,
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

	int flags_tls_checked = 0;
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_NO_CERT_VERIFY);
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_VERSION_MIN_1_1);
	CHECK_FLAG(RRR_NET_TRANSPORT_F_TLS_NO_ALPN);

	if (flags_tls != 0) {
		RRR_BUG("BUG: Unknown flags %i given to rrr_net_transport_tls_new\n", flags_tls);
	}

	if ((result = rrr_allocate_zero(sizeof(*result))) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_net_transport_tls_new\n");
		ret = 1;
		goto out;
	}

	if ((ret = rrr_socket_graylist_new (&result->connect_graylist)) != 0) {
		RRR_MSG_0("Could not allocate memory for connect graylist in rrr_net_transport_tls_new\n");
		goto out_free;
	}

	if (certificate_file != NULL && *certificate_file != '\0') {
		if ((result->certificate_file = rrr_strdup(certificate_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for certificate file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free_strings;
		}
	}

	if (private_key_file != NULL && *private_key_file != '\0') {
		if ((result->private_key_file = rrr_strdup(private_key_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for private key file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free_strings;
		}
	}

	if (ca_file != NULL && *ca_file != '\0') {
		if ((result->ca_file = rrr_strdup(ca_file)) == NULL) {
			RRR_MSG_0("Could not allocate memory for CA file file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free_strings;
		}
	}

	if (ca_path != NULL && *ca_path != '\0') {
		if ((result->ca_path = rrr_strdup(ca_path)) == NULL) {
			RRR_MSG_0("Could not allocate memory for CA path file in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free_strings;
		}
	}

	if (alpn_protos != NULL && *alpn_protos != '\0') {
		if ((result->alpn.protos = rrr_allocate(alpn_protos_length)) == NULL) {
			RRR_MSG_0("Could not allocate memory for ALPN protos in rrr_net_transport_tls_new\n");
			ret = 1;
			goto out_free_strings;
		}
		memcpy(result->alpn.protos, alpn_protos, alpn_protos_length);
		result->alpn.length = alpn_protos_length;
	}

	result->flags_tls = flags_tls_checked;
	result->flags_submodule = flags_submodule;

	*target = result;

	goto out;
	out_free_strings:
		RRR_FREE_IF_NOT_NULL(result->alpn.protos);
		RRR_FREE_IF_NOT_NULL(result->ca_path);
		RRR_FREE_IF_NOT_NULL(result->ca_file);
		RRR_FREE_IF_NOT_NULL(result->certificate_file);
		RRR_FREE_IF_NOT_NULL(result->private_key_file);
		rrr_socket_graylist_destroy(result->connect_graylist);
	out_free:
		rrr_free(result);
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

	rrr_socket_graylist_destroy(tls->connect_graylist);

	rrr_free(tls);

	return 0;
}

struct rrr_read_session *rrr_net_transport_tls_common_read_get_read_session(void *private_arg) {
	struct rrr_net_transport_read_callback_data *callback_data = private_arg;
	struct rrr_net_transport_tls_data *ssl_data = callback_data->handle->submodule_private_ptr;

	int is_new_dummy = 0;

	return rrr_read_session_collection_maintain_and_find_or_create (
			&is_new_dummy,
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

		i += (unsigned int) text_length + 1;
	}

	// PS ! Don't subtract 1 from 0 (please)
	out_buf[wpos > 0 ? wpos - 1 : 0] = '\0'; // Overwrites last ,
}
