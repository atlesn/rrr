/*
return ret;

Read Route Record

Copyright (C) 2020-2023 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <strings.h>

#include "../log.h"
#include "../allocator.h"

#include "net_transport_config.h"

#include "../instance_config.h"
#include "../util/gnu.h"
#include "../util/macro_utils.h"

void rrr_net_transport_config_cleanup (
		struct rrr_net_transport_config *data
) {
	RRR_FREE_IF_NOT_NULL(data->tls_certificate_file);
	RRR_FREE_IF_NOT_NULL(data->tls_key_file);
	RRR_FREE_IF_NOT_NULL(data->tls_ca_file);
	RRR_FREE_IF_NOT_NULL(data->tls_ca_path);
	memset(data, '\0', sizeof(*data));
}

void rrr_net_transport_config_copy_mask_tls (
		struct rrr_net_transport_config *target,
		const struct rrr_net_transport_config *source
) {
	// Copy only non-TLS fields
	memset(target, '\0', sizeof(*target));
	target->transport_type_p = source->transport_type_p;
	target->transport_type_f = source->transport_type_f;
}

struct rrr_net_transport_config_parse_transport_type_callback_data {
	struct rrr_net_transport_config *data;
	struct rrr_instance_config_data *config;
	const char *prefix;
	int allow_multiple_transport_types;
};

static int __rrr_net_transport_config_parse_transport_type_callback (
		const char *value,
		void *arg
) {
	struct rrr_net_transport_config_parse_transport_type_callback_data *callback_data = arg;
	struct rrr_net_transport_config *data = callback_data->data;
	struct rrr_instance_config_data *config = callback_data->config;
	const char *prefix = callback_data->prefix;
	const char *name = config->name;

	int ret = 0;

	if (!callback_data->allow_multiple_transport_types && data->transport_type_p != RRR_NET_TRANSPORT_NONE) {
		RRR_MSG_0("Multiple %s_transport_type values specified in instance %s, this is an invalid configuration.\n",
			prefix, name);
		ret = 1;
		goto out;
	}

	if (strcasecmp(value, "both") == 0) {
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
		if (!callback_data->allow_multiple_transport_types) {
			RRR_MSG_0("Multiple %s_transport_type values specified in instance %s through use of deprecated " \
				"'both' specifier, this is an invalid configuration.\n",
				prefix, name);
			ret = 1;
			goto out;
		}

		RRR_MSG_0("Warning: The value 'both' for %s_transport_type is deprecated, use 'plain,tls' " \
			"or leave unspecified (for automatic selection) in instance %s\n",
			prefix, name);

		data->transport_type_f |= RRR_NET_TRANSPORT_F_PLAIN | RRR_NET_TRANSPORT_F_TLS;
#else
		RRR_MSG_0("Deprecated transport type specifier 'both' used in %s_transport_type but RRR is not compiled with TLS support\n",
			prefix);
		ret = 1;
		goto out;
#endif
	}
	else if (strcasecmp(value, "plain") == 0) {
		data->transport_type_f |= RRR_NET_TRANSPORT_F_PLAIN;
	}
	else if (strcasecmp(value, "tls") == 0) {
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
		data->transport_type_f |= RRR_NET_TRANSPORT_F_TLS;
#else
		RRR_MSG_0("TLS transport type specified in %s_transport_type but RRR is not compiled with TLS support\n",
			prefix);
#endif
	}
	else if (strcasecmp(value, "quic") == 0) {
#if defined(RRR_WITH_HTTP3)
		data->transport_type_f |= RRR_NET_TRANSPORT_F_QUIC;
#else
		RRR_MSG_0("QUIC transport type specified in %s_transport_type but RRR is not compiled with QUIC support\n",
			prefix);
#endif
	}
	else {
		RRR_MSG_0("Unknown value '%s' for %s_transport_type in instance %s\n",
			value, prefix, name);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int rrr_net_transport_config_parse (
		struct rrr_net_transport_config *data,
		struct rrr_instance_config_data *config,
		const char *prefix,
		int allow_multiple_transport_types,
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_HTTP3)
		int allow_tls_parameters_without_tls,
#endif
		enum rrr_net_transport_type default_transport,
		enum rrr_net_transport_type_f allowed_transports
) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PREFIX_BEGIN(prefix);

	struct rrr_net_transport_config_parse_transport_type_callback_data callback_data = {
		.data = data,
		.config = config,
		.prefix = prefix,
		.allow_multiple_transport_types = allow_multiple_transport_types
	};

	RRR_INSTANCE_CONFIG_STRING_SET("_transport_type");
	if ((ret = rrr_instance_config_traverse_split_commas_silent_fail (
			config,
			config_string,
			__rrr_net_transport_config_parse_transport_type_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error parsing %s_transport_type in instance %s\n",
			prefix, config->name);
		goto out;
	}

	data->transport_type_p = default_transport;

	if (data->transport_type_f == RRR_NET_TRANSPORT_F_NONE) {
		data->transport_type_f = (int) default_transport;
	}

	enum rrr_net_transport_type_f disallowed_transports = ~allowed_transports & data->transport_type_f;

	if (disallowed_transports & RRR_NET_TRANSPORT_F_PLAIN) {
		RRR_MSG_0("Plain transport type specified in %s_transport_type but type is not allowed in instance %s\n",
			prefix);
		ret = 1;
	}
#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL)
	if (disallowed_transports & RRR_NET_TRANSPORT_F_TLS) {
		RRR_MSG_0("TLS transport type specified in %s_transport_type but type is not allowed in instance %s\n",
			prefix);
		ret = 1;
	}
#endif
#if defined(RRR_WITH_HTTP3)
	if (disallowed_transports & RRR_NET_TRANSPORT_F_QUIC) {
		RRR_MSG_0("QUIC transport type specified in %s_transport_type but type is not allowed in instance %s\n",
			prefix);
		ret = 1;
	}
#endif
	if (ret != 0) {
		goto out;
	}

#if defined(RRR_WITH_LIBRESSL) || defined(RRR_WITH_OPENSSL) || defined(RRR_WITH_HTTP3)

	RRR_INSTANCE_CONFIG_STRING_SET("_tls_certificate_file");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, tls_certificate_file);

	RRR_INSTANCE_CONFIG_STRING_SET("_tls_key_file");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, tls_key_file);

	RRR_INSTANCE_CONFIG_STRING_SET("_tls_ca_file");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, tls_ca_file);

	RRR_INSTANCE_CONFIG_STRING_SET("_tls_ca_path");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, tls_ca_path);

	if (	(data->tls_certificate_file != NULL && data->tls_key_file == NULL) ||
			(data->tls_certificate_file == NULL && data->tls_key_file != NULL)
	) {
		RRR_MSG_0("Only one of %s_tls_certificate_file and %s_tls_key_file was specified, either both or none are required in instance %s\n",
				prefix, prefix, config->name);
		ret = 1;
		goto out;
	}

	if ( data->tls_certificate_file != NULL &&
	     !(data->transport_type_f & RRR_NET_TRANSPORT_F_TLS) &&
#if defined(RRR_WITH_HTTP3)
	     !(data->transport_type_f & RRR_NET_TRANSPORT_F_QUIC) &&
#endif
	     !allow_tls_parameters_without_tls
	) {
		RRR_MSG_0("TLS certificate specified in %s_tls_certificate_file but %s_transport_type did not contain 'tls' for instance %s\n",
				prefix, prefix, config->name);
		ret = 1;
		goto out;
	}
#endif

	RRR_INSTANCE_CONFIG_PREFIX_END();

	return ret;
}
