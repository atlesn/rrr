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

#ifndef RRR_NET_TRANSPORT_CONFIG_H
#define RRR_NET_TRANSPORT_CONFIG_H

#include "net_transport_defines.h"

struct rrr_instance_config;

struct rrr_net_transport_config {
	char *tls_certificate_file;
	char *tls_key_file;
	char *tls_ca_file;
	char *tls_ca_path;

	char *transport_type_str;
	enum rrr_net_transport_type transport_type;
};

void rrr_net_transport_config_cleanup (
		struct rrr_net_transport_config *data
);

int rrr_net_transport_config_parse (
		struct rrr_net_transport_config *data,
		struct rrr_instance_config *config,
		const char *prefix,
		int allow_both_transport_type,
		enum rrr_net_transport_type default_transport
);

#endif /* RRR_NET_TRANSPORT_TLS_CONFIG_H */
