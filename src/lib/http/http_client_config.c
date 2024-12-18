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
#include <string.h>
#include <strings.h>

#include "../log.h"
#include "../allocator.h"

#include "http_client_config.h"
#include "http_util.h"

#include "../instance_config.h"
#include "../map.h"
#include "../util/macro_utils.h"
#include "../util/rrr_str.h"
#include "../util/gnu.h"

void rrr_http_client_config_cleanup (
		struct rrr_http_client_config *data
) {
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->method_str);
	RRR_FREE_IF_NOT_NULL(data->endpoint);
	RRR_FREE_IF_NOT_NULL(data->body_format_str);
	RRR_MAP_CLEAR(&data->tags);
	RRR_MAP_CLEAR(&data->fixed_tags);
	RRR_MAP_CLEAR(&data->fields);
	RRR_MAP_CLEAR(&data->fixed_fields);
	RRR_MAP_CLEAR(&data->extra_parse_headers);
}

int rrr_http_client_config_parse (
		struct rrr_http_client_config *data,
		struct rrr_instance_config_data *config,
		const char *prefix,
		const char *default_server,
		uint16_t default_port,
		uint16_t default_concurrent_connections,
		int enable_fixed,
		int enable_endpoint,
		int enable_format
) {
	int ret = 0;

	char *value_tmp = NULL;

	RRR_INSTANCE_CONFIG_PREFIX_BEGIN(prefix);

	RRR_INSTANCE_CONFIG_STRING_SET("_server");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(config_string, server, default_server);

	if (enable_endpoint) {
		RRR_INSTANCE_CONFIG_STRING_SET("_endpoint");
		RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(config_string, endpoint, "/");
	}

	// Allow default port to be set to 0
	data->server_port = default_port;
	RRR_INSTANCE_CONFIG_STRING_SET("_port");
	if ((ret = rrr_instance_config_read_optional_port_number (&data->server_port, config, config_string)) != 0) {
		RRR_MSG_0("Error while parsing %s setting for instance %s\n", config_string, config->name);
		goto out;
	}

	RRR_INSTANCE_CONFIG_STRING_SET("_method");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, method_str);

#ifdef RRR_WITH_NGHTTP2
	RRR_INSTANCE_CONFIG_STRING_SET("_plain_http2");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(config_string, do_plain_http2, 0);

	RRR_INSTANCE_CONFIG_STRING_SET("_no_http2_upgrade");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(config_string, do_no_http2_upgrade, 0);
#endif

	RRR_INSTANCE_CONFIG_STRING_SET("_concurrent_connections");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UNSIGNED(config_string, concurrent_connections, default_concurrent_connections);

	RRR_INSTANCE_CONFIG_STRING_SET("_version_10");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_YESNO(config_string, do_http_10, 0);

	if (data->concurrent_connections < 1 || data->concurrent_connections > 0xffff) {
		RRR_MSG_0("Parameter %s was out of range, value must be > 0 and < 65536.\n", config_string);
		ret = 1;
		goto out;
	}

	data->method = rrr_http_util_method_str_to_enum(data->method_str); // Any value allowed, also NULL

	RRR_INSTANCE_CONFIG_STRING_SET("_tags");
	if ((ret = rrr_settings_traverse_split_commas_silent_fail (
			&config->settings_used,
			config->settings,
			config_string,
			rrr_map_parse_pair_arrow,
			&data->tags
	)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
			ret = 1;
			goto out;
		}
	}

	// In the httpclient module, which does not use fixed tags and fields parameters, this
	// paramaters consists of name=value pairs.
	int (*fields_parse_callback)(const char *input, void *arg) = (
			enable_fixed
			? rrr_map_parse_pair_arrow
			: rrr_map_parse_pair_equal
	);

	RRR_INSTANCE_CONFIG_STRING_SET("_fields");
	if ((ret = rrr_settings_traverse_split_commas_silent_fail(&config->settings_used, config->settings, config_string, fields_parse_callback, &data->fields)) != 0) {
		ret &= ~(RRR_SETTING_NOT_FOUND);
		if (ret != 0) {
			RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
			ret = 1;
			goto out;
		}
	}

	if (enable_format) {
		RRR_INSTANCE_CONFIG_STRING_SET("_format");
		RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, body_format_str);
		data->body_format = rrr_http_util_format_str_to_enum(data->body_format_str); // Any value allowed, also NULL
	}

	if (enable_fixed) {
		RRR_INSTANCE_CONFIG_STRING_SET("_fixed_tags");
		if ((ret = rrr_settings_traverse_split_commas_silent_fail(&config->settings_used, config->settings, config_string, rrr_map_parse_pair_equal, &data->fixed_tags)) != 0) {
			ret &= ~(RRR_SETTING_NOT_FOUND);
			if (ret != 0) {
				RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
				ret = 1;
				goto out;
			}
		}

		RRR_INSTANCE_CONFIG_STRING_SET("_fixed_fields");
		if ((ret = rrr_settings_traverse_split_commas_silent_fail(&config->settings_used, config->settings, config_string, rrr_map_parse_pair_equal, &data->fixed_fields)) != 0) {
			ret &= ~(RRR_SETTING_NOT_FOUND);
			if (ret != 0) {
				RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
				ret = 1;
				goto out;
			}
		}
	}

	RRR_INSTANCE_CONFIG_STRING_SET("_trap_headers");
	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN(config_string,
		if  ((ret = rrr_instance_config_parse_comma_separated_to_map (
				&data->extra_parse_headers,
				config,
				config_string
		)) != 0) {
			RRR_MSG_0("Failed to parse parameter '%s' of instance %s\n",
				config_string, config->name);
			goto out;
		}

		RRR_MAP_ITERATE_BEGIN(&data->extra_parse_headers);
			RRR_FREE_IF_NOT_NULL(value_tmp);

			rrr_str_tolower(node->tag);

			if (rrr_asprintf(&value_tmp, "http_%s", node->tag) <= 0) {
				RRR_MSG_0("Failed to create header trap value in %s\n", __func__);
				ret = 1;
				goto out;
			}

			if ((ret = rrr_map_item_value_set(node, value_tmp)) != 0) {
				RRR_MSG_0("Failed to set header trap value in %s\n", __func__);
				goto out;
			}
		RRR_MAP_ITERATE_END();
	);

	RRR_INSTANCE_CONFIG_PREFIX_END();

	RRR_FREE_IF_NOT_NULL(value_tmp);

	return ret;
}
