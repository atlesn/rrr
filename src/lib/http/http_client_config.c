/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include "http_client_config.h"

#include "../instance_config.h"
#include "../map.h"
#include "../macro_utils.h"

void rrr_http_client_config_cleanup (
		struct rrr_http_client_config *data
) {
	RRR_FREE_IF_NOT_NULL(data->server);
	RRR_FREE_IF_NOT_NULL(data->method_str);
	RRR_FREE_IF_NOT_NULL(data->endpoint);
	RRR_MAP_CLEAR(&data->tags);
	RRR_MAP_CLEAR(&data->fixed_tags);
	RRR_MAP_CLEAR(&data->fields);
	RRR_MAP_CLEAR(&data->fixed_fields);
}

int rrr_http_client_config_parse (
		struct rrr_http_client_config *data,
		struct rrr_instance_config *config,
		const char *prefix,
		const char *default_server,
		uint16_t default_port,
		int enable_fixed,
		int enable_endpoint
) {
	int ret = 0;

	RRR_INSTANCE_CONFIG_PREFIX_BEGIN(prefix);

	RRR_INSTANCE_CONFIG_STRING_SET("_server");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(config_string, server, default_server);

	if (enable_endpoint) {
		RRR_INSTANCE_CONFIG_STRING_SET("_endpoint");
		RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8(config_string, endpoint, "/");
	}

	// Allow default port to be set to 0
	RRR_INSTANCE_CONFIG_STRING_SET("_port");
	RRR_INSTANCE_CONFIG_IF_EXISTS_THEN(config_string, RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_PORT(config_string, server_port, default_port));

	RRR_INSTANCE_CONFIG_STRING_SET("_method");
	RRR_INSTANCE_CONFIG_PARSE_OPTIONAL_UTF8_DEFAULT_NULL(config_string, method_str);

	/*
	 * DO NOT REMOVE THIS COMMENT
	 * Default method when user only specifies POST is RRR_HTTP_METHOD_POST_URLENCODED
	 */

	if (data->method_str == NULL || *(data->method_str) == '\0') {
		data->method = RRR_HTTP_METHOD_GET;
	}
	else if (	strcasecmp(data->method_str, "get") == 0
	) {
		data->method = RRR_HTTP_METHOD_GET;
	}
	else if (	strcasecmp(data->method_str, "post_multipart") == 0 ||
				strcasecmp(data->method_str, "post_multipart_form_data") == 0 ||
				strcasecmp(data->method_str, "multipart/form-data") == 0
	) {
		data->method = RRR_HTTP_METHOD_POST_MULTIPART_FORM_DATA;
	}
	else if (	strcasecmp(data->method_str, "post_urlencoded") == 0 ||
				strcasecmp(data->method_str, "post") == 0 ||
				strcasecmp(data->method_str, "application/x-www-urlencoded") == 0
	) {
		data->method = RRR_HTTP_METHOD_POST_URLENCODED;
		// RRR_HTTP_METHOD_POST_URLENCODED_NO_QUOTING only used by influxdb, not configurable
	}
	else if (	strcasecmp(data->method_str, "post_binary") == 0 ||
				strcasecmp(data->method_str, "post_application_octet_stream") == 0 ||
				strcasecmp(data->method_str, "application/octet-stream") == 0
	) {
		data->method = RRR_HTTP_METHOD_POST_APPLICATION_OCTET_STREAM;
	}
	else if (	strcasecmp(data->method_str, "post_text_plain") == 0
	) {
		data->method = RRR_HTTP_METHOD_POST_TEXT_PLAIN;
	}
	else {
		RRR_MSG_0("Unknown value '%s' for HTTP method in instance %s\n", config->name);
		ret = 1;
		goto out;
	}

	RRR_INSTANCE_CONFIG_STRING_SET("_tags");
	if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, config_string, rrr_map_parse_pair_arrow, &data->tags)) != 0) {
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
	if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, config_string, fields_parse_callback, &data->fields)) != 0) {
		if (ret != RRR_SETTING_NOT_FOUND) {
			RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
			ret = 1;
			goto out;
		}
	}

	if (enable_fixed) {
		RRR_INSTANCE_CONFIG_STRING_SET("_fixed_tags");
		if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, config_string, rrr_map_parse_pair_equal, &data->fixed_tags)) != 0) {
			if (ret != RRR_SETTING_NOT_FOUND) {
				RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
				ret = 1;
				goto out;
			}
			ret = 0;
		}

		RRR_INSTANCE_CONFIG_STRING_SET("_fixed_fields");
		if ((ret = rrr_settings_traverse_split_commas_silent_fail(config->settings, config_string, rrr_map_parse_pair_equal, &data->fixed_fields)) != 0) {
			if (ret != RRR_SETTING_NOT_FOUND) {
				RRR_MSG_0("Error while parsing %s of instance %s\n", config_string, config->name);
				ret = 1;
				goto out;
			}
		}
	}

	RRR_INSTANCE_CONFIG_PREFIX_END();

	return ret;
}
