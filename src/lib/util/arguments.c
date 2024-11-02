/*

Read Route Record

Copyright (C) 2019-2022 Atle Solbakken atle@goliathdns.no

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

#include "../cmdlineparser/cmdline.h"
#include "../log.h"

int rrr_arguments_parse_port (
		uint16_t *result,
		struct cmd_data *cmd,
		const char *arg,
		uint16_t port_default
) {
	int ret = 0;

	uint64_t port_tmp = port_default;

	const char *port_str = cmd_get_value(cmd, arg, 0);
	if (port_str != NULL) {
		if (cmd_get_value (cmd, arg, 1) != NULL) {
			RRR_MSG_0("Only one '%s' argument may be specified\n", arg);
			ret = 1;
			goto out;
		}
		if (cmd_convert_uint64_10(port_str, &port_tmp)) {
			RRR_MSG_0("Could not understand argument '%s', must an unsigned integer\n", arg);
			ret = 1;
			goto out;
		}
		if (port_tmp < 1 || port_tmp > 65535) {
			RRR_MSG_0("Argument '%s' out of range (must be 1-65535, got %" PRIu64 ")\n", arg, port_tmp);
			ret = 1;
			goto out;
		}
	}

	*result = (uint16_t) port_tmp;

	out:
	return ret;
}
