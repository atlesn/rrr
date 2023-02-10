/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

extern "C" {
#include "allocator.h"
#include "instance_config.h"
};

#include <InstanceConfig.hxx>

namespace RRR {
	bool InstanceConfig::has(std::string name) {
		return rrr_instance_config_setting_exists(config, name.c_str()) != 0;
	}

	std::string InstanceConfig::get(std::string name) {
		if (!has(name)) {
			throw E("parameter " + name + " did not exist");
		}

		char *value = nullptr;
		if (rrr_instance_config_get_string_noconvert_silent(&value, config, name.c_str()) != 0) {
			throw E("failed to retrieve parameter " + name);
		}
		std::string result(value);
		rrr_free(value);

		return result;
	}
} // namespace RRR
