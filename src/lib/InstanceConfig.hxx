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
};

#include <string>

#include "util/E.hxx"

struct rrr_instance_config_data;

namespace RRR {
	class InstanceConfig {
		struct rrr_instance_config_data *config;

		public:
		class E : public RRR::util::E {
			public:
			E(std::string msg) :
				RRR::util::E(msg)
			{
			}
		};

		InstanceConfig(struct rrr_instance_config_data *config) :
			config(config)
		{
		}

		bool has(std::string name);
		std::string get(std::string name);
	};
} // namespace RRR
