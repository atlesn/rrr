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

#ifndef RRR_INSTANCE_CONFIG_HPP
#define RRR_INSTANCE_CONFIG_HPP

#include <string>

extern "C" {
#include "instance_config.h"
#include "allocator.h"
#include "util/macro_utils.h"
}

namespace rrr::instance_config::parse {
	class parse_error : public std::exception {
		std::string msg;

		public:
		parse_error(std::string msg) : msg(msg) {
		}

		virtual const char *what() throw() {
			return this->msg.c_str();
		}
	};

	template <typename T> struct ptr {
		T *p;
		ptr() {
			this->p = NULL;
		}
		ptr(T *p) : p(p) {
		}
		~ptr() {
			RRR_FREE_IF_NOT_NULL(this->p);
		}
		T *operator= (char *p) {
			RRR_FREE_IF_NOT_NULL(this->p);
			return (this->p = p);
		}
	};

	void utf8_optional (
			std::string &target,
			struct rrr_instance_config_data *config,
			const std::string &string,
			const std::string &def
	) {
		ptr<char> p;

		int ret_tmp = 0;

		if ((ret_tmp = rrr_instance_config_parse_optional_utf8 (&p.p, config, string.c_str(), def.c_str())) != 0) {
			if (ret_tmp != RRR_SETTING_NOT_FOUND) {
				throw new parse_error("Failed to parse UTF8 parameter '" + string + "'");
			}
			target = def;
			goto out;
		}

		target = p.p;

		out:
		return;
	}
}

#endif /* RRR_INSTANCE_CONFIG_HPP */
