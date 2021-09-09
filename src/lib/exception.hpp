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

#ifndef RRR_EXCEPTION_HPP
#define RRR_EXCEPTION_HPP

#include <string>

namespace rrr::exp {
	struct def : public std::exception {
		std::string msg;
		def(const std::string &msg) : msg(msg) {
		}
		const char *what() const noexcept override {
			return msg.c_str();
		}
		std::string what_str() const noexcept {
			return msg;
		}
	};

	struct bug : def {
		bug(const std::string &msg) : def(msg + " - BUG") {}
	};

	struct normal : def {
		normal(const std::string &msg) : def(msg) {}
		virtual int num() noexcept;
	};

	struct hard : normal {
		hard(const std::string &msg) : normal(msg + " - hard error") {}
		virtual int num() noexcept override;
	};
	struct soft : normal {
		soft(const std::string &msg) : normal(msg + " - soft error") {}
		virtual int num() noexcept override;
	};

	void check_and_throw (int ret, const std::string &msg);
}


#endif /* RRR_EXCEPTION_HPP */
