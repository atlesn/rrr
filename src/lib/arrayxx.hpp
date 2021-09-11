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

#ifndef RRR_ARRAY_HPP
#define RRR_ARRAY_HPP

#include "exception.hpp"
#include "type.hpp"

extern "C" {
#include "array.h"
}

namespace rrr::array {
	class array {
		struct rrr_array a;

		public:
		array();
		array(const struct rrr_msg_msg *msg);
		~array();

		rrr::type::data_const get_value_raw_by_tag (const std::string &tag) const;
	};
}

#endif /* RRR_ARRAY_HPP */
