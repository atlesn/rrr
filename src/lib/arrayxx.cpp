/*

Read Route Record

Copyright (C) 2021 Atle Solbakken atle@goliathdns.no

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

#include "arrayxx.hpp"
#include "type.hpp"
#include "messages/msg_msg.h"
#include "util/macro_utils.hpp"

namespace rrr::array {
	array::array() : a() {
	}

	array::array(const struct rrr_msg_msg *msg) : a() {
		uint16_t version_dummy;
		if (!MSG_IS_ARRAY(msg)) {
			throw rrr::exp::soft("Message was not an array in " + RRR_FUNC);
		}
		if (rrr_array_message_append_to_array (&version_dummy, &a, msg) != 0) {
			throw rrr::exp::hard("Failed to append array to message in " + RRR_FUNC);
		}
	}

	array::~array() {
		rrr_array_clear(&a);
	}

	rrr::type::data_const array::get_value_raw_by_tag (const std::string &tag) const {
		const void *d;
		rrr_length l;
		if (rrr_array_get_value_raw_by_tag(&d, &l, &a, tag.c_str()) != 0) {
			throw rrr::exp::soft("Tag " + std::string(tag) + " not found in array");
		}
		return rrr::type::data_const(d, l);
	}
}
