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

#pragma once

extern "C" {
#include "array.h"
};

#include <string>

#include "util/E.hxx"

namespace RRR {
	class Array {
		private:
		struct rrr_array array;
		public:
		Array();
		~Array();
		class E : public RRR::util::E {
			public:
			E(std::string msg) : RRR::util::E(msg) {}
		};
		static void verify_tag(std::string tag) {
			if (tag.length() > RRR_TYPE_TAG_MAX) {
				throw E(std::string("Tag length exceeds maximum (") + std::to_string(tag.length()) + ">" + std::to_string(RRR_TYPE_TAG_MAX) + ")");
			}
		}
		struct rrr_array * operator *() {
			return &array;
		}
		int count() {
			return rrr_array_count(&array);
		}
		void push_value_vain_with_tag(std::string tag) {
			verify_tag(tag);
			if (rrr_array_push_value_vain_with_tag(&array, tag.c_str()) != 0) {
				throw E("Error while pushing vain value");
			}
		}
	};
}; // namespace RRR
