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

#include "Array.hxx"

extern "C" {
#include <string.h>
#include "array.h"
};

namespace RRR {
	Array::Array() {
		memset(&array, 0, sizeof(array));
	}
	Array::~Array() {
		rrr_array_clear(&array);
	}
	void Array::push_value_vain_with_tag(std::string tag) {
		verify_tag(tag);
		if (rrr_array_push_value_vain_with_tag(&array, tag.c_str()) != 0) {
			throw E("Error while pushing vain value");
		}
	}

	void Array::push_value_str_with_tag(std::string tag, std::string value) {
		verify_tag(tag);
		if (rrr_array_push_value_str_with_tag_with_size(&array, tag.c_str(), value.c_str(), value.length()) != 0) {
			throw E("Error while pushing string value");
		}
	}

	void Array::push_value_blob_with_tag_with_size(std::string tag, const char *value, rrr_length size) {
		verify_tag(tag);
		if (rrr_array_push_value_blob_with_tag_with_size(&array, tag.c_str(), value, size) != 0) {
			throw E("Error while pushing blob value");
		}
	}
}; // namespace RRR
