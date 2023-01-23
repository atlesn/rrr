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
	rrr_biglength Array::allocated_size() {
		return rrr_array_get_allocated_size(&array);
	}
	void Array::to_message (struct rrr_msg_msg **final_message, uint64_t time, const char *topic, rrr_u16 topic_length) {
		if (rrr_array_new_message_from_array(final_message, &array, time, topic, topic_length)) {
			throw E("Failed to make message from array");
		}

	}
	void Array::add_from_message(uint16_t *version, const struct rrr_msg_msg *msg) {
		if (rrr_array_message_append_to_array(version, &array, msg) != 0) {
			throw E(std::string("Failed to append array in ") + __func__);
		}
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

	void Array::push_value_64_with_tag(std::string tag, uint64_t value) {
		verify_tag(tag);
		if (rrr_array_push_value_u64_with_tag(&array, tag.c_str(), value) != 0) {
			throw E("Error while pushing u64 value");
		}
	}

	void Array::push_value_64_with_tag(std::string tag, int64_t value) {
		verify_tag(tag);
		if (rrr_array_push_value_i64_with_tag(&array, tag.c_str(), value) != 0) {
			throw E("Error while pushing i64 value");
		}
	}

	void Array::push_value_fixp_with_tag(std::string tag, rrr_fixp value) {
		verify_tag(tag);
		if (rrr_array_push_value_fixp_with_tag(&array, tag.c_str(), value) != 0) {
			throw E("Error while pushing fixp value");
		}
	}

	void Array::push_value_fixp_with_tag(std::string tag, std::string string) {
		verify_tag(tag);
		rrr_fixp fixp = 0;
		const char *endptr = nullptr;
		if (rrr_fixp_str_to_fixp(&fixp, string.c_str(), string.length(), &endptr) != 0 || string.c_str() + string.length() != endptr) {
			throw E("Error while converting fixp value");
		}
		if (rrr_array_push_value_fixp_with_tag(&array, tag.c_str(), fixp) != 0) {
			throw E("Error while pushing fixp value");
		}
	}
}; // namespace RRR
