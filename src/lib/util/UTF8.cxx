/*

Read Route Record

Copyright (C) 2024 Atle Solbakken atle@goliathdns.no

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

#include "UTF8.hxx"
#include "E.hxx"

extern "C" {
#include "../rrr_types.h"
#include "utf8.h"
};

namespace RRR::util {
	void UTF8::validate(const std::string &str) {
		if (str.size() > RRR_LENGTH_MAX) {
			throw E("String length exceeded maximum while validating UTF-8");
		}
		if (rrr_utf8_validate(str.c_str(), str.size()) != 0) {
			throw E("UTF-8 validation failed");
		}
	}

	void UTF8::validate(const std::vector<char> &vec) {
		if (vec.size() > RRR_LENGTH_MAX) {
			throw E("String length exceeded maximum while validating UTF-8");
		}
		if (rrr_utf8_validate(vec.data(), (rrr_length) vec.size())) {
			throw E("UTF-8 validation failed");
		}
	}
};
