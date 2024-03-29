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
#include "../rrr_types.h"
};

#include <string>
#include <memory>

#include "Deleter.hxx"
#include "E.hxx"

namespace RRR::util {
	class Readfile {
		private:
		std::string data;

		public:
		class E : public RRR::util::E {
			public:
			E(std::string str) : RRR::util::E(str) {}
		};
		Readfile(std::string filename, size_t max_size, bool enoent_ok);
		operator std::string();
	};

}; // namespace RRR::util

