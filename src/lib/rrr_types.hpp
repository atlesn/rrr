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

#ifndef RRR_TYPES_HPP
#define RRR_TYPES_HPP

extern "C" {
#include "rrr_types.h"
}

namespace rrr::types {
	class data_const {
		public:
		const void *d;
		rrr_length l;
		data_const() = default;
		data_const(const void *d, rrr_length l) : d(d), l(l) {}
	};
}

#endif /* RRR_TYPES_HPP */
