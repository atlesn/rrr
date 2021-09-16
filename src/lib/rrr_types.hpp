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

#include "exception.hpp"
#include "util/macro_utils.hpp"

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
		data_const(std::pair<const void *, rrr_length> d) : d(d.first), l(d.second) {}
	};

	class data {
		public:
		void *d;
		rrr_length l;
		data() : d(NULL), l(0) {}
		data(void **d, rrr_length l) : d(*d), l(l) {
			*d = NULL;
		}
		data_const to_const() {
			if (d == NULL) {
				throw rrr::exp::bug(std::string("Data was NULL in ") + RRR_FUNC);
			}
			return data_const(d, l);
		}
	};

	static inline rrr_length length_from_size_t_exp_const (size_t x) {
		if (x > RRR_LENGTH_MAX) {
			throw new rrr::exp::soft("Overflow in " + RRR_FUNC);
		}
		return (rrr_length) x;
	}
}

#endif /* RRR_TYPES_HPP */
