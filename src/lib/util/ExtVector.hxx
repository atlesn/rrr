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
#include "../type.h"
};

#include <cassert>

namespace RRR::util {
	template <typename T> class ExtVector {
		private:
		void *data;
		rrr_length size;

		public:
		ExtVector(void *data, rrr_length size) :
			data(data),
			size(size)
		{
			assert(size % sizeof(T) == 0);
			assert(size > 0);
		}
		template <typename L> void iterate(L l) {
			for (rrr_length i = 0; i < size; i += sizeof(T)) {
				l(* (T*) ((uint8_t *) data + i));
			}
		}
	};

	template <typename T> class DynExtVector {
		private:
		T *data;
		rrr_length size;
		rrr_length divisor;

		public:
		DynExtVector(T *data, rrr_length size, rrr_length divisor) :
			data(data),
			size(size),
			divisor(divisor)
		{
			assert(size % divisor == 0);
			assert(size > 0);
		}
		template <typename L> void iterate(L l) {
			for (rrr_length i = 0; i < size; i += divisor) {
				l((T*) ((uint8_t *) data + i));
			}
		}
	};
} // namespace RRR::util
