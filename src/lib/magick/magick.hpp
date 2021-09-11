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

#ifndef RRR_MAGICK_HPP
#define RRR_MAGICK_HPP

#include <Magick++.h>

#include <vector>

#include "../rrr_types.hpp"

namespace rrr::magick {
	template<typename T> class coordinate {
		public:
		T x;
		T y;
		coordinate(T x, T y) : x(x), y(y) {}
	};

	template<typename T> class pixel {
		public:
		T v;
		pixel(T v) : v(v) {}
	};

	void load();
	void unload();

	class pixbuf {
		Magick::Image image;

		short do_debug;

		static const uint16_t pixel_max = UINT16_MAX;
		std::vector<pixel<uint16_t>> pixels;

		const size_t rows;
		const size_t cols;
		const size_t size;
		const size_t channels;
		
		const double max_range_combined;

		public:
		pixbuf(const rrr::types::data_const &d);

		void set_debug() {
			do_debug = true;
		}

		std::vector<coordinate<rrr_length>> horizontal_edges_get(float threshold);
	};
}

#endif /* RRR_MAGICK_HPP */
