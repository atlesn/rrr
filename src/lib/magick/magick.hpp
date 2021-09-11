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

#include <functional>
#include <vector>

#include "../rrr_types.hpp"

namespace rrr::magick {
	template<typename T> class coordinate {
		public:
		T x;
		T y;
		coordinate(T x, T y) : x(x), y(y) {}
	};
/*
	template<typename T> class pixel {
		public:
		T v;
		pixel(T v) : v(v) {}
		pixel(const T &p) : v(p.v) {}
		T operator= (T v) {
			return this->v = v;
		}
		pixel<T> operator= (const pixel<T> &p) {
			return this->v = p.v;
		}
	};
*/
	template<typename T> class map {
		public:
		class element {
			public:
			T v;
			element() : v(0) {}
			element(T v) : v(v) {}
			T operator= (T &v) {
				return element::v = v;
			}
		};

		private:
		const size_t size_x;
		const size_t size_y;
		std::vector<element> v;

		public:
		map(size_t x, size_t y) : size_x(x), size_y(y), v(x * y) {
			v.insert(v.begin(), x * y, element(0));
		}
		T get (size_t x, size_t y) const {
			return v[x + y * size_x].v;
		}
		T set(size_t x, size_t y) {
			v[x + y * size_x] = element(1);
			return 1;
		}
		T set(size_t x, size_t y, T value) {
			v[x + y * size_x].v = value;
			return value;
		}
		size_t count() {
			size_t count = 0;
			for (size_t i = 0; i < v.size(); i++) {
				if (v[i].v != 0) {
					count++;
				}
			}
			return count;
		}
	};

	typedef map<uint8_t> edges;

	void load();
	void unload();

	class pixbuf {
		Magick::Image image;

		short do_debug;

		static const uint16_t pixel_max = UINT16_MAX;
		map<uint16_t> pixels;

		const size_t rows;
		const size_t cols;
		const size_t size;
		const size_t channels;
		
		const double max_range_combined;

		template <typename A, typename B> void edges_get (
				float threshold,
				A getter,
				B setter,
				rrr_length a_max,
				rrr_length b_max
		);

		public:
		pixbuf(const rrr::types::data_const &d);

		void set_debug() {
			do_debug = true;
		}

		edges edges_get(float threshold);
		void edges_dump (const std::string &target_file_no_extension, const edges &m);
	};
}

#endif /* RRR_MAGICK_HPP */
