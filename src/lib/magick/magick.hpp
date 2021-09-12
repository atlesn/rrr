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
#include "../exception.hpp"

namespace rrr::magick {
	class wrap : rrr::exp::eof {
		using rrr::exp::eof::eof;
	};

	template<typename T> class coordinate {
		public:
		T a;
		T b;
		coordinate(T a, T b) : a(a), b(b) {}
		coordinate() : a(0), b(0) {}
		void step(T max_a, T max_b) {
			if (++b >= max_b) {
				b = 0;
				if (++a >= max_a) {
					a = 0;
					b = 0;
					throw rrr::exp::eof();
				}
			}
		}
		coordinate<T> &set(T a, T b) {
			this->a = a;
			this->b = b;
			return *this;
		}
		bool operator== (const coordinate<T> &test) const {
			return (test.a == a && test.b == b);
		}
		coordinate<T> operator= (const coordinate<T> &src) {
			this->a = src.a;
			this->b = src.b;
			return *this;
		}
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
		const size_t size_a;
		const size_t size_b;
		std::vector<element> v;

		public:
		static const uint8_t TR = 1<<0;
		static const uint8_t RR = 1<<1;
		static const uint8_t BR = 1<<2;
		static const uint8_t BB = 1<<3;
		static const uint8_t BL = 1<<4;
		static const uint8_t LL = 1<<5;
		static const uint8_t TL = 1<<6;
		static const uint8_t TT = 1<<7;

		map(size_t a, size_t b) : size_a(a), size_b(b), v(a * b) {
			v.insert(v.begin(), a * b, element(0));
		}
		T get (size_t a, size_t b) const {
			return v[a + b * size_a].v;
		}
		T get(const coordinate<size_t> &c) const {
			return get(c.a, c.b);
		}
		T set(size_t a, size_t b, T value) {
			v[a + b * size_a].v = value;
			return value;
		}
		T set(size_t a, size_t b) {
			return set(a, b, 1);
		}
		T set(const coordinate<size_t> &c, T value) {
			return set(c.a, c.b, value);
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
		template<typename F> coordinate<size_t> get_next_set(const coordinate<size_t> &start, F filter) const {
			coordinate<size_t> pos = start;
			do {
				pos.step(size_a, size_b);
				if (get(pos.a, pos.b) && filter((const coordinate<size_t>) pos)) {
					break;
				}
			} while (1);
			return pos;
		}
		template<typename F> coordinate<size_t> get_next_neighbour(uint16_t &constraint_mask, const coordinate<size_t> &start, F filter) const {
			coordinate<size_t> pos;

			// Checks must be performed in circular order, these checks start with the top right and go clockwise
			if (!(
			      (!(constraint_mask & TR) && start.a > 0        && start.b < size_b-1 && filter(pos.set(start.a-1, start.b+1)) && (constraint_mask = TR)) ||
			      (!(constraint_mask & RR) && start.b < size_b-1                       && filter(pos.set(start.a, start.b+1))   && (constraint_mask = RR)) || 
			      (!(constraint_mask & BR) && start.a < size_a-1 && start.b < size_b-1 && filter(pos.set(start.a+1, start.b+1)) && (constraint_mask = BR)) ||
			      (!(constraint_mask & BB) && start.a < size_a-1                       && filter(pos.set(start.a+1, start.b))   && (constraint_mask = BB)) ||
			      (!(constraint_mask & BL) && start.a < size_a-1 && start.b > 0        && filter(pos.set(start.a+1, start.b-1)) && (constraint_mask = BL)) ||
			      (!(constraint_mask & LL) && start.b > 0                              && filter(pos.set(start.a, start.b-1))   && (constraint_mask = LL)) ||
			      (!(constraint_mask & TL) && start.a > 0        && start.b > 0        && filter(pos.set(start.a-1, start.b-1)) && (constraint_mask = TL)) ||
			      (!(constraint_mask & TT) && start.a > 0                              && filter(pos.set(start.a-1, start.b))   && (constraint_mask = TT)) ||
			      0
			)) {
				throw rrr::exp::eof();
			}

			return pos;
		}
		size_t neighbours_count(const coordinate<size_t> pos, size_t max) const {
			T count = 0;
			((pos.a > 0        && pos.b > 0        && get(pos.a-1, pos.b-1) && ++count >= max) ||
			 (pos.a > 0        && pos.b < size_b-1 && get(pos.a-1, pos.b+1) && ++count >= max) ||
			 (pos.a < size_a-1 && pos.b > 0        && get(pos.a+1, pos.b-1) && ++count >= max) ||
			 (pos.a < size_a-1 && pos.b < size_b-1 && get(pos.a+1, pos.b+1) && ++count >= max) ||
			 (pos.a > 0        && get(pos.a-1, pos.b) && ++count >= max) ||
			 (pos.a < size_a-1 && get(pos.a+1, pos.b) && ++count >= max) ||
			 (pos.b > 0        && get(pos.a, pos.b-1) && ++count >= max) ||
			 (pos.b < size_b-1 && get(pos.a, pos.b+1) && ++count >= max)
			);
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

		edges outlines_get (const edges &m);
	};
}

#endif /* RRR_MAGICK_HPP */
