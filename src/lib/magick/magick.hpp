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

	typedef uint16_t pixel_value;
	typedef int8_t edge_value;

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

	class edgemask {
		public:
		static const uint8_t TR = 1<<0;
		static const uint8_t RR = 1<<1;
		static const uint8_t BR = 1<<2;
		static const uint8_t BB = 1<<3;
		static const uint8_t BL = 1<<4;
		static const uint8_t LL = 1<<5;
		static const uint8_t TL = 1<<6;
		static const uint8_t TT = 1<<7;

		uint8_t m;

		edgemask () : m(0xff) {
		}
		edgemask (uint8_t m) : m(m) {
		}
		edgemask (const edgemask &em) : m(em.m){
		}
		uint8_t operator|= (const edgemask &em) {
			return m |= em.m;
		}
		uint8_t operator= (const edgemask &em) {
			return m = em.m;
		}
		void widen() {
			m = (m << 1) | (m >> 1) | (m & TR ? TT : 0) | (m & TT ? TR : 0);
		}
		bool tr() const {return (m & TR) != 0; };
		bool rr() const {return (m & RR) != 0; };
		bool br() const {return (m & BR) != 0; };
		bool bb() const {return (m & BB) != 0; };
		bool bl() const {return (m & BL) != 0; };
		bool ll() const {return (m & LL) != 0; };
		bool tl() const {return (m & TL) != 0; };
		bool tt() const {return (m & TT) != 0; };
		void dump() const {
			printf("TR: %i RR: %i BR: %i BB: %i BL: %i LL: %i TL: %i TT: %i\n",
					(m & TR) != 0,
					(m & RR) != 0,
					(m & BR) != 0,
					(m & BB) != 0,
					(m & BL) != 0,
					(m & LL) != 0,
					(m & TL) != 0,
					(m & TT) != 0
			);
		}
	};

	typedef uint16_t mapunit;
	typedef coordinate<mapunit> mappos;

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

		map(size_t a, size_t b) : size_a(a), size_b(b), v(a * b) {
			if (a > UINT16_MAX || b > UINT16_MAX) {
				throw rrr::exp::soft("Size overflow in " + RRR_FUNC);
			}
			v.insert(v.begin(), a * b, element(0));
		}
		T get (mapunit a, mapunit b) const {
			return v[a + b * size_a].v;
		}
		T get(const mappos &c) const {
			return get(c.a, c.b);
		}
		T set(mapunit a, mapunit b, T value) {
			v[a + b * size_a].v = value;
			return value;
		}
		T set(mapunit a, mapunit b) {
			return set(a, b, 1);
		}
		T set(const mappos &c, T value) {
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
		template<typename F> mappos get_next_set(const mappos &start, F filter) const {
			mappos pos = start;
			do {
				pos.step(size_a, size_b);
				if (get(pos.a, pos.b) && filter((const mappos) pos)) {
					break;
				}
			} while (1);
			return pos;
		}
		template<typename F> mappos get_next_neighbour( const mappos &start, F filter) const {
			mappos pos;

			// Checks must be performed in circular order, these checks start with the top right and go clockwise

			// Check 3x3 square around position
			if (!(
			      // Top right
			      (start.a > 0          && start.b < size_b - 1 && filter(pos.set(start.a - 1, start.b + 1))) ||
			      (start.b < size_b - 1                         && filter(pos.set(start.a    , start.b + 1))) ||
			      // Bottom right
			      (start.a < size_a - 1 && start.b < size_b - 1 && filter(pos.set(start.a + 1, start.b + 1))) ||
			      (start.a < size_a - 1                         && filter(pos.set(start.a + 1, start.b    ))) ||
			      // Bottom left
			      (start.a < size_a - 1 && start.b > 0          && filter(pos.set(start.a + 1, start.b - 1))) ||
			      (start.b > 0                                  && filter(pos.set(start.a,     start.b - 1))) ||
			      // Top left
			      (start.a > 0          && start.b > 0          && filter(pos.set(start.a - 1, start.b - 1))) ||
			      (start.a > 0                                  && filter(pos.set(start.a - 1, start.b    ))) ||
			      0
			)) {
				// Check 5x5 square around position
				if (!(
				      // Right edge
				      (start.a > 1          && start.b < size_b - 2 && filter(pos.set(start.a - 2, start.b + 2))) ||
				      (start.a > 0          && start.b < size_b - 2 && filter(pos.set(start.a - 1, start.b + 2))) ||
				      (                        start.b < size_b - 2 && filter(pos.set(start.a,     start.b + 2))) ||
				      (start.a < size_a - 1 && start.b < size_b - 2 && filter(pos.set(start.a + 1, start.b + 2))) ||
				      (start.a < size_a - 2 && start.b < size_b - 2 && filter(pos.set(start.a + 2, start.b + 2))) ||
				      // Bottom edge
				      (start.b < size_b - 1 && start.a < size_a - 2 && filter(pos.set(start.a + 2, start.b + 1))) ||
				      (                        start.a < size_a - 2 && filter(pos.set(start.a + 2, start.b    ))) ||
				      (start.b > 0          && start.a < size_a - 2 && filter(pos.set(start.a + 2, start.b - 1))) ||
				      // Left edge
				      (start.a < size_a - 2 && start.b > 1          && filter(pos.set(start.a + 2, start.b - 2))) ||
				      (start.a < size_a - 1 && start.b > 1          && filter(pos.set(start.a + 1, start.b - 2))) ||
				      (                        start.b > 1          && filter(pos.set(start.a,     start.b - 2))) ||
				      (start.a > 0          && start.b > 1          && filter(pos.set(start.a - 1, start.b - 2))) ||
				      (start.a > 1          && start.b > 1          && filter(pos.set(start.a - 2, start.b - 2))) ||
				      // Top edge
				      (start.b > 0          && start.a > 1          && filter(pos.set(start.a - 2, start.b - 1))) ||
				      (                        start.a > 1          && filter(pos.set(start.a - 2, start.b    ))) ||
				      (start.b < size_b - 1 && start.a > 1          && filter(pos.set(start.a - 2, start.b + 1))) ||
				      0
				)) {
					throw rrr::exp::eof();
				}
			}

			return pos;
		}
		size_t neighbours_count(edgemask &mask, const mappos &pos, size_t max, T value) const {
			edgemask mask_out = 0;
			T count = 0;
			((mask.tl() && pos.a > 0        && pos.b > 0        && get(pos.a-1, pos.b-1) == value && (mask_out |= edgemask::TL) && ++count >= max) ||
			 (mask.tr() && pos.a > 0        && pos.b < size_b-1 && get(pos.a-1, pos.b+1) == value && (mask_out |= edgemask::TR) && ++count >= max) ||
			 (mask.bl() && pos.a < size_a-1 && pos.b > 0        && get(pos.a+1, pos.b-1) == value && (mask_out |= edgemask::BL) && ++count >= max) ||
			 (mask.br() && pos.a < size_a-1 && pos.b < size_b-1 && get(pos.a+1, pos.b+1) == value && (mask_out |= edgemask::BR) && ++count >= max) ||
			 (mask.tt() && pos.a > 0        && get(pos.a-1, pos.b) == value && (mask_out |= edgemask:: TT) && ++count >= max) ||
			 (mask.bb() && pos.a < size_a-1 && get(pos.a+1, pos.b) == value && (mask_out |= edgemask:: BB) && ++count >= max) ||
			 (mask.ll() && pos.b > 0        && get(pos.a, pos.b-1) == value && (mask_out |= edgemask:: LL) && ++count >= max) ||
			 (mask.rr() && pos.b < size_b-1 && get(pos.a, pos.b+1) == value && (mask_out |= edgemask:: RR) && ++count >= max) ||
			 0
			);
			mask = mask_out;
			return count;
		}
		size_t neighbours_count(const edgemask &mask, const mappos &pos, size_t max, T value) const {
			edgemask mask_tmp = mask;
			return neighbours_count(mask_tmp, pos, max, value);
		}
		size_t neighbours_count(const mappos &pos, size_t max, T value) const {
			return neighbours_count(0xff, pos, max, value);
		}
	};

	typedef map<edge_value> edges;

	void load();
	void unload();

	class pixbuf {
		Magick::Image image;

		short do_debug;

		static const uint16_t pixel_max = UINT16_MAX;
		map<pixel_value> pixels;

		const size_t rows;
		const size_t cols;
		const size_t size;
		const size_t channels;
		
		const double max_range_combined;

		template <typename A, typename B> void edges_get (
				float threshold,
				rrr_length edge_length_max,
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

		edges edges_get(float threshold, rrr_length edge_length_max);
		void edges_dump (const std::string &target_file_no_extension, const edges &m);

		edges outlines_get (const edges &m);
	};
}

#endif /* RRR_MAGICK_HPP */
