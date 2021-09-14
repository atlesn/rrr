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
#include <algorithm>
#include <iostream>
#include <vector>
#include <cmath>
#include <map>

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
		coordinate() : a(0), b(0) {}
		coordinate(T a, T b) : a(a), b(b) {}
		void reset() {
			a = 0;
			b = 0;
		}
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
		void update_min(const coordinate<T> &src) {
			if (a == 0 || src.a < a)
				a = src.a;
			if (b == 0 || src.b < b)
				b = src.b;
		}
		void update_max(const coordinate<T> &src) {
			if (src.a > a)
				a = src.a;
			if (src.b > b)
				b = src.b;
		}
		bool in_box(const coordinate<T> &test, const T size) const {
			const size_t box_tl_a = test.a - (size > a ? a : size); 
			const size_t box_tl_b = test.b - (size > b ? b : size);
			const size_t box_br_a = test.a + size; 
			const size_t box_br_b = test.b + size;
			return (a >= box_tl_a && b >= box_tl_b && a <= box_br_a && b <= box_br_b);
		}
		void sub(size_t s) {
			a = s > a ? 0 : a - s;
			b = s > b ? 0 : b - s;
		}
		void add(size_t s, size_t a_max, size_t b_max) {
			size_t a_new = a + s;
			size_t b_new = b + s;
			if (a_new > a_max || a_new < a)
				a_new = a_max;
			if (b_new > b_max || b_new < b)
				b_new = b_max;
			a = a_new;
			b = b_new;
		}
	};

	template<typename T> class equals {
		public:
		constexpr bool operator() (const T &a, const T &b) const {
			printf("%u %u - %u %u\n", a.a, a.b, b.a, b.b);
			return a == b;
		}
	};

	typedef uint16_t mapunit;
	typedef coordinate<mapunit> mappos;
	
	std::ostream &operator<< (std::ostream &o, const rrr::magick::mappos &p) {
		o << std::to_string(p.a) << "x" << std::to_string(p.b);
		return o;
	}

	template<typename T> class minmax {
		public:
		T min;
		T max;
		void reset() {
		}
		void update(const T &c) {
			min.update_min(c);
			max.update_max(c);
		}
		void update(const minmax<T> &m) {
			min.update_min(m.min);
			min.update_min(m.max);
			max.update_max(m.min);
			max.update_max(m.max);
		}
		void expand(size_t s, size_t a_max, size_t b_max) {
			min.sub(s);
			max.add(s, a_max, b_max);
		}
	};

	class mappath {
		class interception {
			public:
			std::pair<const mappath *, const mappos> i;
			interception(const mappath *p, const mappos &pos) : i(p, pos) {}
			const mappath *path() const {
				return i.first;
			}
			const mappos pos() const {
				return i.second;
			}
		};

		public:
		std::vector<mappos> p;
		std::map<mappos,const mappath *,equals<mappos>> interceptions;
		minmax<mappos> m;
		void update_minmax_fast(const mappos &c) {
			m.update(c);
		}
		void update_minmax() {
			m.reset();
			for (size_t i = 0; i < p.size(); i++) {
				update_minmax_fast(p[i]);
			}
		}
		void update_ext_minmax(minmax<mappos> &m) const {
			m.update(this->m);
		}
		mappath(size_t reserve) : p() {
			p.reserve(reserve);
		}
		mappath &operator= (const mappath &src) {
			p = src.p;
			m = src.m;
			interceptions = src.interceptions;
			return *this;
		}
		size_t count() const {
			return p.size();
		}
		mappos operator[] (size_t i) const {
			return p[i];
		}
		void push(const mappos &e) {
			p.push_back(e);
			update_minmax_fast(e);
		}
		void push(const mappath &src) {
			p.insert(p.end(), src.p.begin(), src.p.end());
			m.update(src.m);
		}
		mappos pop_skip() {
			p.pop_back();
			mappos e = p.back();
			update_minmax();
			return e;
		}
		template<typename F> void check_close_to (const mappath &test, F action) const {
			for (size_t i = 0; i < p.size(); i++) {
				if (p[i].in_box(test.p.front(), 1) || p[i].in_box(test.p.back(), 1)) {
					action(p[i]);
					return;
				}
			}
		}
		mappos start() const {
			return p.front();
		}
		void push_unique_interception (const mappath *p, const mappos pos) {
			interceptions[pos] = p;
		}
		size_t count_interceptions() const {
			return interceptions.size();
		}
		template<typename F, typename G> void iterate(F f_pos, G f_path, std::vector<const mappath *> &tree) const {
			if (std::find_if(tree.begin(), tree.end(), [&](const mappath *p){
					return this == p;
			}) != tree.end()) {
				return;
			}

			f_path(*this);

			tree.push_back(this);

			int ic_count = 0;
			for (size_t i = 0; i < p.size(); i++) {
				f_pos(p[i]);
				if (interceptions.contains(p[i])) {
					std::cout << std::to_string(ic_count) << std::string(": ") << p[i] << std::endl;
					ic_count++;
					(*it).second->iterate(f_pos, f_path, tree);
				}
			}

			printf("============\n");
//			printf("%lu<>%i\n", interceptions.size(), ic_count);

			tree.pop_back();
		}
		template<typename F, typename G> void iterate(F f_pos, G f_path) const {
			std::vector<const mappath *> tree;
			iterate(f_pos, f_path, tree);
		}
	};

	struct vector {
		public:
		const float m;
		const float a;
		vector(float m, float a) : m(m), a(a) {}
	};

	class vectorpath {
		static const int calculate_border = 5;
		mappos p;
		std::vector<vector> v;
		std::vector<mappos> buf;
		public:
		vectorpath(const mappos &p) : p(p), buf(calculate_border) {}
		void calculate() {
			if (buf.size() < 2)
				return;

			const mappos &a = buf.front();
			const mappos &b = buf.back();

			const float v1 = (float) a.a - (float) b.a;
			const float v2 = (float) b.a - (float) b.b;

			const float mag = std::sqrt(std::pow(v1, 2.0f) + std::pow(v2, 2.0f));
			const float tan = v2 / v1;
			const float rad = std::atan(tan);

			v.emplace_back(mag, rad);

			buf.clear();
			
		}
		void push(const mappos &p) {
			buf.push_back(p);
			if (buf.size() == calculate_border) {
				calculate();
			}
		}
	};

	class mappath_group {
		std::vector<mappath> p;
		minmax<mappos> m;
		void update_minmax_fast(const mappath &p) {
			m.update(p.m);
		}
		public:
		void push(const mappath &src) {
			update_minmax_fast(src);
			p.push_back(src);
		}
		size_t count() const {
			return p.size();
		}
		template<typename F> void split(F action) {
			for (std::vector<mappath>::iterator it_a = p.begin(); it_a != p.end(); ++it_a) {
				for (std::vector<mappath>::const_iterator it_b = p.begin(); it_b != p.end(); ++it_b) {
					if (it_a == it_b)
						continue;
					const mappath *path_friend = &(*it_b);
					(*it_a).check_close_to((*it_b), [&](const mappos &p){
						it_a->push_unique_interception(path_friend, p);
					});
				}
				action(*it_a);
			}
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
		size_t size_a;
		size_t size_b;
		std::vector<element> v;

		public:
		map() : size_a(0), size_b(0), v() {}
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
		map<T> &operator= (const map<T> &src) {
			size_a = src.size_a;
			size_b = src.size_b;
			v = src.v;
			return *this;
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
		pixbuf(const pixbuf &src) :
			image(src.image),
			do_debug(src.do_debug),
			pixels(src.pixels),
			rows(src.rows),
			cols(src.cols),
			size(src.size),
			channels(src.channels),
			max_range_combined(src.max_range_combined) {
		}
		edges edges_clean_get() {
			return edges(rows, cols);
		}
		size_t height() const {
			return rows;
		}
		size_t width() const {
			return cols;
		}
		void set_debug() {
			do_debug = true;
		}
		void set(size_t a, size_t b, pixel_value v) {
			pixels.set(a, b, v);
		}
		edges edges_get (
				float threshold,
				rrr_length edge_length_max,
				size_t result_max
		);
		void edges_dump (
				const std::string &target_file_no_extension,
				const edges &m,
				mappos tl,
				mappos br
		);
		void edges_dump (
				const std::string &target_file_no_extension,
				const edges &m,
				minmax<mappos> crop
		);
		void edges_dump (
				const std::string &target_file_no_extension,
				const edges &m
		);
		mappath_group paths_get (
				const edges &m,
				rrr_length path_length_min,
				std::function<void(const edges &outlines)> debug
		);
	};
}

#endif /* RRR_MAGICK_HPP */
