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

#include <iterator>
#include <string>
#include <iostream>
#include <functional>
#include <algorithm>
#include <vector>
#include <cmath>
#include <map>
#include <set>
#include <bit>
#include <numbers>

#include "../rrr_types.hpp"
#include "../exception.hpp"

extern "C" {
#include "string.h"
}

#define RRR_MAGICK_PIXEL_CLEAN 0
#define RRR_MAGICK_PIXEL_OUTSIDE 1
#define RRR_MAGICK_PIXEL_EDGE 2
#define RRR_MAGICK_PIXEL_INSIDE 3
#define RRR_MAGICK_PIXEL_USED 4
#define RRR_MAGICK_PIXEL_BANNED 5

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
		coordinate(T x) : a(x), b(x) {}
		coordinate(T a, T b) : a(a), b(b) {}
		bool operator== (const coordinate<T> &test) const {
			return (test.a == a && test.b == b);
		}
		coordinate<T> &set(T a, T b) {
			this->a = a;
			this->b = b;
			return *this;
		}
		bool equals(const coordinate<T> &test) const {
			return (test.a == a && test.b == b);
		}
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
		void move_vector(ssize_t a, ssize_t b) {
			ssize_t a_new = this->a + a;
			ssize_t b_new = this->b + b;
			if (a_new < 0)
				a_new = 0;
			if (b_new < 0)
				b_new = 0;
			this->a = (T) a_new;
			this->b = (T) b_new;
		}
		void move_towards(const coordinate<T> &target) {
			if (target.a < a) {
				a--;
			}
			else if (target.a > a) {
				a++;
			}
			if (target.b < b) {
				b--;
			}
			else if (target.b > b) {
				b++;
			}
		}
	};

	typedef uint16_t mapunit;
	typedef uint32_t mapunit_combined;
	typedef coordinate<mapunit> mappos;

	template<typename T> class mapposhash {
		std::map<mapunit_combined,T> m;
		constexpr mapunit_combined combine(mapunit a, mapunit b) const {
			return (mapunit_combined) a << (sizeof(a) * 8) & b;
		}
		constexpr mapunit_combined combine(const mappos &x) const {
			return combine(x.a, x.b);
		}
		public:
		bool has(const mappos &x) const {
			return m.contains(combine(x));
		}
		template<typename F> void has_then(const mappos &k, F f) const {
			auto it = m.find(combine(k));
			if (it != m.end()) {
				f(it->second);
			}
		}
		template<typename F> void iterate(F f) const {
			for (auto it = m.begin(); it != m.end(); it++) {
				f(it->second);
			}
		}
		T &get (const mappos &k) {
			return m[combine(k)];
		}
	};

	std::ostream &operator<< (std::ostream &o, const rrr::magick::mappos &p) {
		o << std::to_string(p.a) << "x" << std::to_string(p.b);
		return o;
	}

	template<typename T> class minmax {
		public:
		T min;
		T max;
		minmax() : min(0), max(0) {};
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

	struct vector {
		int8_t a;
		int8_t b;
		constexpr vector () : a(0), b(0) {}
		constexpr vector (const mappos &a, const mappos &b) :
			a((ssize_t) b.a - a.a),
			b((ssize_t) b.b - a.b) {
		}
		constexpr vector (const vector &augend, const vector &addend) :
			a(augend.a + addend.a),
			b(augend.b + addend.b) {	
		}
		constexpr vector &operator+= (const vector &addend) {
			a += addend.a;
			b += addend.b;
			return *this;
		}
	};

	struct vector_normal {
		double theta;
		double mag;
		constexpr vector_normal(const vector &v) :
			theta(std::atan((double) v.b / (double) v.a)),
			mag(std::sqrt(std::pow((double) v.a, 2.0) + std::pow((double) v.b, 2.0))) {
		}
	};

	class vectorpath_signature {
		std::array<uint16_t,16> s;
		public:
		vectorpath_signature() : s() {
			s.fill(0);
		}
		vectorpath_signature(int x) : s() {
			s.fill(x);
		}
		vectorpath_signature(const rrr::types::data_const &d) {
			s.fill(0);
			printf("%u vs %lu\n", d.l, sizeof(s));
			if (d.l != sizeof(s)) {
				throw rrr::exp::soft(std::string("Byte count mismatch when initializing vectorpath signature from raw data"));
			}
			memcpy(s.data(), d.d, d.l);
		}
		bool operator== (const vectorpath_signature &test) const {
			for (size_t i = 0; i < 16; i++) {
				if (s[i] != test.s[i])
					return false;
			}
			return true;
		}
		uint16_t &operator[] (size_t pos) {
			return s[pos];
		}
		size_t cmpto(const vectorpath_signature &test) const {
			size_t acc = 0;
			for (size_t i = 0; i < 16; i++) {
				ssize_t tmp = (ssize_t) test.s[i] - (ssize_t) s[i];
				acc += (tmp < 0 ? -tmp : tmp);
			}
			return acc;
		}
		std::pair<const void*,rrr_length> data() const {
			return std::pair<const void *,rrr_length>(s.data(),(rrr_length) sizeof(s));
		}
	};

	class vectorpath_normal {
		std::vector<vector_normal> v;
		public:
		vectorpath_normal(size_t reserve) : v() {
			v.reserve(reserve);
		}
		void push(vector v) {
			this->v.emplace_back(v);
		}
		vectorpath_signature signature() const {
			vectorpath_signature s;

			double mag_max = 0.0;
			for (auto it = v.begin(); it != v.end(); it++) {
				if (it->mag > mag_max)
					mag_max = it->mag;
			}
			double theta_diff = v.front().theta;

			size_t i = 0;
			for (auto it = v.begin(); it != v.end() && i < 16; it++) {
				const int sig_theta = (int) (255.0 * ((it->theta - theta_diff) / std::numbers::pi_v<double>));
				const int sig_mag = (int) (255.0 * (it->mag / mag_max));
				//printf("%i %i (%lf %lf)\n", sig_theta, sig_mag, it->theta - theta_diff, it->mag);

				uint16_t res;
				
				*(((uint8_t*) &res) + 0) = (uint8_t) sig_mag;
				*(((uint8_t*) &res) + 1) = (int8_t) sig_theta;

				s[i++] = (uint16_t) res;
			}

			return s;
		}
	};

	class vectorpath {
		mappos prev;
		protected:
		const mappos origin;
		std::vector<vector> v;
		public:
		vectorpath(const mappos &origin, size_t size) :
			prev(origin),
			origin(origin),
			v()
		{
			v.reserve(size);
		} 
		void push(const mappos &p) {
			v.emplace_back(prev, p);
			prev = p;
		}
	};

	class vectorpath_16 : private vectorpath {
		uint8_t b;
		uint8_t popcount() {
			const uint64_t *pos = reinterpret_cast<uint64_t*>(v.data());
			uint8_t sum = 0;
			for (size_t i = 0; i < 4; i++) {
				sum += (uint8_t) std::popcount<uint64_t>(*pos);
				pos++;
			}
			return sum;
		}
		vectorpath_16 &fit() {
			std::vector<vector> v_new;
			v_new.reserve(16);

			if (v.size() > 16) {
				const size_t step = v.size() / 16;
				for (size_t i = 0; i < v.size(); i++) {
					if (i % step == 0 && v_new.size() < 16) {
						v_new.emplace_back(this->v[i]);
					}
					else {
						v_new.back() += this->v[i];
					}
				}
			}
			else {
				v_new.assign(v.begin(), v.end());
			}
	
			while (v_new.size() < 16) {
				v_new.emplace_back();
			}

			v = v_new;

			return *this;
		}
		public:
		vectorpath_16 (const vectorpath &src) : vectorpath(src) {
			if (v.size() == 0) {
				throw rrr::exp::bug(std::string("Vectorpath to ") + RRR_FUNC + " had no elements");
			}
			if (v.size() != 16) {
				fit();
			}
			b = popcount();
		}
		uint8_t bits() const {
			return b;
		}
		template<typename F> void walk(F f) const {
			mappos pos(origin);
			f(pos);
			for (auto it = v.begin(); it != v.end(); ++it) {
				pos.move_vector(it->a, it->b);
				f(pos);
			}
		}
		vectorpath_normal normalize() const {
			vectorpath_normal normal(16);
			for (auto it = v.begin(); it != v.end(); ++it) {
				normal.push(*it);
			}
			return normal;
		}
		template<typename F> void normalize(F f) const {
			f(normalize());
		}
	};

	class mappath {
		public:
		std::vector<mappos> p;
		minmax<mappos> m;
		const mappath *next;
		mappath(size_t reserve) : p(), m(), next(NULL) {
			p.reserve(reserve);
		}
		mappos operator[] (size_t i) const {
			return p[i];
		}
		void update_minmax_fast(const mappos &c) {
			m.update(c);
		}
		void update_minmax() {
			m.reset();
			for (size_t i = 0; i < p.size(); i++) {
				update_minmax_fast(p[i]);
			}
		}
		size_t count() const {
			return p.size();
		}
		void push(const mappos &e) {
			p.push_back(e);
			update_minmax_fast(e);
		}
		void push(const mappath &src) {
			p.insert(p.end(), src.p.begin(), src.p.end());
			m.update(src.m);
		}
		bool check_and_set_continues_with (const mappath &test) {
			return p.back().in_box(test.p.front(), 3) && (next = &test);
		}
		mappos start() const {
			return p.front();
		}
		void complete_circle() {
			/*
			while (p.front() != p.back()) {
				p.emplace_back((p.back())).move_towards(p.front());;
			}
			*/
		}
		template<typename F> void iterate(std::set<const mappath *> &tree, F f) const {
			if (tree.emplace(this).second != true) {
				return;
			}
			for (size_t i = 0; i < p.size(); i++) {
				f(p[i]);
			}
			if (next) {
				next->iterate(f);
			}
			tree.erase(this);
		}
		template<typename F> void iterate(F f) const {
			std::set<const mappath *> tree;
			iterate(tree, f);
		}
		vectorpath_16 to_vectorpath_16 () const {
			auto it = p.begin();
			vectorpath v(*it, p.size());
			while(++it != p.end()) {
				v.push(*it);
			}
			return vectorpath_16(v);
		}
		template<typename F> void to_vectorpath_16 (F f) const {
			f(to_vectorpath_16());
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
		template<typename F> void split(F f) {
			for (auto it_a = p.begin(); it_a != p.end(); ++it_a) {
				for (auto it_b = p.begin(); it_b != p.end(); ++it_b) {
					if (it_a == it_b)
						continue;
					it_a->check_and_set_continues_with(*it_b);
				}
			}
			for (auto it_a = p.begin(); it_a != p.end(); ++it_a) {
				mappath p_new(50);
				it_a->iterate([&](const mappos &p){
					p_new.push(p);
				});
//				p_new.complete_circle();
				f(p_new);
			}
		}
		std::vector<mappath> get() const {
			return p;
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
		T set_if_higher(mapunit a, mapunit b, T value) {
			auto &e = v[a + b * size_a];
			return (e.v = e.v < value
				? value
				: e.v
			);
		}
		T set_if_higher(const mappos &c, T value) {
			return set_if_higher(c.a, c.b, value);
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
		template<typename F> mappos get_next_neighbour(const mappos &start, F filter) const {
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
		size_t neighbours_count(const mappos &pos, size_t max, T value) const {
			size_t count = 0;
			((pos.a > 0        && pos.b > 0        && get(pos.a-1, pos.b-1) == value && ++count >= max) ||
			 (pos.a > 0        && pos.b < size_b-1 && get(pos.a-1, pos.b+1) == value && ++count >= max) ||
			 (pos.a < size_a-1 && pos.b > 0        && get(pos.a+1, pos.b-1) == value && ++count >= max) ||
			 (pos.a < size_a-1 && pos.b < size_b-1 && get(pos.a+1, pos.b+1) == value && ++count >= max) ||
			 (pos.a > 0        && get(pos.a-1, pos.b) == value && ++count >= max) ||
			 (pos.a < size_a-1 && get(pos.a+1, pos.b) == value && ++count >= max) ||
			 (pos.b > 0        && get(pos.a, pos.b-1) == value && ++count >= max) ||
			 (pos.b < size_b-1 && get(pos.a, pos.b+1) == value && ++count >= max) ||
			 0
			);
			return count;
		}
	};

	typedef map<edge_value> edges;

	void load();
	void unload();

	class pixbuf {
		short do_debug;

		Magick::Image image;

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
		) const;

		void edge_start_iterate (
				const edges &outlines,
				auto f
		) const {
			try {
				mappos pos_prev;
				do {
					// Get a starting point
					//pritnf("Start %lu %lu: %lu\n", pos.a, pos.b, outlines.get(pos));
					f(outlines.get_next_set (
							pos_prev,
							[&](const mappos &c) {
								pos_prev = c;

								const edge_value v = outlines.get(c.a, c.b);

								if (v != RRR_MAGICK_PIXEL_EDGE)
									return false;

								const size_t count = outlines.neighbours_count(c, 2, RRR_MAGICK_PIXEL_EDGE);

								return count >= 2;

/*								if (v < 1 || v > 1)
									return false;

								const size_t count = outlines.neighbours_count(c, 7, v) +
										     outlines.neighbours_count(c, 7, -v);

								return (bool) (count <= 6 && count >= 2);*/
							}
					));
				} while(1);
			}
			catch (rrr::exp::eof &e) {
			}
		}

		void edge_walk (
				const mappos &pos_start,
				const edges &m,
				auto check_neighbour,
				auto check_circle,
				auto notify_pos,
				auto notify_end
		) const {
			mappos pos = pos_start;

			notify_pos(pos);

			do {
				//pritnf("Pos %lu %lu: %lu\n", pos.a, pos.b, outlines.get(pos));
				try {
					pos =  m.get_next_neighbour(
							pos,
							[&](const mappos &c) {
								if (c == pos_start && check_circle()) {
									// Complete circle made
									throw rrr::exp::eof();
								}
								return check_neighbour(c);
							}
					);

					notify_pos(pos);
				}
				catch (rrr::exp::eof &e) {
					notify_end(pos);
					break;
				}
			} while(1);
		}

		public:
		pixbuf(const rrr::types::data_const &d);
		edges edges_clean_get() const {
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
		) const;
		Magick::Image edges_dump_image (
				const edges &m,
				mappos tl,
				mappos br
		) const;
		Magick::Blob edges_dump_blob (
				const edges &m,
				mappos tl,
				mappos br
		) const;
		Magick::Blob edges_dump_blob (
				const edges &m,
				minmax<mappos> crop
		) const;
		void edges_dump (
				const std::string &target_file_no_extension,
				const edges &m,
				mappos tl,
				mappos br
		) const;
		void edges_dump (
				const std::string &target_file_no_extension,
				const edges &m,
				minmax<mappos> crop
		) const;
		void edges_dump (
				const std::string &target_file_no_extension,
				const edges &m
		) const;
		mappath_group paths_get (
				const edges &m,
				rrr_length path_length_min
		) const;
	};
}

#endif /* RRR_MAGICK_HPP */
