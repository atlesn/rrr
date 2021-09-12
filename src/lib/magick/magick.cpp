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

#include <iostream>
#include <unistd.h>

#include "magick.hpp"
#include "../exception.hpp"
#include "../util/macro_utils.hpp"

extern "C" {
#include <pthread.h>
#include "../util/rrr_time.h"
}

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
int usercount = 0;

namespace rrr::magick {
	void load() {
		pthread_mutex_lock(&init_lock);
		if (++usercount == 0) {
			Magick::InitializeMagick(".");
		}
		pthread_mutex_unlock(&init_lock);
	}

	void unload() {
		pthread_mutex_lock(&init_lock);
		if (--usercount == 0) {
			const char *ptr = NULL;
			Magick::TerminateMagick();
		}
		pthread_mutex_unlock(&init_lock);
	}

	pixbuf::pixbuf(const rrr::types::data_const &d) try :
		image(Magick::Blob(d.d, d.l)),
		do_debug(false),
		rows(image.rows()),
		cols(image.columns()),
		size(image.rows() * image.columns()),
		channels(image.channels()),
		max_range_combined(((double) QuantumRange) * channels),
		pixels(image.rows(), image.columns())
	{
		image.modifyImage();

		printf("Size: %lu x %lu (%lu), Channels: %lu\n", rows, cols, size, channels);

		const Magick::Quantum *pixel_cache = image.getConstPixels(0, 0, cols, rows);

		const MagickCore::Quantum *qpos = pixel_cache;
		for (size_t a = 0; a < rows; a++) {
			for (size_t b = 0; b < cols; b++) {
				double sum = 0;
				for (size_t j = 0; j < channels; j++) {
					sum += *(qpos+j);
				}
				sum = sum / max_range_combined;
				pixels.set(a, b, (uint16_t) (sum * pixel_max));
	//			printf("%lu\n", (long unsigned) pixels.back().v);
				qpos += channels;
			}
		}
	}
	catch (std::exception &e) {
		throw rrr::exp::soft(std::string("Failed to create image from buffer in " + RRR_FUNC + ": ") + e.what());
	}

	template <typename A, typename B> void pixbuf::edges_get (
			float threshold,
			A getter,
			B setter,
			rrr_length a_max,
			rrr_length b_max
	) {
		const rrr_slength diff_threshold_pos = (rrr_slength) (threshold * max_range_combined);
		const rrr_length edge_length_max = (b_max / 10 > 0 ? b_max / 10 : 10);

		for (rrr_length a = 0; a < a_max; a++) {
			for (rrr_length b = 0; b < b_max; b++) {
				rrr_slength diff_accumulated = 0;
				rrr_slength direction = 0;
				const uint16_t p1 = getter(a, b);
//				printf("Begin at %" PRIrrrl " x %" PRIrrrl " value %llu/%li\n", x, y, (long long unsigned) p1.v, diff_threshold_pos);
				for (rrr_length b_search = b + 1; b_search < b_search + edge_length_max && b_search < b_max; b_search++) {
					const uint16_t p2 = getter(a, b_search);
					rrr_slength diff = (rrr_slength) p1 - (rrr_slength) p2;
					if (diff == 0) {
						break;
					}
					diff_accumulated += diff;
					rrr_slength direction_test = (diff_accumulated < 0 ? -1 : 1);
					if (direction == 0) {
						direction = direction_test;
					}
					else if (direction != direction_test) {
//						printf("Direction swap at %" PRIrrrl " x %" PRIrrrl "\n", x_search, y);
						break;
					}
					if (diff_accumulated * direction > diff_threshold_pos) {
//						printf("- Edge at %" PRIrrrl "->%" PRIrrrl " x %" PRIrrrl " diff %li\n", b, b_search, a, diff_accumulated);
						setter(a, b);
//						b = b_search;
						break;
					}
				}
			}
		}
	}

	edges pixbuf::edges_get(float threshold) {
		uint64_t time_start = rrr_time_get_64();

		edges result(rows, cols);

		// Get horizontal
		edges_get (
			threshold,
			[&](rrr_length a, rrr_length b) {
				return pixels.get(a, b);
			},
			[&](rrr_length a, rrr_length b) {
				return result.set(a, b);
			},
			rows,
			cols
		);

		// Get vertical
		edges_get (
			threshold,
			[&](rrr_length a, rrr_length b) {
				return pixels.get(b, a);
			},
			[&](rrr_length a, rrr_length b) {
				return result.set(b, a);
			},
			cols,
			rows
		);

		std::cout << "Found " << result.count() << " edges time " << (rrr_time_get_64() - time_start) << std::endl;

		return result;
	}

	void pixbuf::edges_dump (const std::string &target_file_no_extension, const edges &m) {
		Magick::Image tmp(image);
		tmp.magick("png");
		tmp.type(Magick::TrueColorAlphaType);

		for (size_t x = 0; x < cols; x++) {
			for (size_t y = 0; y < rows; y++) {
				switch (m.get(y, x)) {
					case 0:
						break;
					case 1:
						tmp.pixelColor(x, y, Magick::ColorRGB(1.0, 1.0, 0, 1.0));
						break;
					case 2:
						tmp.pixelColor(x, y, Magick::ColorRGB(1.0, 0.0, 0, 1.0));
						break;
					default:
						break;
				};
			}
		}

		tmp.syncPixels();
		tmp.write(target_file_no_extension);
	}

	edges pixbuf::outlines_get (const edges &m) {
		edges outlines = m;
		coordinate<size_t> pos;
		try {
			do {
				std::vector<coordinate<size_t>> path;
				path.reserve(100);

				// Get a starting point
				printf("Start %lu %lu: %lu\n", pos.a, pos.b, outlines.get(pos));
				pos = outlines.get_next_set (
						pos,
						[&](const coordinate<size_t> &c) {
							if (outlines.get(c.a, c.b) != 1)
								return false;
							const size_t count = outlines.neighbours_count(c, 7);
							return (count <= 6 && count >= 2);
						}
				);
				const int retry_max = 2;
				int retries = 0;
				do {
					// Walk around edge
					outlines.set(pos, 2);
//					printf("Pos %lu %lu: %lu\n", pos.a, pos.b, outlines.get(pos));
					uint16_t constraint_mask = 0;
					try {
						pos = m.get_next_neighbour (
								constraint_mask,
								pos,
								[&](const coordinate<size_t> &c) {
									if (outlines.get(c.a, c.b) != 1)
										return false;
									const size_t count = outlines.neighbours_count(c, 7);
//									printf("Count %lu %lu: %lu\n", c.a, c.b, count);
									return (count <= 6 && count >= 2);
								}
						);
						path.push_back(pos);
						if (constraint_mask & (outlines.BL|outlines.BB|outlines.BR)) {
							printf("Constrain top\n");
							constraint_mask = outlines.TL|outlines.TT|outlines.TR;
						}
						else if (constraint_mask & (outlines.TL|outlines.TT|outlines.TR)) {
							printf("Constrain Bottom\n");
							constraint_mask = outlines.BL|outlines.BB|outlines.BR;
						}
						else if (constraint_mask & (outlines.TL|outlines.LL|outlines.BL)) {
							printf("Constrain rigt\n");
							constraint_mask = outlines.TR|outlines.RR|outlines.BR;
						}
						else if (constraint_mask & (outlines.TR|outlines.RR|outlines.BR)) {
							printf("Constrain left\n");
							constraint_mask = outlines.TL|outlines.LL|outlines.BL;
						}
					}
					catch (rrr::exp::eof &e) {
						if (path.size() < retry_max || retries == retry_max) {
							printf("- Stop %lu %lu\n", pos.a, pos.b);
							break;
						}
//						printf("- Retry\n");
						pos = path[path.size() - ++retries];
					}
				} while(1);
			} while(1);
		}
		catch (rrr::exp::eof &e) {
			printf("EOF %lu %lu\n", pos.a, pos.b);
		}
		return outlines;
	}
}
