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
				pixels.set(a, b, (pixel_value) (sum * pixel_max));
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
			rrr_length edge_length_max,
			A getter,
			B setter,
			rrr_length a_max,
			rrr_length b_max
	) {
		const rrr_slength diff_threshold_pos = (rrr_slength) (threshold * max_range_combined);

		for (rrr_length a = 0; a < a_max; a++) {
			for (rrr_length b = 0; b < b_max; b++) {
				rrr_slength diff_accumulated = 0;
				rrr_slength direction = 0;
				const pixel_value p1 = getter(a, b);
//				printf("Begin at %" PRIrrrl " x %" PRIrrrl " value %llu/%li\n", a, b, (long long unsigned) p1, diff_threshold_pos);
				for (rrr_length b_search = b + 1; b_search < b + edge_length_max && b_search < b_max; b_search++) {
					const pixel_value p2 = getter(a, b_search);
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
						if (diff_accumulated > 0) {
//							setter(a, b-1, -1);
							setter(a, b_search, 1);
//							setter(a, b_search, 1);
						}
						else {
//							setter(a, b-1, 1);
//							setter(a, b, 1);
							setter(a, b, 1);
						}
//						b = b_search;
						break;
					}
				}
			}
		}
	}

	edges pixbuf::edges_get(float threshold, rrr_length edge_length_max) {
		uint64_t time_start = rrr_time_get_64();

		edges result(rows, cols);

		// Get horizontal
		edges_get (
			threshold,
			edge_length_max,
			[&](rrr_length a, rrr_length b) {
				return pixels.get(a, b);
			},
			[&](rrr_length a, rrr_length b, int8_t v) {
				return result.set(a, b, v);
			},
			rows,
			cols
		);

		// Get vertical
		edges_get (
			threshold,
			edge_length_max,
			[&](rrr_length a, rrr_length b) {
				return pixels.get(b, a);
			},
			[&](rrr_length a, rrr_length b, int8_t v) {
				return result.set(b, a, v);
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
						tmp.pixelColor(x, y, Magick::ColorRGB(0.7, 0.7, 0.0, 1.0));
					case -1:
						tmp.pixelColor(x, y, Magick::ColorRGB(1.0, 1.0, 0.0, 1.0));
						break;
					case 2:
					case -2:
						tmp.pixelColor(x, y, Magick::ColorRGB(1.0, 0.0, 0.0, 1.0));
						break;
					case 3:
					case -3:
						tmp.pixelColor(x, y, Magick::ColorRGB(0.0, 0.0, 1.0, 1.0));
						break;
					default:
						break;
				};
			}
		}

		tmp.syncPixels();
		tmp.write(target_file_no_extension + ".png");
	}

	edges pixbuf::outlines_get (const edges &m) {
		uint64_t time_start = rrr_time_get_64();
		edges outlines = m;
		mappos pos_prev;
		std::vector<std::vector<mappos>> paths;
		try {
			mappos pos;
			edge_value pos_value = 0;
			do {
				// Get a starting point
				//printf("Start %lu %lu: %lu\n", pos.a, pos.b, outlines.get(pos));
				pos = pos_prev = outlines.get_next_set (
						pos_prev,
						[&](const mappos &c) {
							const edge_value v = outlines.get(c.a, c.b);

							if (v < 1 || v > 1)
								return false;

							const size_t count = outlines.neighbours_count(c, 7, v) +
							                     outlines.neighbours_count(c, 7, -v);

							return (count <= 6 && count >= 2);
						}
				);

				// Walk around edge
				std::vector<mappos> path;
				path.reserve(100);

				pos_value = outlines.get(pos);
				outlines.set(pos, 2);

				path.push_back(pos);

				int retry_max = 8;
				do {
					const mappos pos_start = pos;
					//printf("Pos %lu %lu: %lu\n", pos.a, pos.b, outlines.get(pos));
					edgemask mask_blank;
					try {
						outlines.neighbours_count(mask_blank, pos, 8, 0);
						mask_blank.widen();
//						mask_blank.dump();

						try {
							pos = m.get_next_neighbour (
									pos,
									[&](const mappos &c) {
										if (path.size() > 10 && c == path[0]) {
											// Origin reached
											return true;
										}

										if (outlines.get(c.a, c.b) != 1)
											return false;
										edgemask mask_blank_tmp = mask_blank;
										const size_t count = outlines.neighbours_count(c, 7, pos_value);
										const size_t count_neg = outlines.neighbours_count(c, 7, -pos_value);
										const size_t count_blank = outlines.neighbours_count(mask_blank_tmp, c, 8, 0);
										const size_t count_used = outlines.neighbours_count(c, 3, 2);
										//printf("- Count %lu %lu: %lu used %lu blank %lu\n", c.a, c.b, count, count_used, count_blank);
										return (count <= 6 && count_blank >= 2 && count_blank <= 6 && count_used <= 2);
									}
							);
						}
						catch (rrr::exp::eof &e) {
							//printf("Ban %lu %lu\n", pos.a, pos.b);
							outlines.set(pos, 3); /* Ban pixel */
							if (retry_max-- && path.size() >= 2) {
								path.pop_back();
								pos = path.back();
								//printf("-> Retry %lu %lu\n", pos.a, pos.b);
								continue;
							}
							throw e;
						}

						outlines.set(pos, 2);
						path.push_back(pos);

						if (path.size() > 10 && pos == path[0]) {
							//printf("- Stop, circle made %lu %lu\n", pos.a, pos.b);
							throw rrr::exp::eof();
						}
					}
					catch (rrr::exp::eof &e) {
						if (path.size() < 10) {
							//printf("Ban short path %lu\n", path.size());
							for (int i = 0; i < path.size(); i++) {
								outlines.set(path[i], 3); /* Ban pixel */
							}
						}
						else {
							//printf("- Stop %lu %lu\n", pos.a, pos.b);
							outlines.set(pos, 3); /* Ban pixel */
							paths.push_back(path);
						}
						break;
					}
				} while(1);
			} while(1);
		}
		catch (rrr::exp::eof &e) {
			size_t size_total = 0;
			for (size_t i = 0; i < paths.size(); i++) {
				size_total += paths[i].size() * sizeof(mappos);
			}
			//printf("EOF %lu paths found total size %lu\n", paths.size(), size_total);
		}
		std::cout << "Found " << paths.size() << " outlines time " << (rrr_time_get_64() - time_start) << std::endl;
		return outlines;
	}
}
