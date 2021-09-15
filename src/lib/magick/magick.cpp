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

#include <cstddef>
#include <iostream>

#include <pthread.h>

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
			Magick::TerminateMagick();
		}
		pthread_mutex_unlock(&init_lock);
	}

	pixbuf::pixbuf(const rrr::types::data_const &d) try :
		do_debug(false),
		image(Magick::Blob(d.d, d.l)),
		pixels(image.rows(), image.columns()),
		rows(image.rows()),
		cols(image.columns()),
		size(image.rows() * image.columns()),
		channels(image.channels()),
		max_range_combined(((double) QuantumRange) * channels)
	{
		image.modifyImage();

		//pritnf("Size: %lu x %lu (%lu), Channels: %lu\n", rows, cols, size, channels);

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
	//			//pritnf("%lu\n", (long unsigned) pixels.back().v);
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
//				//pritnf("Begin at %" PRIrrrl " x %" PRIrrrl " value %llu/%li\n", a, b, (long long unsigned) p1, diff_threshold_pos);
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
//						//pritnf("Direction swap at %" PRIrrrl " x %" PRIrrrl "\n", x_search, y);
						break;
					}
					if (diff_accumulated * direction > diff_threshold_pos) {
//						//pritnf("- Edge at %" PRIrrrl "->%" PRIrrrl " x %" PRIrrrl " diff %li\n", b, b_search, a, diff_accumulated);
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

	edges pixbuf::edges_get (
			float threshold,
			rrr_length edge_length_max,
			size_t result_max
	) {
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

		if (result.count() >= result_max) {
			throw rrr::exp::incomplete();
		}

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

		if (result.count() >= result_max) {
			throw rrr::exp::incomplete();
		}

		std::cout << "Found " << result.count() << " edges time " << (rrr_time_get_64() - time_start) << std::endl;

		return result;
	}

	void pixbuf::edges_dump (
			const std::string &target_file_no_extension,
			const edges &m,
			mappos tl,
			mappos br
	) {
		static const std::string extension = "png";
		Magick::Image tmp(image);
		tmp.magick(extension);
		tmp.type(Magick::TrueColorAlphaType);

		for (size_t x = 0; x < cols; x++) {
			for (size_t y = 0; y < rows; y++) {
				switch (m.get(y, x)) {
					case 0:
						break;
					case 1:
						tmp.pixelColor(x, y, Magick::ColorRGB(0.7, 0.7, 0.0, 1.0));
						break;
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

		printf("%u %u\n", tl.a, tl.b);
		printf("%u %u\n", br.a, br.b);

		printf("Crop %u %u %u %u\n", br.b-tl.b, br.a-tl.a, tl.b, tl.a);

		tmp.syncPixels();
		tmp.crop(Magick::Geometry(br.b-tl.b, br.a-tl.a, tl.b, tl.a));
		tmp.write(target_file_no_extension + "." + extension);
	}

	void pixbuf::edges_dump (
			const std::string &target_file_no_extension,
			const edges &m,
			minmax<mappos> crop
	) {
		edges_dump(target_file_no_extension, m, crop.min, crop.max);
	}

	void pixbuf::edges_dump (
			const std::string &target_file_no_extension,
			const edges &m
	) {
		edges_dump(target_file_no_extension, m, mappos(0, 0), mappos(rows, cols));
	}

	mappath_group pixbuf::paths_get (
			const edges &m,
			rrr_length path_length_min,
			std::function<void(const edges &outlines)> debug
	) {
		uint64_t time_start = rrr_time_get_64();
		edges outlines = m;
		mappath_group paths;
		const size_t reserve_size = 100;

		try {
			mappos pos;
			edge_start_iterate(outlines, [&](const mappos &pos) {
				// Walk around edge
				mappath path_new(reserve_size);

				const edge_value pos_value = outlines.get(pos);

				path_new.push(pos);

				edge_walk (
						pos,
						m,
						[&](edgemask &m, const mappos &pos) {
							// Create mask based on blank pixels
							outlines.neighbours_count(m, pos, 8, 0);
							m.widen();
						},
						[&](const mappos &check_pos, const edgemask &mask) {
							if (outlines.get(check_pos) != 1)
								return false;

							// XXX : We only follow positive edges, don't know if thats a good or bad thing

							const size_t count       = outlines.neighbours_count(check_pos, 7, pos_value);
							const size_t count_blank = outlines.neighbours_count(mask, check_pos, 8, 0);
							const size_t count_used  = outlines.neighbours_count(check_pos, 3, 2);

							return (count <= 6 && count_blank >= 2 && count_blank <= 6 && count_used <= 2);
						},
						[&]() {
							// Accept circle path?
							return path_new.count() >= path_length_min;
						},
						[&](const mappos &pos) {
							// Push found point
							outlines.set(pos, 2);
							path_new.push(pos);
						},
						[&](const mappos &pos_end) {
							if (path_new.count() >= path_length_min) {
								// Ban end pixel
								outlines.set(pos_end, 3);
								paths.push(path_new);
							}
							else {
								// Ban all found pixels
								for (size_t i = 0; i < path_new.count(); i++) {
									outlines.set(path_new[i], 3);
								}
							}
							path_new = mappath(reserve_size);
						}
				);
			});
		}
		catch (rrr::exp::eof &e) {
		}

		std::cout << "Found " << paths.count() << " outlines time " << (rrr_time_get_64() - time_start) << std::endl;

		return paths;
	}
}
