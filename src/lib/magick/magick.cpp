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

#include <pthread.h>

#include "magick.hpp"
#include "../exception.hpp"
#include "../util/macro_utils.hpp"

extern "C" {
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
		size(rows*cols),
		channels(image.channels()),
		max_range_combined(((double) QuantumRange) * channels)
	{
		image.modifyImage();
		pixels.reserve(size);

		printf("Size: %lu, Channels: %lu\n", size, channels);

		const Magick::Quantum *pixel_cache = image.getConstPixels(0, 0, cols, rows);

		const MagickCore::Quantum *qpos = pixel_cache;
		for (size_t i = 0; i < size; i++) {
			double sum = 0;
			for (size_t j = 0; j < channels; j++) {
				sum += *(qpos+j);
			}
			sum = sum / max_range_combined;
			pixels.emplace_back(sum * pixel_max);
//			printf("%lu\n", (long unsigned) pixels.back().v);
			qpos += channels;
		}
	}
	catch (std::exception &e) {
		throw rrr::exp::soft(std::string("Failed to create image from buffer in " + RRR_FUNC + ": ") + e.what());
	}

	std::vector<coordinate<rrr_length>> pixbuf::horizontal_edges_get(float threshold) {
		uint64_t time_start = rrr_time_get_64();

		std::vector<coordinate<rrr_length>> result;

		result.reserve(rows * 2);

		const rrr_slength diff_threshold_pos = (rrr_slength) (threshold * max_range_combined);
		const rrr_length edge_length_max = (cols / 10 > 0 ? cols / 10 : 10);

		uint64_t comparisons = 0;

		for (rrr_length y = 0; y < rows; y++) {
			const size_t rowpos = cols * y;
			for (rrr_length x = 0; x < cols; x++) {
				rrr_slength diff_accumulated = 0;
				rrr_slength direction = 0;
				const pixel<uint16_t> &p1 = pixels[rowpos + x];
//				printf("Begin at %" PRIrrrl " x %" PRIrrrl " value %llu/%li\n", x, y, (long long unsigned) p1.v, diff_threshold_pos);
				for (rrr_length x_search = x + 1; x_search < x_search + edge_length_max && x_search < cols; x_search++) {
					comparisons++;
					const pixel<uint16_t> &p2 = pixels[rowpos + x_search];
					rrr_slength diff = (rrr_slength) p1.v - (rrr_slength) p2.v;
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
//						printf("- Edge at %" PRIrrrl "->%" PRIrrrl " x %" PRIrrrl " diff %li\n", x, x_search, y, diff_accumulated);
						result.emplace_back((x + x_search) / 2, y);
						x = x_search;
						break;
					}
				}
			}
		}

		std::cout << "Found " << result.size() << " edges compared " << comparisons <<  " factor " << ((float) comparisons / (float) size) << " time " << (rrr_time_get_64() - time_start) << std::endl;

		return result;
	}
}
