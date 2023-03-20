/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#pragma once

#include "E.hxx"

extern "C" {
#include "../rrr_strerror.h"
#include <inttypes.h>
#include <sys/time.h>
};

namespace RRR::util {
	static inline int64_t time_get_i64(void) {
		struct timeval tv;

		if (gettimeofday(&tv, NULL) != 0) {
			throw E(std::string("Error while getting time in ") + __func__ + ", cannot recover from this: " + rrr_strerror(errno));
		}

		int64_t tv_sec = tv.tv_sec;
		int64_t tv_factor = 1000000;
		int64_t tv_usec = tv.tv_usec;

		return (tv_sec * tv_factor) + (tv_usec);
	}
}; // namespace RRR
