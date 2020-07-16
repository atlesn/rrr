/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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

// Specify this define in the C-file to be benchmarked
// #define RRR_BENCHMARK_ENABLE

#ifndef RRR_BENCHMARK_H
#define RRR_BENCHMARK_H

#include <stdint.h>

#include "vl_time.h"
#include "log.h"
#include "macro_utils.h"

#define RRR_BENCHMARK_TOTAL(name)	\
		RRR_PASTE(_benchmark_total_,name)

#define RRR_BENCHMARK_TMP(name)	\
		RRR_PASTE(_benchmark_total_tmp_,name)

#ifdef RRR_BENCHMARK_ENABLE

#define RRR_BENCHMARK_INIT(name)						\
	do {uint64_t RRR_PASTE(_benchmark_total_,name) = 0;	\
	uint64_t RRR_PASTE(_benchmark_total_tmp_,name)

#define RRR_BENCHMARK_DUMP(name)																		\
		RRR_MSG_1("BM %s total ms %" PRIu64 "\n", RRR_QUOTE(name), RRR_BENCHMARK_TOTAL(name) / 1000);	\
	} while (0)

#define RRR_BENCHMARK_IN(name)													\
	do {RRR_BENCHMARK_TMP(name) = rrr_time_get_64()

#define RRR_BENCHMARK_OUT(name)													\
	RRR_BENCHMARK_TOTAL(name) += rrr_time_get_64() - RRR_BENCHMARK_TMP(name); 	\
	} while (0)

#else
#	define RRR_BENCHMARK_INIT(name)	do { do { } while(0)
#	define RRR_BENCHMARK_DUMP(name)	} while (0)
#	define RRR_BENCHMARK_IN(name)	do { do { } while(0)
#	define RRR_BENCHMARK_OUT(name)	} while (0)
#endif /* RRR_BENCMARK_ENABLE */

#endif /* RRR_BENCHMARK_H */
