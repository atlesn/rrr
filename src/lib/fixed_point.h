/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_FIXED_POINT_H
#define RRR_FIXED_POINT_H

#define RRR_FIXED_POINT_BASE2_EXPONENT 24
#define RRR_FIXED_POINT_NUMBER_MAX 0x7FFFFFFFFF

#define RRR_FIXED_POINT_PARSE_OK			0
#define RRR_FIXED_POINT_PARSE_ERR			1
#define RRR_FIXED_POINT_PARSE_SOFT_ERR		2
#define RRR_FIXED_POINT_PARSE_INCOMPLETE	3

#include <stdint.h>

#include "rrr_types.h"

typedef int64_t rrr_fixp;

int rrr_fixp_ldouble_to_fixp (rrr_fixp *target, long double source);
int rrr_fixp_to_ldouble (long double *target, rrr_fixp source);
int rrr_fixp_to_str (char *target, ssize_t target_size, rrr_fixp source);
int rrr_fixp_str_get_length (rrr_length *result, const char *str, rrr_biglength str_length);
int rrr_fixp_str_to_fixp (rrr_fixp *target, const char *str, ssize_t str_length, const char **endptr);

#endif /* RRR_FIXED_POINT_H */
