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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "log.h"
#include "fixed_point.h"
#include "rrr_types.h"
#include "util/rrr_endian.h"
#include "util/gnu.h"

static const double decimal_fractions_base2[24] = {
		1.0/2.0,
		1.0/4.0,
		1.0/8.0,
		1.0/16.0,
		1.0/32.0,
		1.0/64.0,
		1.0/128.0,
		1.0/256.0,
		1.0/512.0,
		1.0/1024.0,
		1.0/2048.0,
		1.0/4096.0,
		1.0/8192.0,
		1.0/16384.0,
		1.0/32768.0,
		1.0/65536.0,
		1.0/131072.0,
		1.0/262144.0,
		1.0/524288.0,
		1.0/1048576.0,
		1.0/2097152.0,
		1.0/4194304.0,
		1.0/8388608.0,
		1.0/16777216.0
};

int rrr_fixp_ldouble_to_fixp (rrr_fixp *target, long double source) {
	long double integer = 0;
	long double fraction = modfl(source, &integer);

	if (!isfinite(fraction)) {
		return 1;
	}

	int sign = 0;
	if (integer < 0.0) {
		integer *= -1;
		fraction *= -1;
		sign = 1;
	}

	uint64_t result = 0;
	double running_sum = 0.0;
	for (int i = 0; i < RRR_FIXED_POINT_BASE2_EXPONENT; i++) {
		long double test_sum = running_sum + decimal_fractions_base2[i];
		if (test_sum == fraction || test_sum < fraction) {
			result |= (1 << (RRR_FIXED_POINT_BASE2_EXPONENT - 1)) >> i;
			running_sum = test_sum;
			if (test_sum == fraction) {
				break;
			}
		}
	}

	uint64_t integer_u = integer;
	result |= integer_u << RRR_FIXED_POINT_BASE2_EXPONENT;

	if (sign != 0) {
		result |= ((uint64_t) 1) << 63;
	}

	memcpy(target, &result, sizeof(*target));

	return 0;
}

int rrr_fixp_to_ldouble (long double *target, rrr_fixp source) {
	long double result = 0;
	uint64_t sign = ((uint64_t) source) >> 63;
	source &= ~(sign<<63);

	uint64_t whole_number = source >> RRR_FIXED_POINT_BASE2_EXPONENT;
	uint64_t decimals = source & 0xFFFFFF;

	result += whole_number;

	for (int i = 0; i < RRR_FIXED_POINT_BASE2_EXPONENT; i++) {
		unsigned int bit = (((uint64_t) 1) << (23 - i)) & decimals;
		if (bit != 0) {
			result += decimal_fractions_base2[i];
		}
	}

	if (sign != 0) {
		result *= -1;
	}

	*target = result;

	return 0;
}

int rrr_fixp_to_str_16 (char *target, ssize_t target_size, rrr_fixp source) {
	unsigned char buf[8];

	source = rrr_htobe64(source);
	memcpy(buf, &source, sizeof(buf));

	char tmp_b[32];
	int wpos = 0;
	for (int pos = 0; pos < (int) sizeof(buf); pos++) {
		unsigned char cur = buf[pos];
		unsigned char h = (cur & 0xf0) >> 4;
		unsigned char l = cur & 0x0f;
		tmp_b[wpos++] = h + (h > 9 ? 'a' - 10 : '0');
		tmp_b[wpos++] = l + (l > 9 ? 'a' - 10 : '0');
		if (pos == 4) {
			tmp_b[wpos++] = '.';
		}
	}

	tmp_b[wpos] = '\0';

	ssize_t size = strlen("16#") + strlen(tmp_b) + 1;
	if (size > target_size) {
		return 1;
	}

	sprintf(target, "16#%s", tmp_b);

	return 0;
}

int rrr_fixp_to_str_double (char *target, ssize_t target_size, rrr_fixp source) {
	char buf[512];
	long double intermediate = 0;

	if (rrr_fixp_to_ldouble(&intermediate, source) != 0) {
		return 1;
	}

	int bytes = snprintf(buf, 511, "%.10Lf", intermediate);

	if (bytes <= 0) {
		return 1;
	}

	if (bytes > 511 || bytes > target_size - 1) {
		return 1;
	}

	buf[bytes] = '\0';

	memcpy(target, buf, bytes + 1);

	return 0;
}

int rrr_fixp_to_new_str_double (char **target, rrr_fixp fixp) {
	int ret = 0;

	*target = NULL;

	char *buf = NULL;

	long double intermediate = 0;
	if (rrr_fixp_to_ldouble(&intermediate, fixp) != 0) {
		ret = 1;
		goto out;
	}

	if (rrr_asprintf(&buf, "%.10Lf", intermediate) <= 0) {
		ret = 0;
		goto out;
	}

	*target = buf;
	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
	return ret;
}

static long double __rrr_fixp_convert_char (char c) {
	if (c >= '0' && c <= '9') {
		c -= '0';
	}
	else if (c >= 'a' && c <= 'f') {
		c -= 'a';
		c += 10;
	}
	else if (c >= 'A' && c <= 'F') {
		c -= 'A';
		c += 10;
	}
	else {
		RRR_BUG("Unknown character %c while parsing decimals in rrr_str_to_fixp\n", c);
	}

	return c;
}

static int __rrr_fixp_str_preliminary_parse (
		const char *str,
		ssize_t str_length,
		const char **integer_pos,
		const char **dot,
		const char **endptr,
		int *base,
		int *is_negative
) {
	if (str_length == 0) {
		return 1;
	}

	const char *start = str;
	const char *end = start + str_length;

	ssize_t prefix_length = 0;
	ssize_t number_length = 0;

	*integer_pos = NULL;
	*dot = NULL;
	*endptr = NULL;
	*base = 10;
	*is_negative = 0;

	// PREFIX PARSING
	if (str_length > 3) {
		if (strncmp(start, "16#", 3) == 0) {
			*base = 16;
			start += 3;
			prefix_length += 3;
		}
		else if (strncmp(start, "10#", 3) == 0) {
			*base = 10;
			start += 3;
			prefix_length += 3;
		}
	}

	if (start >= end) {
		return RRR_FIXED_POINT_PARSE_INCOMPLETE;
	}

	if (*start == '-') {
		*is_negative = 1;
		start++;
		prefix_length++;
	}
	else if (*start == '+') {
		start++;
		prefix_length++;
	}

	if (start >= end) {
		return RRR_FIXED_POINT_PARSE_INCOMPLETE;
	}

	*integer_pos = start;

	// PRELIMINARY INPUT CHECK AND SEPARATOR SEARCH
	int dot_count = 0;
	for (const char *pos = start; pos < end; pos++) {
		char c = *pos;
		if (c >= '0' && c <= '9') {
			// OK
		}
		else if (*base == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
			// OK
		}
		else if (c == '.') {
			if (pos == start) {
				return RRR_FIXED_POINT_PARSE_ERR;
			}
			if (++dot_count > 1) {
				return RRR_FIXED_POINT_PARSE_ERR;
			}
			*dot = pos;
		}
		else {
			break;
		}
		number_length++;
	}

	if (number_length == 0) {
		return RRR_FIXED_POINT_PARSE_ERR;
	}

	end = str + prefix_length + number_length;
	*endptr = end;

	if (dot == NULL) {
		*dot = end;
	}

	return 0;
}

int rrr_fixp_str_to_fixp (rrr_fixp *target, const char *str, ssize_t str_length, const char **endptr) {
	*target = 0;

	int ret = 0;

	uint64_t result = 0;
	uint64_t result_integer = 0;
	uint64_t result_fraction = 0;

	const char *integer_pos = NULL;
	const char *start = str;
	const char *end = str + str_length;
	const char *dot = NULL;

	int is_negative = 0;
	int base = 10;

	long double factor = 1.0;
	long double fraction = 0.0;
	long double running_sum = 0.0;

	// PRELIMINARY INPUT CHECK AND SEPARATOR SEARCH
	if ((ret = __rrr_fixp_str_preliminary_parse(str, str_length, &integer_pos, &dot, &end, &base, &is_negative)) != 0) {
		return ret;
	}

	*endptr = end;

	if (dot == NULL) {
		goto no_decimals;
	}

	// FRACTION CONVERSION
	fraction = 0.0;
	factor = 1.0;
	for (const char *pos = dot + 1; pos < end; pos++) {
		char c = *pos;
		fraction += (__rrr_fixp_convert_char(c) / base) / factor;
		factor *= base;
	}

	if (!isfinite(fraction)) {
		goto no_decimals;
	}

	for (int i = 0; i < RRR_FIXED_POINT_BASE2_EXPONENT; i++) {
		long double position_value = decimal_fractions_base2[i];
		long double test_sum = running_sum + position_value;

		if (test_sum < fraction) {
			result_fraction |= 1 << (23 - i);
			running_sum += position_value;
		}
		else if (test_sum == fraction) {
			result_fraction |= 1 << (23 - i);
			break;
		}
	}
	result |= result_fraction;

	// INTEGER CONVERSION
	no_decimals:
	start = integer_pos;
	factor = 1.0;
	for (const char *pos = (dot != NULL ? dot - 1 : end - 1); pos >= start; pos--) {
		char c = *pos;
		result_integer += __rrr_fixp_convert_char(c) * factor;
		factor *= base;
	}

	result |= (result_integer << RRR_FIXED_POINT_BASE2_EXPONENT);
	result &= ~((uint64_t) 1 << 63);

	// NEGATION
	if (is_negative) {
		result = 0 - result;
	}

	memcpy (target, &result, sizeof(*target));

	return ret;
}

