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
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "fixed_point.h"

static const double decimal_fractions[24] = {
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

int rrr_ldouble_to_fixp (rrr_fixp *target, long double source) {
	long double integer = 0;
	long double fraction = modfl(source, &integer);

	int sign = 0;
	if (integer < 0.0) {
		integer *= -1;
		fraction *= -1;
		sign = 1;
	}

	uint64_t result = 0;
	double running_sum = 0.0;
	for (int i = 0; i < RRR_FIXED_POINT_BASE2_EXPONENT; i++) {
		double test_sum = running_sum + decimal_fractions[i];
		if (test_sum == fraction) {
			result |= 1 >> i;
			running_sum = test_sum;
			break;
		}
		else if (test_sum < fraction) {
			result |= 1 >> i;
			running_sum = test_sum;
		}
	}

	result >>= 64 - RRR_FIXED_POINT_BASE2_EXPONENT;

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
			result += decimal_fractions[i];
		}
	}

	if (sign != 0) {
		result *= -1;
	}

	*target = result;

	return 0;
}

int rrr_fixp_to_str (char *target, ssize_t target_size, rrr_fixp source) {
	char buf[512];
	long double intermediate = 0;

	if (rrr_fixp_to_ldouble(&intermediate, source) != 0) {
		return 1;
	}

	int bytes = snprintf(buf, 511, "%.10Lf", intermediate);

	if (bytes > 511 || bytes > target_size - 1) {
		return 1;
	}

	memcpy(target, buf, strlen(buf));

	return 0;
}

int rrr_str_to_fixp (rrr_fixp *target, const char *str) {
	ssize_t input_length = strlen(str);

	char buf[input_length + 1];
	memcpy(buf, str, input_length + 1);

	uint64_t result = 0;

	if (input_length == 0) {
		return 1;
	}

	char *start = buf;
	char *end = buf + input_length;
	char *dot = NULL;
	char *endptr = NULL;

	int is_negative = 0;
	if (*start == '-') {
		is_negative = 1;
		start++;
		input_length--;
	}
	else if (*start == '+') {
		start++;
		input_length--;
	}

	int decimal_start_zeros = 0;
	int dot_count = 0;
	for (int i = 0; i < input_length; i++) {
		char c = *(start + i);
		if (c >= '0' && c <= '9') {
			// OK
		}
		else if (c == '.') {
			if (i == 0) {
				return 1;
			}
			if (++dot_count > 1) {
				return 1;
			}
			dot = start + i;

			for (i = i + 1; i < input_length; i++) {
				char c = *(start + i);
				if (c == '0') {
					decimal_start_zeros++;
				}
				else {
					i--;
					break;
				}
			}
		}
		else {
			return 1;
		}
	}

	result = strtoull(start, &endptr, 10);

//	printf ("%" PRIu64 " < %" PRIu64 "\n", result, RRR_FIXED_POINT_NUMBER_MAX);

	if (result > RRR_FIXED_POINT_NUMBER_MAX) {
		return 1;
	}

	result <<= RRR_FIXED_POINT_BASE2_EXPONENT;

	if (dot == NULL) {
		if (endptr != end) {
			return 1;
		}
	}
	else {
		if (endptr != dot) {
			return 1;
		}

		// Any better precision will be lost as we can't store it
		if (decimal_start_zeros < 9) {
			char *before_dot_digit = dot - 1;
			*before_dot_digit = '0';

			double decimals = strtod(before_dot_digit, &endptr);
			if (endptr != end) {
				return 1;
			}

//			printf ("Input decimals: %s / %f\n", before_dot_digit, decimals);

			uint64_t decimals_out = 0;
			double running_sum = 0.0;
			for (int i = 0; i < RRR_FIXED_POINT_BASE2_EXPONENT; i++) {
				double position_value = decimal_fractions[i];
				double test_sum = running_sum + position_value;

//				printf ("test sum %lf fraction %lf ", test_sum, position_value);

				if (test_sum < decimals) {
//					printf ("lt\n");
					decimals_out |= 1 << (23 - i);
					running_sum += position_value;
				}
				else if (test_sum == decimals) {
//					printf ("eq\n");
					decimals_out |= 1 << (23 - i);
					running_sum += position_value;
					break;
				}
				else {
//					printf ("gt\n");
				}
			}
//			printf ("decimals out: %" PRIu64 "\n", decimals_out);
//			printf ("result out: %" PRIu64 "\n", result);
			result |= decimals_out;
//			printf ("result out: %" PRIu64 "\n", result);

		}
	}

	if (is_negative) {
		result = 0 - result;
	}

	memcpy (target, &result, sizeof(*target));

	return 0;
}

