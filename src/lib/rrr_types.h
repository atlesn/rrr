/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_TYPES_H
#define RRR_TYPES_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "log.h"
#include "util/macro_utils.h"

/*
 * These types are used to detect underflow and overflow situations. The normal
 * storage length to be used for most cases is rrr_length.
 *
 * The rrr_length type is always smaller than rrr_slength, making it possible
 * to always add two large rrr_length values together and check the result.
 *
 * The 'length' names do not indicate null-terminated strings. When these values
 * are used, it is necessary to fully understand what they actually inidicates.
 *
 * Variable names should however differentiate between 'length' and 'size', where
 * the first indicates a count of non-null characters in a string and the latter
 * the total allocated size, possibly including a null terminating character.
 *
 * When navigating in strings and doing pointer arithmetics, rrr_length should
 * be used to store length.
 *
 * - Value of rrr_length need not to be checked if it arises from data already
 *   allocated (like when counting characters in a 0-terminated string)
 *
 * - Value of rrr_length must be checked when doing other arithmetic
 *   operations by first doing calculations using rrr_slength and helper macros
 *
 * - If overflow is likely, do not use the helper functions which causes
 *   abort(), implement a custom check instead (possibly in addition to using
 *   the macros if you are in the mood for a bugtrap)
 *
 * - When storing results from functions returning size_t, use rrr_biglength. At
 *   compile time, it is assured that it can always hold a size_t.
 *
 * - When subtracting one pointer from another, always store result in rrr_biglength
 *   and then check result against RRR_LENGTH_MAX possibly using RRR_TYPES_BUG_IF_LENGTH_EXCEEDED
 *
 * - rrr_biglength should not be passed to functions accepting size_t unless checking
 *   first that it's value does not exceed RRR_LENGTH_MAX.
 *
 * DO NOT do operations like 'rrr_slength a = b + c' where b and c are rrr_length
 * values, this can cause undetected overflow. Instead, do for instance
 * 'rrr_slength a = b; a += c;' and then check the result.
 */

typedef uint32_t rrr_length;
typedef uint64_t rrr_biglength;
typedef int64_t rrr_slength;

#define PRIrrrl PRIu32
#define PRIrrrbl PRIu64
#define PRIrrrsl PRIi64

#define RRR_SLENGTH_MAX INT64_MAX
#define RRR_LENGTH_MAX 0xffffffff // 8 f's

static inline void __rrr_types_asserts (void) {
	RRR_ASSERT(sizeof(size_t) <= sizeof(rrr_biglength),unsafe_platform_size_t_is_too_big);
	RRR_ASSERT(sizeof(size_t) >= sizeof(rrr_length),unsafe_platform_size_t_is_too_small);
}

static inline void __rrr_types_checked_length_counter_add (rrr_slength *target, rrr_biglength operand) {
	*target += (rrr_slength) operand;
	if (*target < 0 || *target > RRR_LENGTH_MAX || operand > RRR_LENGTH_MAX) {
		RRR_BUG("BUG: Overflow in __rrr_types_checked_tmp_add");
	}
}

static inline void __rrr_types_checked_length_counter_sub (rrr_slength *target, rrr_biglength operand) {
	*target -= (rrr_slength) operand;
	if (*target < 0 || operand > RRR_LENGTH_MAX) {
		RRR_BUG("BUG: Underflow in __rrr_types_checked_tmp_add");
	}
}

static inline void rrr_length_sub_bug (rrr_length *a, rrr_length b) {
	rrr_length r = *a - b;
	if (r > *a) {
		RRR_BUG("Bug: Underflow in rrr_types_length_sub_bug input was %" PRIrrrl " and %" PRIrrrl "\n", *a, b);
	}
	*a = r;
}

static inline int rrr_length_add_err (rrr_length *a, rrr_length b) {
	rrr_length r = *a + b;
	if (r < *a) {
		RRR_MSG_0("Error: Overflow in rrr_length_add_err, input was %" PRIrrrl " and %" PRIrrrl "\n", *a, b);
		return 1;
	}
	*a = r;
	return 0;
}

static inline int rrr_length_inc_err (rrr_length *a) {
	if (++(*a) == 0) {
		RRR_MSG_0("Error: Overflow in rrr_length_inc_err\n");
		return 1;
	}
	return 0;
}

static inline void rrr_length_inc_bug (rrr_length *a) {
	if (++(*a) == 0) {
		RRR_BUG("Bug: Overflow in rrr_length_inc_bug\n");
	}
}

static inline rrr_length rrr_length_inc_bug_new_value (rrr_length *a) {
	rrr_length_inc_bug(a);
	return *a;
}

static inline rrr_length rrr_length_inc_bug_old_value (rrr_length *a) {
	rrr_length_inc_bug(a);
	return *a - 1;
}

#define RRR_TYPES_CHECKED_LENGTH_COUNTER_INIT(name)				\
	rrr_slength name = 0

#define RRR_TYPES_CHECKED_LENGTH_COUNTER_ADD(name, op_u64)		\
	__rrr_types_checked_length_counter_add(&(name), op_u64)

#define RRR_TYPES_CHECKED_LENGTH_COUNTER_SUB(name, op_u64)		\
	__rrr_types_checked_length_counter_sub(&(name), op_u64)

#define RRR_TYPES_BUG_IF_LENGTH_EXCEEDED(value,msg_str)											\
	do {if (value > RRR_LENGTH_MAX) {															\
		RRR_BUG("BUG: length of " RRR_QUOTE(value) " exceeded maximum value in " msg_str "\n");	\
	}} while(0)

/*
 * Types for array framework
 */

typedef uint8_t rrr_type;
typedef uint8_t rrr_type_flags;
typedef uint64_t rrr_type_le;
typedef uint64_t rrr_type_be;
typedef uint64_t rrr_type_h;
typedef uint64_t rrr_type_istr;
typedef uint64_t rrr_type_ustr;

#endif /* RRR_TYPES_H */
