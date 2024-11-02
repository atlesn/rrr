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

#include <EXTERN.h>
#include <perl.h>
#include <string.h>
#include <inttypes.h>

#include "../log.h"
#include "../allocator.h"
#include "../type.h"
#include "../util/linked_list.h"
#include "../util/macro_utils.h"
#include "../util/utf8.h"
#include "../fixed_point.h"

#include "perl5.h"
#include "perl5_types.h"

#define ELEMENT_SIZE_SET                                                                         \
    ssize_t element_size = value->total_stored_length / value->element_count;                    \
    do {if (element_size * value->element_count != value->total_stored_length) {                 \
        RRR_BUG("BUG: Array element size discrepancy in __rrr_perl5_type_*_to_sv\n");            \
    }} while(0)

#define ELEMENT_LOOP_BEGIN                                                                       \
    do {for (int i = 0; i < value->element_count; i++) {                                         \
        void *pos = value->data + (element_size * i)

#define ELEMENT_CALL_CALLBACK                                                                    \
    do {ret = callback(ctx, sv, i, value->definition, callback_arg);                             \
        SvREFCNT_dec(sv);                                                                        \
        if (ret != 0) {                                                                          \
  RRR_MSG_0("Error from callback in __rrr_perl5_type_*_to_sv\n");                                \
  ret = 1;                                                                                       \
  goto out;                                                                                      \
    }} while(0)

#define ELEMENT_LOOP_END																\
	}} while (0)

static int __rrr_perl5_type_to_sv_64 (RRR_PERL5_TYPE_TO_SV_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	ELEMENT_SIZE_SET;

	if (element_size != IVSIZE) {
		RRR_MSG_0("Element size not the same as capacity of perl integer in __rrr_perl5_type_h_to_sv, cannot convert value (%li vs %i)\n",
				element_size, IVSIZE);
		ret = 1;
		goto out;
	}

	ELEMENT_LOOP_BEGIN;
		SV *sv = NULL;
		char tmp[64];

		if (value->definition->type == RRR_TYPE_FIXP) {
			if (rrr_fixp_to_str_16(tmp, (ssize_t) sizeof(tmp), *((rrr_fixp*) pos))) {
				RRR_MSG_0("Failed to convert fixed pointer in __rrr_perl5_type_to_sv_64\n");
				ret = 1;
				goto out;
			}
			sv = newSVpv(tmp, strlen(tmp));
		}
		else if (RRR_TYPE_FLAG_IS_SIGNED(value->flags)) {
			sv = newSViv(*((IV*) pos));
		}
		else {
			sv = newSVuv(*((UV*) pos));
		}

		ELEMENT_CALL_CALLBACK;
	ELEMENT_LOOP_END;

	out:
	return ret;
}

static int __rrr_perl5_type_to_sv_blob (RRR_PERL5_TYPE_TO_SV_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	ELEMENT_SIZE_SET;

	ELEMENT_LOOP_BEGIN;
		SV *sv = newSVpvn(pos, element_size);
		ELEMENT_CALL_CALLBACK;
	ELEMENT_LOOP_END;

	out:
	return ret;
}

static int __rrr_perl5_type_to_sv_str (RRR_PERL5_TYPE_TO_SV_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	ELEMENT_SIZE_SET;

	ELEMENT_LOOP_BEGIN;
		SV *sv = newSVpvn_utf8(pos, element_size, 1);
		ELEMENT_CALL_CALLBACK;
	ELEMENT_LOOP_END;

	out:
	return ret;
}

static int __rrr_perl5_type_to_sv_vain (RRR_PERL5_TYPE_TO_SV_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	ELEMENT_SIZE_SET;

	ELEMENT_LOOP_BEGIN;
		SV *sv = newSV(0);
		ELEMENT_CALL_CALLBACK;
	ELEMENT_LOOP_END;

	out:
	return ret;
}

struct type_to_value_h_intermediate_result {
	RRR_LL_NODE(struct type_to_value_h_intermediate_result);
	int do_signed;
	uint64_t unsigned_value;
	int64_t signed_value;
};

struct type_to_value_h_intermediate_result_collection {
	RRR_LL_HEAD(struct type_to_value_h_intermediate_result);
};

// If SV is a string, assume string notation like /^(10#|16#|)-?\d+\.\d+$/
// If SV is a double (NV), convert directly from double to fixed point
// If SV is an IV, assume native full length notation. If IV is <64 bits, it is not possible to store
// fixed point natively in Perl
int rrr_perl5_type_auto_sv_to_fixp (
		rrr_fixp *result,
		struct rrr_perl5_ctx *ctx,
		SV *sv
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	if (SvREADONLY(sv)) {
		RRR_BUG("BUG: READONLY sv to rrr_perl5_type_auto_sv_to_fixp\n");
	}

	int ret = 0;

	STRLEN str_len;
	char *num_str = SvPVutf8_force(sv, str_len);

	if (str_len == 0 || *num_str == '\0') {
		*result = 0;
	}
	else {
		if (sizeof(IV) < sizeof(rrr_fixp) && SvIOK(sv)) {
			RRR_MSG_0("Warning: Perl5 integer value is too small to hold RRR fixed pointer on this system (64 bits are required). Cannot convert Perl5 integer directly, attempting to convert using double or string instead\n");
		}

		// If a scalar was created inside a perl script and not by C API,
		// it is unlikely that we will end up in another function than the
		// string converter. When we export the fixp to the perl script,
		// we also use the 16# - style which is guaranteed not to change
		// the actual value, this may be imported by this string converter.

//		printf ("IOK: %u UOK: %u looks_like_number: %u\n", SvIOK(sv), SvUOK(sv), looks_like_number(sv));

		rrr_fixp fixp;
		if (sizeof(IV) >= sizeof(rrr_fixp) && (SvIOK(sv) || SvUOK(sv))) {
			fixp = SvIV(sv);
//			printf("Direct IV to FIXP conversion %lu\n", fixp);
		}
		else if (SvNOK(sv)) {
			NV nv = SvNV(sv);
			if (rrr_fixp_ldouble_to_fixp(&fixp, nv) != 0) {
				RRR_MSG_0("Warning: Conversion from double to RRR fixed pointer failed, double value may not be finite\n");
				ret = 1;
				goto out;
			}
//			printf("Double to FIXP conversion %f -> %lu\n", nv, fixp);
		}
		else {
			const char *endptr;
			if (rrr_fixp_str_to_fixp(&fixp, num_str, str_len, &endptr) != 0) {
				RRR_MSG_0("Warning: Conversion to RRR fixed pointer failed for value '%s'\n",
						num_str);
				ret = 1;
				goto out;
			}
			if (endptr - num_str != str_len) {
				RRR_MSG_0("Warning: Conversion to RRR fixed pointer failed for value '%s', possible junk data at the end of string.\n",
						num_str);
				ret = 1;
				goto out;
			}
//			printf("String to FIXP conversion %s -> %lu\n", num_str, fixp);
		}
		*result = fixp;
	}

	out:
	return ret;
}

static int __rrr_perl5_type_to_value_64_common_save_intermediate_result (
		struct rrr_perl5_ctx *ctx,
		struct type_to_value_h_intermediate_result_collection *collection,
		SV *sv,
		rrr_type type
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	struct type_to_value_h_intermediate_result *result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_perl5_type_to_value_h_save_intermediate_result\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	STRLEN str_len;
	char *num_str = SvPV_force(sv, str_len);
	if (num_str == NULL) {
		RRR_MSG_0("Could not convert SV to string in __rrr_perl5_type_to_value_h_save_intermediate_result\n");
		ret = 1;
		goto out;
	}

	RRR_ASSERT(sizeof(int64_t) >= sizeof(IV),perl5_int64_t_cannot_hold_iv);
	RRR_ASSERT(sizeof(double) >= sizeof(NV),perl5_double_cannot_hold_nv);

	if (type == RRR_TYPE_FIXP) {
		rrr_fixp fixp;

		// Will print error message
		if ((ret = rrr_perl5_type_auto_sv_to_fixp (&fixp, ctx, sv)) != 0) {
			goto out;
		}

		result->do_signed = 1;
		result->signed_value = fixp;
	}
	else {
		if (str_len == 0 || *num_str == '\0') {
			result->signed_value = 0;
			result->do_signed = 1;
		}
		else if (*num_str == '-') {
			result->signed_value = SvIV(sv);
			result->do_signed = 1;
		}
		else {
			result->unsigned_value = SvUV(sv);
		}
	}

	RRR_LL_APPEND(collection, result);
	result = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(result);
	return ret;
}

static int __rrr_perl5_type_to_value_64_common (
		RRR_PERL5_TYPE_TO_VALUE_ARGS, rrr_type type
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	struct rrr_type_value *result = NULL;

	int ret = 0;

	*target = NULL;

	struct type_to_value_h_intermediate_result_collection intermediate_values = {0};

	// If one or more values were signed, we save all values as signed (only used for h type)
	int some_values_were_signed = 0;

	const struct rrr_type_definition *definition = NULL;

	switch (type) {
		case RRR_TYPE_FIXP:
			definition = &rrr_type_definition_fixp;
			break;
		case RRR_TYPE_H:
			definition = &rrr_type_definition_h;
			break;
		default:
			RRR_BUG("BUG: Unsupported type %u given to __rrr_perl5_type_to_value_64_common\n", type);
	};

	for (int i = 0; i <= av_len(values); i++) {
		SV **tmp = av_fetch(values, i, 1);
		if (tmp == NULL || *tmp == NULL) {
			RRR_MSG_0("Could not fetch from AV in __rrr_perl5_type_to_value_h\n");
			ret = 1;
			goto out;
		}
		if (__rrr_perl5_type_to_value_64_common_save_intermediate_result(ctx, &intermediate_values, *tmp, type)) {
			RRR_MSG_0("Error in perl5 while converting array value with index %i to RRR value\n", i);
			ret = 1;
			goto out;
		}
		if (RRR_LL_LAST(&intermediate_values)->do_signed != 0) {
			some_values_were_signed = 1;
		}
	}

	if (RRR_LL_COUNT(&intermediate_values) != av_len(values) + 1) {
		RRR_BUG("Bug: Not all values were saved in __rrr_perl5_type_to_value_h\n");
	}

	if (rrr_type_value_new (
			&result,
			definition,
			(some_values_were_signed != 0 ? RRR_TYPE_FLAG_SIGNED : 0),
			0,
			NULL,
			0,
			NULL,
			RRR_LL_COUNT(&intermediate_values),
			NULL,
			RRR_LL_COUNT(&intermediate_values) * sizeof(uint64_t)
	) != 0) {
		RRR_MSG_0("Could not allocate new value in __rrr_perl5_type_to_value_h\n");
		ret = 1;
		goto out;
	}

	int i = 0;
	void *pos = result->data;
	RRR_LL_ITERATE_BEGIN(&intermediate_values, struct type_to_value_h_intermediate_result);
		if (some_values_were_signed != 0) {
			int64_t value = 0;
			if (node->do_signed != 0) {
				value = node->signed_value;
			}
			else {
				if (node->unsigned_value > INT64_MAX) {
					RRR_MSG_0("Warning: Integer value from perl5 array at position %i overflows due to conversion to signed integer\n", i);
				}
				value = node->unsigned_value;
			}
//			printf("Save signed value %" PRIi64 "\n", value);
			memcpy(pos, &value, sizeof(value));
		}
		else {
			if (node->do_signed != 0) {
				RRR_BUG("BUG: A value was signed but was not processed as such in __rrr_perl5_type_to_value_h\n");
			}
			uint64_t value = node->unsigned_value;
//			printf("Save unsigned value %" PRIu64 "\n", value);
			memcpy(pos, &value, sizeof(value));
		}

		pos += sizeof(uint64_t);
		i++;
	RRR_LL_ITERATE_END();

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		rrr_type_value_destroy(result);
	}
	RRR_LL_DESTROY(&intermediate_values, struct type_to_value_h_intermediate_result, rrr_free(node));
	return ret;
}

static int __rrr_perl5_type_to_value_h (
		RRR_PERL5_TYPE_TO_VALUE_ARGS
) {
	return __rrr_perl5_type_to_value_64_common(target, ctx, def_orig, values, RRR_TYPE_H);
}

static int __rrr_perl5_type_to_value_fixp (
		RRR_PERL5_TYPE_TO_VALUE_ARGS
) {
	return __rrr_perl5_type_to_value_64_common(target, ctx, def_orig, values, RRR_TYPE_FIXP);
}

struct type_to_value_blob_intermediate_result {
	RRR_LL_NODE(struct type_to_value_blob_intermediate_result);
	char *data;
	ssize_t data_size;
};

void __rrr_perl5_type_to_value_blob_intermediate_result_destroy (struct type_to_value_blob_intermediate_result *result) {
	RRR_FREE_IF_NOT_NULL(result->data);
	rrr_free(result);
}

struct type_to_value_blob_intermediate_result_collection {
	RRR_LL_HEAD(struct type_to_value_blob_intermediate_result);
};

static int __rrr_perl5_type_to_value_blob_save_intermediate_result (
		struct rrr_perl5_ctx *ctx,
		struct type_to_value_blob_intermediate_result_collection *collection,
		SV *sv,
		int do_binary
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	SV *sv_to_free = NULL;

	struct type_to_value_blob_intermediate_result *result = rrr_allocate(sizeof(*result));
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_perl5_type_to_value_blob_save_intermediate_result\n");
		ret = 1;
		goto out;
	}

	memset(result, '\0', sizeof(*result));

	STRLEN str_len = 0;
	char *value = NULL;
	SV *sv_to_use = sv;

	if (SvREADONLY(sv)) {
		sv_to_free = newSVsv(sv);
		sv_to_use = sv_to_free;
	}

	if (do_binary != 0) {
		value = SvPVbyte_force(sv_to_use, str_len);
	}
	else {
		value = SvPVutf8_force(sv_to_use, str_len);
	}

	if (str_len == 0) {
		RRR_MSG_0("Empty strings or blobs cannot be used in arrays in __rrr_perl5_type_to_value_blob_save_intermediate_result\n");
		ret = 1;
		goto out;
	}

	if ((result->data = rrr_allocate(str_len + 1)) == NULL) {
		RRR_MSG_0("Could not allocate memory for data in __rrr_perl5_type_to_value_blob_save_intermediate_result\n");
		ret = 1;
		goto out;
	}

	memcpy(result->data, value, str_len);

	result->data_size = str_len;

	RRR_LL_APPEND(collection, result);
	result = NULL;

	out:
	SvREFCNT_dec(sv_to_free); // Pass NULL allowed
	if (result != NULL) {
		__rrr_perl5_type_to_value_blob_intermediate_result_destroy(result);
	}
	return ret;
}

static int __rrr_perl5_type_to_value_blob_populate_intermediate_list (
		struct type_to_value_blob_intermediate_result_collection *collection,
		ssize_t *total_length_result,
		struct rrr_perl5_ctx *ctx,
		AV *values,
		int lengths_must_be_equal,
		int do_binary
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	ssize_t total_length = 0;
	ssize_t previous_length = 0;

	// Note: av_len returns index of last element
	ssize_t array_length = av_len(values);
	for (int i = 0; i <= array_length; i++) {
		SV **tmp = av_fetch(values, i, 1);
		if (tmp == NULL || *tmp == NULL) {
			RRR_MSG_0("Could not fetch from AV in __rrr_perl5_type_to_value_blob_populate_intermediate_list\n");
			ret = 1;
			goto out;
		}

		// This performs 0-length check
		if (__rrr_perl5_type_to_value_blob_save_intermediate_result(ctx, collection, *tmp, do_binary) != 0) {
			RRR_MSG_0("Error in perl5 while converting stringish array value with index %i to RRR value\n", i);
			ret = 1;
			goto out;
		}

		ssize_t data_len = RRR_LL_LAST(collection)->data_size;
		if (lengths_must_be_equal != 0 && i > 0 && data_len != previous_length) {
			RRR_MSG_0("Stringish array value length %li at index %i differed from the previous value. All lengths must be equal, cannot continue.\n",
					data_len, i);
			ret = 1;
			goto out;
		}

		total_length += data_len;
		previous_length = data_len;
	}

	*total_length_result = total_length;

	out:
	return ret;
}

static int __rrr_perl5_type_to_value_blob (RRR_PERL5_TYPE_TO_VALUE_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	struct rrr_type_value *result = NULL;

	int ret = 0;

	*target = NULL;

	struct type_to_value_blob_intermediate_result_collection intermediate_values = {0};

	int do_binary = 0;
	switch (def_orig->type) {
		case RRR_TYPE_BLOB:
		case RRR_TYPE_MSG:
		case RRR_TYPE_HDLC:
			do_binary = 1;
			break;
		default:
			do_binary = 0;
			break;
	}

	ssize_t total_length = 0;
	if ((ret = __rrr_perl5_type_to_value_blob_populate_intermediate_list (
			&intermediate_values,
			&total_length,
			ctx,
			values,
			1,			// Lengths must be equal
			do_binary
	)) != 0) {
		goto out;
	}

	if (rrr_type_value_new (
			&result,
			def_orig,
			0,
			0,
			NULL,
			0,
			NULL,
			RRR_LL_COUNT(&intermediate_values),
			NULL,
			total_length
	) != 0) {
		RRR_MSG_0("Could not allocate new value in __rrr_perl5_type_to_value_blob\n");
		ret = 1;
		goto out;
	}

	memset(result->data, '\0', total_length);

	// We do some extra checks here just to be sure we haven't made any bugs
	ssize_t element_length = total_length / RRR_LL_COUNT(&intermediate_values);
	if (RRR_LL_COUNT(&intermediate_values) * element_length != total_length) {
		RRR_BUG("BUG: Size discrepancy in __rrr_perl5_type_to_value_blob\n");
	}

	void *pos = result->data;

	RRR_LL_ITERATE_BEGIN(&intermediate_values, struct type_to_value_blob_intermediate_result);
		// Extra paranoid check
		if (node->data_size != element_length) {
			RRR_BUG("BUG: Size discrepancy in element in __rrr_perl5_type_to_value_blob\n");
		}

		memcpy(pos, node->data, element_length);

		pos += element_length;
	RRR_LL_ITERATE_END();

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		rrr_type_value_destroy(result);
	}
	RRR_LL_DESTROY (
			&intermediate_values,
			struct type_to_value_blob_intermediate_result,
			__rrr_perl5_type_to_value_blob_intermediate_result_destroy(node)
	);
	return ret;
}

static int __rrr_perl5_type_to_value_str (RRR_PERL5_TYPE_TO_VALUE_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	struct rrr_type_value *result = NULL;

	int ret = 0;

	*target = NULL;

	struct type_to_value_blob_intermediate_result_collection intermediate_values = {0};

	ssize_t total_length = 0;
	if ((ret = __rrr_perl5_type_to_value_blob_populate_intermediate_list (
			&intermediate_values,
			&total_length,
			ctx,
			values,
			0,			// Lengths may be different
			0			// Non-binary
	)) != 0) {
		goto out;
	}

	ssize_t data_size = RRR_LL_FIRST(&intermediate_values)->data_size;
	const char *data = RRR_LL_FIRST(&intermediate_values)->data;

	if (rrr_type_value_new (
			&result,
			&rrr_type_definition_str,
			0,
			0,
			NULL,
			0,
			NULL,
			1,
			NULL,
			data_size
	) != 0) {
		RRR_MSG_0("Could not create new value in __rrr_perl5_type_to_value_str\n");
		ret = 1;
		goto out;
	}

	memcpy(result->data, data, data_size);

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		rrr_type_value_destroy(result);
	}
	RRR_LL_DESTROY (
			&intermediate_values,
			struct type_to_value_blob_intermediate_result,
			__rrr_perl5_type_to_value_blob_intermediate_result_destroy(node)
	);
	return ret;
}

static int __rrr_perl5_type_to_value_vain (RRR_PERL5_TYPE_TO_VALUE_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	if (av_len(values) > 1) {
		RRR_MSG_0("Array items of type vain cannot have more than one value, %lld were found\n", (long long int) av_len(values));
		return 1;
	}

	return rrr_type_value_new (
			target,
			&rrr_type_definition_vain,
			0,
			0,
			NULL,
			0,
			NULL,
			1,
			NULL,
			0
	);
}

static int __rrr_perl5_type_to_value_ustr_istr (RRR_PERL5_TYPE_TO_VALUE_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	struct rrr_type_value *result = NULL;

	int ret = 0;

	struct type_to_value_blob_intermediate_result_collection intermediate_values = {0};

	ssize_t total_length = 0;
	if ((ret = __rrr_perl5_type_to_value_blob_populate_intermediate_list (
			&intermediate_values,
			&total_length,
			ctx,
			values,
			0,	// Lengths may differ
			0	// Non-binary, adds '\0' to all values
	)) != 0) {
		goto out;
	}

	if (rrr_type_value_new (
			&result,
			&rrr_type_definition_h,
			(def_orig->type == RRR_TYPE_ISTR ? RRR_TYPE_FLAG_SIGNED : 0),
			0,
			NULL,
			0,
			NULL,
			RRR_LL_COUNT(&intermediate_values),
			NULL,
			RRR_LL_COUNT(&intermediate_values) * sizeof(uint64_t)
	) != 0) {
		RRR_MSG_0("Could not allocate memory for value in __rrr_perl5_type_to_value_ustr_istr\n");
		ret = 1;
		goto out;
	}

	memset(result->data, '\0', result->total_stored_length);

	int i = 0;
	void *pos = result->data;
	RRR_LL_ITERATE_BEGIN(&intermediate_values, struct type_to_value_blob_intermediate_result);
		if (node->data_size == 0) {
			RRR_BUG("BUG: Size was 0, should be at least 1 to hold termination character in __rrr_perl5_type_to_value_ustr_istr\n");
		}
		else if (node->data_size == 1) {
			// Empty string is treated as zero
			goto increment_and_next;
		}

		rrr_length parsed_bytes = 0;
		if (def_orig->type == RRR_TYPE_USTR) {
			ret = rrr_type_import_ustr_raw(pos, &parsed_bytes, node->data, node->data + node->data_size);
		}
		else if (def_orig->type == RRR_TYPE_ISTR) {
			ret = rrr_type_import_istr_raw(pos, &parsed_bytes, node->data, node->data + node->data_size);
		}
		else {
			RRR_BUG("Type was neither USTR nor ISTR in __rrr_perl5_type_to_value_ustr\n");
		}

		if (parsed_bytes < node->data_size - 1) {
			RRR_MSG_0("Invalid characters in perl5 istr or ustr in array value index %i at position ~%li\n", i, parsed_bytes);
			ret = 1;
			goto out;
		}

		if (ret != 0) {
			RRR_MSG_0("Error while importing istr or ustr from perl5 for value with index %i\n", i);
			ret = 1;
			goto out;
		}

		increment_and_next:
		i++;
		pos += sizeof(uint64_t);
	RRR_LL_ITERATE_END();

	*target = result;
	result = NULL;

	out:
	if (result != NULL) {
		rrr_type_value_destroy(result);
	}
	RRR_LL_DESTROY (
			&intermediate_values,
			struct type_to_value_blob_intermediate_result,
			__rrr_perl5_type_to_value_blob_intermediate_result_destroy(node)
	);
	return ret;
}

#define DEFINE_PERL5_TYPE(name_uc,name_lc,to_sv,to_value) \
		{ RRR_PASTE(RRR_TYPE_,name_uc), & RRR_PASTE(rrr_type_definition_,name_lc), to_sv, to_value }

static const struct rrr_perl5_type_definition rrr_perl5_type_definitions[] = {
	DEFINE_PERL5_TYPE(LE,   le,   NULL,                        NULL),                                // 0
	DEFINE_PERL5_TYPE(BE,   be,   NULL,                        NULL),                                // 1
	DEFINE_PERL5_TYPE(H,    h,    __rrr_perl5_type_to_sv_64,   __rrr_perl5_type_to_value_h),         // 2
	DEFINE_PERL5_TYPE(BLOB, blob, __rrr_perl5_type_to_sv_blob, __rrr_perl5_type_to_value_blob),      // 3
	DEFINE_PERL5_TYPE(USTR, ustr, NULL,                        __rrr_perl5_type_to_value_ustr_istr), // 4
	DEFINE_PERL5_TYPE(ISTR, istr, NULL,                        __rrr_perl5_type_to_value_ustr_istr), // 5
	DEFINE_PERL5_TYPE(SEP,  sep,  __rrr_perl5_type_to_sv_blob, __rrr_perl5_type_to_value_blob),      // 6
	DEFINE_PERL5_TYPE(MSG,  msg,  __rrr_perl5_type_to_sv_blob, __rrr_perl5_type_to_value_blob),      // 7
	DEFINE_PERL5_TYPE(FIXP, fixp, __rrr_perl5_type_to_sv_64,   __rrr_perl5_type_to_value_fixp),      // 8
	DEFINE_PERL5_TYPE(STR,  str,  __rrr_perl5_type_to_sv_str,  __rrr_perl5_type_to_value_str),       // 9
	DEFINE_PERL5_TYPE(HEX,  str,  __rrr_perl5_type_to_sv_str,  __rrr_perl5_type_to_value_str),       //10
	DEFINE_PERL5_TYPE(NSEP, nsep, __rrr_perl5_type_to_sv_blob, __rrr_perl5_type_to_value_blob),      //11
	DEFINE_PERL5_TYPE(STX,  stx,  __rrr_perl5_type_to_sv_blob, __rrr_perl5_type_to_value_blob),      //12
	DEFINE_PERL5_TYPE(ERR,  err,  NULL,                        NULL),                                //13
	DEFINE_PERL5_TYPE(VAIN, vain, __rrr_perl5_type_to_sv_vain, __rrr_perl5_type_to_value_vain),      //14
	DEFINE_PERL5_TYPE(HDLC, hdlc, __rrr_perl5_type_to_sv_blob, __rrr_perl5_type_to_value_blob),      //15
	{ 0, NULL, NULL, NULL }
};
// NOTE : Count correctly here
const struct rrr_perl5_type_definition *rrr_perl5_type_definition_string = &rrr_perl5_type_definitions[9];
const struct rrr_perl5_type_definition *rrr_perl5_type_definition_h = &rrr_perl5_type_definitions[2];
const struct rrr_perl5_type_definition *rrr_perl5_type_definition_blob = &rrr_perl5_type_definitions[3];
const struct rrr_perl5_type_definition *rrr_perl5_type_definition_vain = &rrr_perl5_type_definitions[14];

const struct rrr_perl5_type_definition *rrr_perl5_type_get_from_name (
		const char *name
) {
	int i = 0;
	do {
		const struct rrr_perl5_type_definition *type = &rrr_perl5_type_definitions[i];
		if (strcmp(type->definition->identifier, name) == 0) {
			return type;
		}
		i++;
	} while(rrr_perl5_type_definitions[i].type != 0);

	return NULL;
}

const struct rrr_perl5_type_definition *rrr_perl5_type_get_from_id (
		uint8_t type_in
) {
	int i = 0;
	do {
		const struct rrr_perl5_type_definition *type = &rrr_perl5_type_definitions[i];
		if (type->type == type_in) {
			return type;
		}
		i++;
	} while(rrr_perl5_type_definitions[i].type != 0);

	return NULL;
}

const struct rrr_perl5_type_definition *rrr_perl5_type_get_from_sv (
		SV *sv
) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	const struct rrr_perl5_type_definition *type = rrr_perl5_type_definition_blob;

	if (SvIOK(sv)) {
		type = rrr_perl5_type_definition_h;
	}
	else if (SvNOK(sv)) {
		// Use default (blob)
	}
	else if (SvUTF8(sv) || SvPOK(sv) ) {
		// Use string
		STRLEN len;
		char *str = SvPV(sv, len);
		if (rrr_utf8_validate(str, len) == 0) {
			type = rrr_perl5_type_definition_string;
		}
	}
	else if (!SvOK(sv)) {
		type = rrr_perl5_type_definition_vain;
	}

	return type;
}
