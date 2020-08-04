/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>

#include <EXTERN.h>
#include <perl.h>

#include "../log.h"
#include "perl5.h"
#include "perl5_types.h"
#include "perl5_xsub.h"
#include "perl5_hv_macros.h"

#include "../array.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../util/rrr_time.h"
#include "../fixed_point.h"

unsigned int rrr_perl5_message_send (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);
	struct rrr_perl5_message_hv *message_new_hv = NULL;

	unsigned int ret = TRUE;

	SvREFCNT_inc(hv);
	message_new_hv = rrr_perl5_allocate_message_hv_with_hv (ctx, hv);
	if (message_new_hv == NULL) {
		RRR_MSG_0("Could not allocate message hv in rrr_perl5_message_send\n");
		ret = FALSE;
		goto out;
	}

	struct rrr_msg_addr addr_msg;
	struct rrr_msg_msg *message_new = NULL;
	if (rrr_msg_msg_new_empty(&message_new, MSG_TYPE_MSG, MSG_CLASS_DATA, rrr_time_get_64(), 0, 0) != 0) {
		RRR_MSG_0("Could not allocate new message in rrr_perl5_message_send\n");
		ret = FALSE;
		goto out;
	}
	if (rrr_perl5_hv_to_message(&message_new, &addr_msg, ctx, message_new_hv) != 0) {
		ret = FALSE;
		goto out;
	}

	// Takes ownership of memory of message (but not address message)
	ctx->send_message(message_new, &addr_msg, ctx->private_data);
	message_new = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(message_new);
	if (message_new_hv != NULL) {
		rrr_perl5_destruct_message_hv(ctx, message_new_hv);
	}
	return TRUE;
}

unsigned int rrr_perl5_message_push_tag_blob (HV *hv, const char *tag, const char *value, size_t size) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (rrr_array_push_value_blob_with_tag_with_size(array, tag, value, size) != 0) {
		RRR_MSG_0("Failed to push string to array in rrr_perl5_message_set_tag_str\n");
		ret = FALSE;
		goto out;
	}

	out:
	return ret;
}

unsigned int rrr_perl5_message_push_tag_str (HV *hv, const char *tag, const char *str) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (rrr_array_push_value_str_with_tag(array, tag, str) != 0) {
		RRR_MSG_0("Failed to push string to array in rrr_perl5_message_set_tag_str\n");
		ret = FALSE;
		goto out;
	}

	out:
	return ret;
}

unsigned int rrr_perl5_message_push_tag_h (HV *hv, const char *tag, SV *sv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (SvUOK(sv)) {
		if (rrr_array_push_value_u64_with_tag(array, tag, SvUV(sv)) != 0) {
			RRR_MSG_0("Warning: Failed to push unsigned value to array in push_tag_h\n");
			ret = FALSE;
			goto out;
		}
	}
	else {
		if (rrr_array_push_value_i64_with_tag(array, tag, SvIV(sv)) != 0) {
			RRR_MSG_0("Warning: Failed to push signed value to array in push_tag_h\n");
			ret = FALSE;
			goto out;
		}
	}

	out:
	return ret;
}

unsigned int rrr_perl5_message_push_tag_fixp (HV *hv, const char *tag, SV *sv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_fixp fixp;

	// Cannot pass READONLY to fixp convert
	SV *sv_tmp = newSVsv(sv);

	if (rrr_perl5_type_auto_sv_to_fixp(&fixp, ctx, sv_tmp) != 0) {
		RRR_MSG_0("Failed to convert SV to fixed point in Perl5 push_tag_fixp\n");
		ret = false;
		goto out;
	}

	if (rrr_array_push_value_fixp_with_tag(array, tag, fixp) != 0) {
		RRR_MSG_0("Warning: Failed to push fixed pointer value to array in Perl5 push_tag_fixp\n");
		ret = FALSE;
		goto out;
	}

	out:
	SvREFCNT_dec(sv_tmp);
	return ret;
}

static int __rrr_perl5_message_push_tag (struct rrr_array *target, const char *tag, SV *values) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

    int ret = 0;

    struct rrr_type_value *new_value = NULL;
    AV *temporary_av = newAV();

    // All values must be copied due to problems with READONLY-stuff while we convert
	if (SvTYPE(values) == SVt_PVAV) {
		for (int i = 0; i < av_len((AV*)values) + 1; i++) {
			SV **tmp = av_fetch((AV*)values, i, 0);
			if (tmp == NULL) {
				RRR_MSG_0("Warning: Skipping undefined value in position %i of array given to push_tag in Perl5\n", i);
				continue;
			}
			av_push(temporary_av, newSVsv(*tmp));
		}
	}
	else {
    	av_push(temporary_av, newSVsv(values));
    }

	const struct rrr_perl5_type_definition *type_def = rrr_perl5_type_definition_string;
	SV **type_template_sv = av_fetch(temporary_av, 0, 0);

	if (type_template_sv != NULL) {
		type_def = rrr_perl5_type_get_from_sv(*type_template_sv);
	}
	else {
		RRR_MSG_0("Warning: First value of array given to push_tag was undefined in Perl5, defaulting to string type\n");
	}

	if (type_def->to_value == NULL) {
		RRR_BUG("rrr_perl5_type_get_from_sv returned a type which cannot be converted in __rrr_perl5_message_push_tag\n");
	}

    if ((ret = type_def->to_value (&new_value, ctx, type_def->definition, temporary_av)) != 0) {
    	RRR_MSG_0("Could not convert perl5 array item, result was %i\n", ret);
    	ret = 1;
    	goto out;
    }

    if (rrr_type_value_set_tag(new_value, tag, strlen(tag)) != 0) {
    	RRR_MSG_0("Warning: Failed to set tag of array value in Perl5 push_tag\n");
    	ret = 1;
    	goto out;
    }

    RRR_LL_APPEND(target, new_value);
    new_value = NULL;

    out:
	SvREFCNT_dec(temporary_av);
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
    return ret;
}

unsigned int rrr_perl5_message_push_tag (HV *hv, const char *tag, SV *values) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

    if ((values = rrr_perl5_deep_dereference(values)) == NULL) {
    	RRR_MSG_0("Could not dereference value in rrr_perl5_message_push_tag\n");
    	ret = FALSE;
    	goto out;
    }

     if ((ret = __rrr_perl5_message_push_tag(array, tag, values)) != 0) {
		RRR_MSG_0("Warning: Failed to push value(s) to array in Perl5 push_tag\n");
		ret = FALSE;
	}

	out:
	return ret;
}

unsigned int rrr_perl5_message_set_tag_blob (HV *hv, const char *tag, const char *value, size_t size) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);
	ret = rrr_perl5_message_push_tag_blob(hv, tag, value, size);
	out:
	return ret;
}

unsigned int rrr_perl5_message_set_tag_str (HV *hv, const char *tag, const char *str) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);
	ret = rrr_perl5_message_push_tag_str(hv, tag, str);
	out:
	return ret;
}

unsigned int rrr_perl5_message_set_tag_h (HV *hv, const char *tag, SV *values) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);
	ret = rrr_perl5_message_push_tag_h(hv, tag, values);
	out:
	return ret;
}

unsigned int rrr_perl5_message_set_tag_fixp (HV *hv, const char *tag, SV *values) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	unsigned int ret = TRUE;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);
	ret = rrr_perl5_message_push_tag_fixp(hv, tag, values);
	out:
	return ret;
}

struct rrr_perl5_arrays_populate_push_element_callback_data {
	AV *target_array;
};

static int __rrr_perl5_message_hv_arrays_populate_push_element_callback(RRR_PERL5_TYPE_TO_SV_CALLBACK_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    (void)(idx);
    (void)(def_orig);

	struct rrr_perl5_arrays_populate_push_element_callback_data *callback_data = arg;
	av_push(callback_data->target_array, sv);
	SvREFCNT_inc(sv);

	return 0;
}

AV *rrr_perl5_message_get_tag (HV *hv, const char *tag) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = 0;

	AV *array_values = newAV();

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

	RRR_LL_ITERATE_BEGIN(array, struct rrr_type_value);
		// Note : Tags may be duplicated in array
		if (node->tag != NULL && strcmp(node->tag, tag) == 0) {
			const struct rrr_perl5_type_definition *definition = rrr_perl5_type_get_from_id(node->definition->type);

			if (definition == NULL) {
				RRR_MSG_0("Warning: Unknown array value type %u for tag %s in Perl5 get_tag, cannot add to array\n",
						node->definition->type, node->tag);
				RRR_LL_ITERATE_NEXT();
			}

			if (definition->to_sv == NULL) {
				RRR_MSG_0("Warning: Cannot convert array value type '%s' in tag '%s' to Perl5 type in get_tag, unsupported type\n",
						definition->definition->identifier, node->tag);
				RRR_LL_ITERATE_NEXT();
			}

			struct rrr_perl5_arrays_populate_push_element_callback_data callback_data = { array_values };

			if (definition->to_sv(ctx, node, __rrr_perl5_message_hv_arrays_populate_push_element_callback, &callback_data)) {
				RRR_MSG_0("Warning: Error while converting value from tag %s to Perl5 type in get_tag\n",
						node->tag);
				RRR_LL_ITERATE_NEXT();
			}
		}
	RRR_LL_ITERATE_END();

	out:
	if (ret != 0) {
		av_clear(array_values);
		RRR_MSG_0("Warning: Error in Perl5 get_tag while getting values for array tag\n");
	}

	return array_values;
}

SV *rrr_perl5_message_get_tag_at (HV *hv, const char *tag, size_t pos) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	SV *result = NULL;

	AV *array_values = rrr_perl5_message_get_tag (hv, tag);
	SV **ref = av_fetch(array_values, pos, 0);

	if (ref != NULL) {
		result = *ref;
		SvREFCNT_inc(result);
	}

	SvREFCNT_dec((SV*)array_values);

	out:
	if (result == NULL) {
		result = newSViv(0);
		sv_set_undef(result);
	}

	return result;
}

SV *rrr_perl5_settings_get (HV *settings, const char *key) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	char *value = ctx->get_setting(key, ctx->private_data);
	SV *ret = NULL;

	if (value != NULL) {
		ret = newSVpv(value, strlen(value));
	}
	else {
		ret = newSV(0);
		sv_set_undef(ret);
	}

	RRR_FREE_IF_NOT_NULL(value);

	return ret;
}

int rrr_perl5_settings_set (HV *settings, const char *key, const char *value) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = ctx->set_setting(key, value, ctx->private_data);

	return (ret == 0 ? TRUE : FALSE);
}

static int __rrr_perl5_debug_print (HV *debug, int debuglevel, const char *string, int always_print) {
	(void)(debug);

	if (!RRR_DEBUGLEVEL_OK(debuglevel)) {
		RRR_MSG_0("Received unknown debuglevel %i in __rrr_perl5_debug_print\n", debuglevel);
		return FALSE;
	}

	// Unsure if error in the script may cause string to become NULL. If not, this should
	// be an RRR_BUG
	if (string == NULL) {
		RRR_MSG_0("String was NULL in __rrr_perl5_debug_print\n");
		return FALSE;
	}

	if (always_print) {
		RRR_MSG_X(debuglevel, "%s", string);
	}
	else {
		RRR_DBG_X(debuglevel, "%s", string);
	}

	return TRUE;
}

int rrr_perl5_debug_msg (HV *debug, int debuglevel, const char *string) {
	return __rrr_perl5_debug_print(debug, debuglevel, string, 1); // Always print
}

int rrr_perl5_debug_dbg (HV *debug, int debuglevel, const char *string) {
	return __rrr_perl5_debug_print(debug, debuglevel, string, 0); // Print if debuglevel is active
}

int rrr_perl5_debug_err (HV *debug, const char *string) {
	// Unsure if error in the script may cause string to become NULL. If not, this should
	// be an RRR_BUG
	if (string == NULL) {
		RRR_MSG_0("String was NULL in __rrr_perl5_debug_print\n");
		return FALSE;
	}

	RRR_MSG_ERR("%s", string);
	return TRUE;
}
