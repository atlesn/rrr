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
#include "../rrr_strerror.h"

unsigned int rrr_perl5_message_send (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);
	struct rrr_perl5_message_hv *message_new_hv = NULL;

	int ret = 0;

	if ((message_new_hv = rrr_perl5_allocate_message_hv_with_hv (ctx, hv)) == NULL) { // Will incref
		RRR_MSG_0("Could not allocate message hv in rrr_perl5_message_send\n");
		ret = 1;
		goto out_final;
	}

	struct rrr_msg_addr addr_msg;
	struct rrr_msg_msg *message_new = NULL;
	if (rrr_msg_msg_new_empty(&message_new, MSG_TYPE_MSG, MSG_CLASS_DATA, rrr_time_get_64(), 0, 0) != 0) {
		RRR_MSG_0("Could not allocate new message in rrr_perl5_message_send\n");
		ret = 1;
		goto out_free_message_hv;
	}
	if (rrr_perl5_hv_to_message(&message_new, &addr_msg, ctx, message_new_hv) != 0) {
		ret = 1;
		goto out_free_message_new;
	}

	// Takes ownership of memory of message (but not address message)
	ctx->send_message(message_new, &addr_msg, ctx->private_data);
	message_new = NULL;

	// Always destroy message hv
	goto out_free_message_hv;
	out_free_message_new:
		RRR_FREE_IF_NOT_NULL(message_new);
	out_free_message_hv:
		rrr_perl5_destruct_message_hv(ctx, message_new_hv);
	out_final:
		return ret;
}

unsigned int rrr_perl5_message_clear_array (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear(array);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_push_tag_blob (HV *hv, const char *tag, const char *value, size_t size) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (rrr_array_push_value_blob_with_tag_with_size(array, tag, value, size) != 0) {
		RRR_MSG_0("Failed to push string to array in rrr_perl5_message_set_tag_str\n");
		ret = 1;
		goto out;
	}

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_push_tag_str (HV *hv, const char *tag, const char *str) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (rrr_array_push_value_str_with_tag(array, tag, str) != 0) {
		RRR_MSG_0("Failed to push string to array in rrr_perl5_message_set_tag_str\n");
		ret = 1;
		goto out;
	}

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_push_tag_h (HV *hv, const char *tag, SV *sv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (SvUOK(sv)) {
		if (rrr_array_push_value_u64_with_tag(array, tag, SvUV(sv)) != 0) {
			RRR_MSG_0("Warning: Failed to push unsigned value to array in push_tag_h\n");
			ret = 1;
			goto out;
		}
	}
	else {
		if (rrr_array_push_value_i64_with_tag(array, tag, SvIV(sv)) != 0) {
			RRR_MSG_0("Warning: Failed to push signed value to array in push_tag_h\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_push_tag_fixp (HV *hv, const char *tag, SV *sv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = 0;

	SV *sv_tmp = NULL;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_fixp fixp;

	// Cannot pass READONLY to fixp convert
	sv_tmp = newSVsv(sv);

	if (rrr_perl5_type_auto_sv_to_fixp(&fixp, ctx, sv_tmp) != 0) {
		RRR_MSG_0("Failed to convert SV to fixed point in Perl5 push_tag_fixp\n");
		ret = 1;
		goto out;
	}

	if (rrr_array_push_value_fixp_with_tag(array, tag, fixp) != 0) {
		RRR_MSG_0("Warning: Failed to push fixed pointer value to array in Perl5 push_tag_fixp\n");
		ret = 1;
		goto out;
	}

	out:
	SvREFCNT_dec(sv_tmp);
	return (ret == 0 ? TRUE : FALSE);
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

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

    if ((values = rrr_perl5_deep_dereference(values)) == NULL) {
    	RRR_MSG_0("Could not dereference value in rrr_perl5_message_push_tag\n");
    	ret = 1;
    	goto out;
    }

     if ((ret = __rrr_perl5_message_push_tag(array, tag, values)) != 0) {
		RRR_MSG_0("Warning: Failed to push value(s) to array in Perl5 push_tag\n");
		ret = 1;
		goto out;
	}

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_set_tag_blob (HV *hv, const char *tag, const char *value, size_t size) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);

	ret = (rrr_perl5_message_push_tag_blob(hv, tag, value, size) == TRUE ? 0 : 1);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_set_tag_str (HV *hv, const char *tag, const char *str) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);

	ret = (rrr_perl5_message_push_tag_str(hv, tag, str) == TRUE ? 0 : 1);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_set_tag_h (HV *hv, const char *tag, SV *values) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);

	ret = (rrr_perl5_message_push_tag_h(hv, tag, values) == TRUE ? 0 : 1);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_set_tag_fixp (HV *hv, const char *tag, SV *values) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);

	ret = (rrr_perl5_message_push_tag_fixp(hv, tag, values) == TRUE ? 0 : 1);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_clear_tag (HV *hv, const char *tag) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	rrr_array_clear_by_tag(array, tag);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

unsigned int rrr_perl5_message_ip_set (HV *hv, const char *ip, UV uv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	struct sockaddr_storage result = {0};
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &result;
	struct sockaddr_in *in = (struct sockaddr_in *) &result;

	socklen_t addr_len = 0;

	if (uv > UINT16_MAX) {
		RRR_MSG_0("Warning: Port number was too large in Perl5 ip_set\n");
		ret = 1;
		goto out;
	}

	uint16_t port = uv;

	if (inet_pton(AF_INET, ip, &(in->sin_addr)) == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		addr_len = sizeof(*in);
	}
	else if (inet_pton(AF_INET6, ip, &(in6->sin6_addr)) == 1) {
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		addr_len = sizeof(*in6);
	}
	else {
		RRR_MSG_0("Warning: Could not convert '%s' to internal address representation in Perl5 ip_set, possibly invalid address format.\n",
				ip);
		ret = 1;
		goto out;
	}

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr,hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr_len,hv);

	sv_setpvn(ip_addr, (char *) &result, (STRLEN) addr_len);
	sv_setuv(ip_addr_len, addr_len);

	out:
	return (ret == 0 ? TRUE : FALSE);
}

AV *rrr_perl5_message_ip_get (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	AV *result = newAV();

	int ret = 0; // Just a dummy, we return empty array on failure

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr,hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr_len,hv);

	// Must initialize result values here
	uint16_t result_port = 0;
	char result_string[INET6_ADDRSTRLEN];
	*result_string = '\0';

	UV addr_len = SvUV(ip_addr_len);
	STRLEN addr_len_storage;
	char *addr = SvPV(ip_addr, addr_len_storage);

	if (addr_len_storage != addr_len) {
		RRR_MSG_0("Warning: Mismatch between address length in ip_addr and stated length in ip_addr_len in Perl5 ip_get, cannot get address\n");
		goto out;
	}

	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;
	struct sockaddr_in *in = (struct sockaddr_in *) addr;

	if (addr_len == sizeof(*in6)) {
		if (inet_ntop(AF_INET6, &in6->sin6_addr, result_string, sizeof(result_string)) == NULL) {
			RRR_MSG_0("Could not convert IP6 address to string in ip_get of Perl5: %s\n", rrr_strerror(errno));
			goto out;
		}
		result_port = ntohs(in6->sin6_port);
	}
	else if (addr_len == sizeof(*in)) {
		if (inet_ntop(AF_INET, &in->sin_addr, result_string, sizeof(result_string)) == NULL) {
			RRR_MSG_0("Could not convert IP4 address to string in ip_get of Perl5: %s\n", rrr_strerror(errno));
			goto out;
		}
		result_port = ntohs(in->sin_port);
	}
	else if (addr_len == 0) {
		// Return undefined
		goto out;
	}
	else {
		RRR_MSG_0("Warning: Unknown address length %lu in ip_get of Perl5\n", addr_len);
		goto out;
	}

	av_push(result, newSVpv(result_string, strlen(result_string)));
	av_push(result, newSVuv(result_port));

	out:
	return result;
}

unsigned int rrr_perl5_message_ip_clear (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr,hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr_len,hv);

	sv_setuv(ip_addr_len, 0);
	sv_setpv(ip_addr, "");

	out:
	return (ret == 0 ? TRUE : FALSE);
}

SV *rrr_perl5_message_ip_get_protocol (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0; // Dummy

	SV *result = newSVpv("udp", 3);
	SvUTF8_on(result);

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_so_type, hv);

	STRLEN len;

	char *proto = SvPVutf8_force(ip_so_type, len);

	if (len == 3 && strncasecmp(proto, "tcp", 3)) {
		SvPV_set(result, "tcp");
		SvPV_set(ip_so_type, "tcp");
	}
	else {
		SvPV_set(ip_so_type, "udp");
	}

	out:
	return result;
}

unsigned int rrr_perl5_message_ip_set_protocol (HV *hv, const char *protocol) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_so_type, hv);

	if (strcasecmp(protocol, "tcp") == 0) {
		SvUTF8_on(ip_so_type);
		sv_setpv(ip_so_type, "tcp");
	}
	else if (strcasecmp(protocol, "udp") == 0) {
		SvUTF8_on(ip_so_type);
		sv_setpv(ip_so_type, "udp");
	}
	else {
		RRR_MSG_0("Warning: Unknown protocol '%s' given to Perl5 set_protocol, must be 'udp' or 'tcp'\n");
		ret = 1;
		goto out;
	}

	out:
	return (ret == 0 ? TRUE : FALSE);
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

int __rrr_perl5_message_type_to_sv (AV *target, struct rrr_perl5_ctx *ctx, struct rrr_type_value *node) {
	const struct rrr_perl5_type_definition *definition = rrr_perl5_type_get_from_id(node->definition->type);

	if (definition == NULL) {
		RRR_MSG_0("Warning: Unknown array value type %u for tag %s in Perl5, cannot add to array\n",
				node->definition->type, node->tag);
		return 1;
	}

	if (definition->to_sv == NULL) {
		RRR_MSG_0("Warning: Cannot convert array value type '%s' in tag '%s' to Perl5 type, unsupported type\n",
				definition->definition->identifier, node->tag);
		return 1;
	}

	struct rrr_perl5_arrays_populate_push_element_callback_data callback_data = { target };

	if (definition->to_sv(ctx, node, __rrr_perl5_message_hv_arrays_populate_push_element_callback, &callback_data)) {
		RRR_MSG_0("Warning: Error while converting value from tag %s to Perl5 type\n",
				node->tag);
		return 1;
	}

	return 0;
}

AV *rrr_perl5_message_get_tag_all (HV *hv, const char *tag) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = 0;

	AV *array_values = newAV();

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

	int i = 0;
	RRR_LL_ITERATE_BEGIN(array, struct rrr_type_value);
		// Note : Tags may be duplicated in array
		if (	(node->tag != NULL && *(node->tag) != '\0' && *tag != '\0' && strcmp(node->tag, tag) == 0)
				|| (*tag == '\0' && (node->tag == NULL || *(node->tag) == '\0'))
		) {
			if (__rrr_perl5_message_type_to_sv(array_values, ctx, node) != 0) {
				RRR_MSG_0("Warning: Conversion error in Perl5 get_tag_all at array position %i\n", i);
			}
		}
		i++;
	RRR_LL_ITERATE_END();

	out:
	if (ret != 0) {
		SvREFCNT_dec((SV*)array_values);
		array_values = NULL;
	}

	return array_values;
}

AV *rrr_perl5_message_get_position (HV *hv, UV pos) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = rrr_perl5_find_ctx (my_perl);

	int ret = 0;

	AV *array_values = newAV();

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

	// Memory not managed here
	struct rrr_type_value *value = rrr_array_value_get_by_index (array, pos);
	if (value == NULL) {
		ret = 1;
		goto out;
	}

	if (__rrr_perl5_message_type_to_sv(array_values, ctx, value) != 0) {
		RRR_MSG_0("Warning: Conversion error in Perl5 get_position at array position %u\n", pos);
		ret = 1;
		goto out;
	}

	out:
	if (ret != 0) {
		SvREFCNT_dec((SV*)array_values);
		array_values = NULL;
	}
	return array_values;
}

SV *rrr_perl5_message_count_positions (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;
	SV *result = newSVuv(0);

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

	int count = rrr_array_count(array);
	if (count < 0) {
		RRR_BUG("BUG: Array count was <0 in rrr_perl5_message_count_positions\n");
	}

	SvUV_set(result, count);

	out:
	if (ret != 0) {
		sv_setsv(result, &PL_sv_undef);
	}
	return result;
}

AV *rrr_perl5_message_get_tag_names (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	AV *array_tags = newAV();

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

	RRR_LL_ITERATE_BEGIN(array, struct rrr_type_value);
		if (node->tag != NULL && *(node->tag) != '\0') {
			av_push(array_tags, newSVpv(node->tag, node->tag_length));
		}
		else {
			av_push(array_tags, newSVpv("", 0));
		}
	RRR_LL_ITERATE_END();

	out:
	if (ret != 0) {
		RRR_MSG_0("Warning: Error in Perl5 get_tag_names while getting values for array tag\n");
		SvREFCNT_dec((SV*)array_tags);
		array_tags = NULL;
	}
	return array_tags;
}

AV *rrr_perl5_message_get_tag_counts (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;

	int ret = 0;

	AV *array_counts = newAV();

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);

	RRR_LL_ITERATE_BEGIN(array, struct rrr_type_value);
		av_push(array_counts, newSVuv(node->element_count));
	RRR_LL_ITERATE_END();

	out:
	if (ret != 0) {
		RRR_MSG_0("Warning: Error in Perl5 get_tag_count while getting counts for array tag\n");
		SvREFCNT_dec((SV*)array_counts);
		array_counts = NULL;
	}
	return array_counts;
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
		return 1;
	}

	// Unsure if error in the script may cause string to become NULL. If not, this should
	// be an RRR_BUG
	if (string == NULL) {
		RRR_MSG_0("String was NULL in __rrr_perl5_debug_print\n");
		return 1;
	}

	if (always_print) {
		RRR_MSG_X(debuglevel, "%s", string);
	}
	else {
		RRR_DBG_X(debuglevel, "%s", string);
	}

	return 0;
}

int rrr_perl5_debug_msg (HV *debug, int debuglevel, const char *string) {
	return (__rrr_perl5_debug_print(debug, debuglevel, string, 1) == 0 ? TRUE : FALSE); // 1 = Always print
}

int rrr_perl5_debug_dbg (HV *debug, int debuglevel, const char *string) {
	return (__rrr_perl5_debug_print(debug, debuglevel, string, 0) == 0 ? TRUE : FALSE); // 0 = Print if debuglevel is active
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
