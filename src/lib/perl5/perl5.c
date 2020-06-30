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

#include "../posix.h"
#include "perl5.h"
#include "perl5_types.h"

#include "../log.h"
#include "../../build_directory.h"
#include "../common.h"
#include "../messages.h"
#include "../message_addr.h"
#include "../settings.h"
#include "../socket/rrr_socket_msg.h"
#include "../rrr_strerror.h"
#include "../vl_time.h"
#include "../array.h"
#include "../ip.h"

#define RRR_PERL5_BUILD_LIB_PATH_1 \
	RRR_BUILD_DIR "/src/perl5/xsub/lib/rrr/"

#define RRR_PERL5_BUILD_LIB_PATH_2 \
	RRR_BUILD_DIR "/src/perl5/xsub/lib/"

#define RRR_PERL5_BUILD_LIB_PATH_3 \
	RRR_BUILD_DIR "/src/perl5/xsub/blib/arch/auto/rrr/rrr_helper/rrr_message/"

#define RRR_PERL5_BUILD_LIB_PATH_4 \
	RRR_BUILD_DIR "/src/perl5/xsub/blib/arch/auto/rrr/rrr_helper/rrr_settings/"

#define RRR_PERL5_BUILD_LIB_PATH_5 \
	RRR_BUILD_DIR "/src/perl5/xsub/blib/arch/"

static pthread_mutex_t perl5_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t perl5_ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static int perl5_users = 0;
static int perl5_initialized = 0;
static struct rrr_perl5_ctx *first_ctx = NULL;

static void __rrr_perl5_init_lock(void) {
	pthread_mutex_lock(&perl5_init_lock);
}

static void __rrr_perl5_init_unlock(void) {
	pthread_mutex_unlock(&perl5_init_lock);
}

static void __rrr_perl5_ctx_lock(void) {
	pthread_mutex_lock(&perl5_ctx_lock);
}

static void __rrr_perl5_ctx_unlock(void) {
	pthread_mutex_unlock(&perl5_ctx_lock);
}

void rrr_perl5_program_exit_sys_term (void *arg) {
	__rrr_perl5_init_lock();

	(void)(arg);

	if (perl5_initialized != 1) {
		RRR_BUG("perl5_initialized was not 1 in rrr_perl5_program_exit_sys_term\n");
	}

	if (perl5_users == 0) {
		RRR_DBG_1("Perl5 cleaning up at program exit with PERL_SYS_TERM\n");
		PERL_SYS_TERM();
		perl5_initialized = 0;
	}
	else {
		// This might happen if a perl5 thread is ghost
		RRR_MSG_0("Warning: perl5 users was not 0 at program exit in rrr_perl5_program_exit_sys_term\n");
	}

	__rrr_perl5_init_unlock();
}

int rrr_perl5_init3(int argc, char **argv, char **env) {
	__rrr_perl5_init_lock();

	if (++perl5_users == 1 && perl5_initialized == 0) {
		// We do not call PERL_SYS_TERM untill RRR actually exits
		rrr_exit_cleanup_method_push(rrr_perl5_program_exit_sys_term, NULL);
		PERL_SYS_INIT3(&argc, &argv, &env);
		perl5_initialized = 1;
	}

	__rrr_perl5_init_unlock();
	return 0;
}

int rrr_perl5_sys_term(void) {
	__rrr_perl5_init_lock();

	if (--perl5_users == 0) {
		RRR_DBG_1("Last perl5 user done\n");
	}

	__rrr_perl5_init_unlock();
	return 0;
}

static PerlInterpreter *__rrr_perl5_construct(void) {
	PerlInterpreter *ret = NULL;

	__rrr_perl5_init_lock();

	ret = perl_alloc();
	if (ret == NULL) {
		RRR_MSG_0("Could not allocate perl5 interpreter in rrr_perl5_construct\n");
		goto out_unlock;
	}

	perl_construct(ret);
//	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	out_unlock:
	__rrr_perl5_init_unlock();

	out:
	return ret;
}

static void __rrr_perl5_destruct (PerlInterpreter *interpreter) {
	if (interpreter == NULL) {
		return;
	}

	__rrr_perl5_init_lock();
	perl_destruct(interpreter);
	perl_free(interpreter);
	__rrr_perl5_init_unlock();
}

static void __rrr_perl5_push_ctx (struct rrr_perl5_ctx *ctx) {
	__rrr_perl5_ctx_lock();

	ctx->next = first_ctx;
	first_ctx = ctx;

	__rrr_perl5_ctx_unlock();
}

static void __rrr_perl5_remove_ctx (struct rrr_perl5_ctx *ctx) {
	__rrr_perl5_ctx_lock();

	if (first_ctx == ctx) {
		first_ctx = first_ctx->next;
		goto out;
	}

	struct rrr_perl5_ctx *test = first_ctx;
	while (test) {
		if (test->next == ctx) {
			test->next = test->next->next;
			goto out;
		}
		test = test->next;
	}

	RRR_BUG("Context not found in __rrr_perl5_remove_ctx\n");

	out:
	__rrr_perl5_ctx_unlock();
}

static struct rrr_perl5_ctx *__rrr_perl5_find_ctx (const PerlInterpreter *interpreter) {
	__rrr_perl5_ctx_lock();

	struct rrr_perl5_ctx *ret = NULL;
	struct rrr_perl5_ctx *test = first_ctx;

	while (test) {
		if (test->interpreter == interpreter) {
			ret = test;
			goto out;
		}
		test = test->next;
	}

	RRR_BUG("Context not found in __rrr_perl5_find_ctx\n");

	out:
	__rrr_perl5_ctx_unlock();
	return ret;
}

void rrr_perl5_destroy_ctx (struct rrr_perl5_ctx *ctx) {
	if (ctx == NULL) {
		return;
	}
	__rrr_perl5_destruct(ctx->interpreter);
	__rrr_perl5_remove_ctx(ctx);
	free(ctx);
}

int rrr_perl5_new_ctx (
		struct rrr_perl5_ctx **target,
		void *private_data,
		int (*send_message) (struct rrr_message *message, const struct rrr_message_addr *message_addr, void *private_data),
		char *(*get_setting) (const char *key, void *private_data),
		int (*set_setting) (const char *key, const char *value, void *private_data)
) {
	int ret = 0;
	struct rrr_perl5_ctx *ctx = NULL;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_perl5_new_ctx\n");
		ret = 1;
		goto out;
	}
	memset (ctx, '\0', sizeof(*ctx));

	ctx->interpreter = __rrr_perl5_construct();
	if (ctx->interpreter == NULL) {
		RRR_MSG_0("Could not create perl5 interpreter in rrr_perl5_new_ctx\n");
		ret = 1;
		goto out;
	}

	ctx->private_data = private_data;
	ctx->send_message = send_message;
	ctx->get_setting = get_setting;
	ctx->set_setting = set_setting;

	__rrr_perl5_push_ctx(ctx);

	*target = ctx;

	out:
	if (ret != 0 && ctx != NULL) {
		rrr_perl5_destroy_ctx (ctx);
	}
	return ret;
}

/* From perl5_xsi.c generated by configure */
EXTERN_C void xs_init (pTHX);

//static void __rrr_perl5_xs_init(pTHX) {
//	xs_init(my_perl);
//}

int rrr_perl5_ctx_parse (struct rrr_perl5_ctx *ctx, char *filename, int include_build_dirs) {
	int ret = 0;

	PERL_SET_CONTEXT(ctx->interpreter);

	// Test-open file
	int fd = open(filename, O_RDONLY);
	if (fd < 1) {
		RRR_MSG_0("Could not open perl5 file %s: %s\n",
				filename, rrr_strerror(errno));
		ret = 1;
		goto out;
	}
	close(fd);

	// WHEN CHANGING, COUNT ARGC AT LEAST THREE TIMES. THEN COUNT AGAIN.

	char *argv_with_build_dirs[] = {
			"",
			"-I" RRR_PERL5_BUILD_LIB_PATH_1,
			"-I" RRR_PERL5_BUILD_LIB_PATH_2,
			"-I" RRR_PERL5_BUILD_LIB_PATH_3,
			"-I" RRR_PERL5_BUILD_LIB_PATH_4,
			"-I" RRR_PERL5_BUILD_LIB_PATH_5,
			filename,
			NULL
	};
	int argc_with_build_dirs = 7;

	char *argv_plain[] = {
			"",
			filename,
			NULL
	};
	int argc_plain = 2;

	char **argv_to_use = NULL;
	int argc_to_use = 0;

	if (include_build_dirs) {
		argv_to_use = argv_with_build_dirs;
		argc_to_use = argc_with_build_dirs;
	}
	else {
		argv_to_use = argv_plain;
		argc_to_use = argc_plain;
	}

	RRR_DBG_1("Parsing perl5 file '%s', argc: %i\n", filename, argc_to_use);

	if (perl_parse(ctx->interpreter, xs_init, argc_to_use, argv_to_use, (char**) NULL) != 0) {
		RRR_MSG_0("Could not parse perl5 file %s\n", filename);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}


int rrr_perl5_ctx_run (struct rrr_perl5_ctx *ctx) {
	PERL_SET_CONTEXT(ctx->interpreter);
	return perl_run(ctx->interpreter);
}

int rrr_perl5_call_blessed_hvref (struct rrr_perl5_ctx *ctx, const char *sub, const char *class, HV *hv) {
	int ret = 0;

	SV *err_tmp = NULL;
	SV *ret_tmp = NULL;
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    HV *stash = gv_stashpv(class, GV_ADD);
    if (stash == NULL) {
    	RRR_BUG("No stash HV returned in rrr_perl5_call_blessed_hvref\n");
    }

    SV *ref = newRV_inc((SV*) hv);
    if (ref == NULL) {
    	RRR_BUG("No ref SV returned in rrr_perl5_call_blessed_hvref\n");
    }

    SV *blessed_ref = sv_bless(ref, stash);
    if (blessed_ref == NULL) {
    	RRR_BUG("No blessed ref SV returned in rrr_perl5_call_blessed_hvref\n");
    }

//    printf ("A: Blessed a reference, package is %s\n", HvNAME(stash));
//    printf ("B: Blessed a reference, package is %s\n", HvNAME(SvSTASH(SvRV(blessed_ref))));

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	EXTEND(SP, 1);
	PUSHs(sv_2mortal(blessed_ref));
	PUTBACK;

	int numitems = call_pv(sub, G_SCALAR|G_EVAL);

	SPAGAIN;

	err_tmp = ERRSV;

	if ((SvTRUE(err_tmp))) {
		RRR_MSG_0("Error while calling perl5 function: %s\n", SvPV_nolen(err_tmp));
		ret_tmp = POPs;
		ret = 1;
	}
	else if (numitems == 1) {
		// Perl subs should return 1 on success
		ret_tmp = POPs;
		if (!(SvTRUE(ret_tmp))) {
			RRR_MSG_0("perl5 sub %s did not return true (false/0)\n", sub);
			ret = 1;
		}
	}
	else {
		RRR_MSG_0("No return value from perl5 sub %s\n", sub);
		ret = 1;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret;
}
/*
#define QUOTE(str) \
        "\"" #str "\""

#define PASTE(a,b) \
        a ## b
*/
#define SV_DEC_UNLESS_NULL(sv) \
	do {if (sv != NULL) { SvREFCNT_dec((SV*)sv); }} while (0)


#define DEFINE_SCALAR_FIELD(name)																	\
	    do {tmp = hv_fetch(message_hv->hv, RRR_QUOTE(name), strlen(RRR_QUOTE(name)), 1);			\
	    if (tmp == NULL || *tmp == NULL) {															\
	    	RRR_MSG_0("Could not allocate scalar in hv in __rrr_perl5_allocate_message_hv\n");	\
	    	goto out_error;																			\
		}} while (0)

// TODO : Consider removing this struct, it only has one field
struct rrr_perl5_message_hv *__rrr_perl5_allocate_message_hv_with_hv (struct rrr_perl5_ctx *ctx, HV *hv) {
    struct rrr_perl5_message_hv *message_hv = malloc(sizeof(*message_hv));
    if (message_hv == NULL) {
    	RRR_MSG_0("Could not allocate memory in rrr_perl5_message_allocate_hv\n");
    	return NULL;
    }
    memset(message_hv, '\0', sizeof(*message_hv));
    message_hv->hv = hv;
    return message_hv;
}

struct rrr_perl5_message_hv *__rrr_perl5_allocate_message_hv (struct rrr_perl5_ctx *ctx) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    HV *hv = NULL;

    struct rrr_perl5_message_hv *message_hv = malloc(sizeof(*message_hv));
    if (message_hv == NULL) {
    	RRR_MSG_0("Could not allocate memory in rrr_perl5_message_allocate_hv\n");
    	goto out;
    }

    hv = newHV();
	message_hv->hv = hv;

    SV **tmp;

    DEFINE_SCALAR_FIELD(type_and_class);
    DEFINE_SCALAR_FIELD(timestamp);
    DEFINE_SCALAR_FIELD(topic);
    DEFINE_SCALAR_FIELD(data);
    DEFINE_SCALAR_FIELD(data_length);
    DEFINE_SCALAR_FIELD(ip_addr);
    DEFINE_SCALAR_FIELD(ip_addr_len);
    DEFINE_SCALAR_FIELD(ip_so_type);

	SV *data = newSV(0);
	SvUTF8_off(data);
	sv_setpvn(data, "0", 1);
	tmp = hv_store(message_hv->hv, "data", strlen("data"), data, 0);
	if (tmp == NULL || *tmp != data) {
		RRR_MSG_0("Could not allocate field 'data' in hv in __rrr_perl5_allocate_message_hv\n");
		goto out_error;
	}

	SV *topic = newSV(0);
	SvUTF8_on(topic);
	sv_setpvn(topic, "0", 1);
	tmp = hv_store(message_hv->hv, "topic", strlen("topic"), topic, 0);
	if (tmp == NULL || *tmp != topic) {
		RRR_MSG_0("Could not allocate field 'data' in hv in __rrr_perl5_allocate_message_hv\n");
		goto out_error;
	}

    // Don't define the array types here

    goto out;
    out_error:
		rrr_perl5_destruct_message_hv(ctx, message_hv);
		message_hv = NULL;
    out:
    	return message_hv;
}

struct rrr_perl5_message_hv *rrr_perl5_allocate_message_hv (struct rrr_perl5_ctx *ctx) {
	return __rrr_perl5_allocate_message_hv(ctx);
}

void rrr_perl5_destruct_settings_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_settings_hv *source
) {
	if (source == NULL) {
		return;
	}

	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	SV_DEC_UNLESS_NULL(source->hv);
	source->hv = NULL;

	RRR_FREE_IF_NOT_NULL(source->entries);

	for (int i = 0; i < source->allocated_entries; i++) {
		RRR_FREE_IF_NOT_NULL(source->keys[i]);
	}

	RRR_FREE_IF_NOT_NULL(source->keys);
	source->allocated_entries = 0;
	source->used_entries = 0;

	free(source);
}

/*
struct rrr_perl5_settings_to_hv_callback_args {
	struct rrr_perl5_ctx *ctx;
	struct rrr_perl5_settings_hv *settings_hv;
};

static int __rrr_perl5_settings_to_hv_expand(struct rrr_perl5_settings_hv *settings_hv) {
	int ret = 0;

    if (settings_hv->allocated_entries > settings_hv->used_entries) {
    	goto out;
    }

    SV **new_entries = reallocarray (
			settings_hv->entries,
			settings_hv->allocated_entries + 1,
			sizeof(*(settings_hv->entries))
	);
	if (new_entries == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_perl5_settings_to_hv_expand\n");
		ret = 1;
		goto out;
	}
	settings_hv->entries = new_entries;

	char **new_keys = reallocarray (
			settings_hv->keys,
			settings_hv->allocated_entries + 1,
			sizeof(*(settings_hv->keys))
	);
	if (new_keys == NULL) {
		RRR_MSG_0("Could not allocate memory in __rrr_perl5_settings_to_hv_expand\n");
		ret = 1;
		goto out;
	}
	settings_hv->keys = new_keys;

	settings_hv->allocated_entries++;

	out:
	return ret;
}

static int __rrr_perl5_settings_to_hv_callback (
		struct rrr_setting *setting,
		void *arg
) {
	int ret = 0;

	SV *new_entry;
	SV **tmp;
	char *new_key;
	char *new_value;

	struct rrr_perl5_settings_to_hv_callback_args *args = arg;
	struct rrr_perl5_ctx *ctx = args->ctx;
	struct rrr_perl5_settings_hv *settings_hv = args->settings_hv;

	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    if (__rrr_perl5_settings_to_hv_expand(settings_hv) != 0) {
    	ret = 1;
    	goto out;
    }

    new_key = malloc(strlen(setting->name) + 1);
    if (new_key == NULL) {
    	RRR_MSG_0("Could not allocate memory in __rrr_perl5_settings_to_hv_callback\n");
    	ret = 1;
    	goto out;
    }

    if (rrr_settings_setting_to_string_nolock(&new_value, setting) != 0) {
    	RRR_MSG_0("Could not get value of setting in __rrr_perl5_settings_to_hv_callback\n");
    	ret = 1;
    	goto out;
    }

	new_entry = newSV(strlen(new_value));
	sv_setpvn(new_entry, new_value, strlen(new_value));
    tmp = hv_store(settings_hv->hv, new_key, strlen(new_key), new_entry, 0);
    if (tmp == NULL) {
    	RRR_MSG_0("Could not store entry into hv in __rrr_perl5_settings_to_hv_callback\n");
    	ret = 1;
    	goto out;
    }

    settings_hv->entries[settings_hv->used_entries] = *tmp;
    settings_hv->keys[settings_hv->used_entries] = new_key;

    settings_hv->used_entries++;

    new_entry = NULL;
    new_key = NULL;

    out:
	SV_DEC_UNLESS_NULL(new_entry);
	RRR_FREE_IF_NOT_NULL(new_key);
	RRR_FREE_IF_NOT_NULL(new_value);
    return ret;
}
*/

int rrr_perl5_settings_to_hv (
		struct rrr_perl5_settings_hv **target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_instance_settings *source
) {
	int ret = 0;

	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	struct rrr_perl5_settings_hv *settings_hv = malloc(sizeof(*settings_hv));
	if (settings_hv == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_perl5_config_to_hv\n");
		ret = 1;
		goto out;
	}
	memset (settings_hv, '\0', sizeof(*settings_hv));

	settings_hv->hv = newHV();

/* TODO:	We don't actually fill up the HV but instead force the user to utilize the
 * 			get()-method so that we can update was_used-parameter, maybe delete the following

	struct rrr_perl5_settings_to_hv_callback_args callback_args = {
			ctx, settings_hv
	};
	ret = rrr_settings_iterate(source, __rrr_perl5_settings_to_hv_callback, &callback_args);
	if (ret != 0) {
		RRR_MSG_0("Error while converting instance settings to hv in perl5\n");
		goto out;
	}*/

	*target = settings_hv;

	out:
	if (ret != 0) {
		rrr_perl5_destruct_settings_hv(ctx, settings_hv);
	}
	return ret;
}

void rrr_perl5_destruct_message_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	if (source == NULL) {
		return;
	}

	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	SV_DEC_UNLESS_NULL(source->hv);

	free(source);
}

static SV *__rrr_perl5_deep_dereference(SV *sv) {
	int max = 50;
	while (SvROK(sv)) {
		sv = SvRV(sv);
		if (--max == 0) {
			RRR_MSG_0("Too many nested references (50 or more) in _rrr_perl5_deep_dereference\n");
			return NULL;
		}
	}
	return sv;
}

static int __rrr_perl5_hv_to_message_array_store_field (
		struct rrr_array *target,
		struct rrr_perl5_ctx *ctx,
		SV *values,
		SV *tag,
		SV *type
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    struct rrr_type_value *new_value = NULL;
    AV *temporary_av = NULL;

    int ret = 0;

    STRLEN type_len = 0;
    char *type_str = SvPV_force(type, type_len);
    if (type_str == NULL || type_len == 0) {
    	RRR_MSG_0("Could not read a type field from control array or length was 0 in __rrr_perl5_hv_to_message_array_store_field\n");
    	ret = 1;
    	goto out;
    }

    const struct rrr_perl5_type_definition *type_def = rrr_perl5_type_get_from_name(type_str);
    if (type_def == NULL) {
    	RRR_MSG_0("Could not find a definition for type '%s' while converting from perl5 array, please check spelling\n", type_str);
    	ret = 1;
    	goto out;
    }

    if (type_def->to_value == NULL) {
    	RRR_MSG_0("Type %s cannot be used in arrays in perl5 scripts, no conversion method available.\n", type_str);
    	ret = 1;
    	goto out;
    }

    if ((values = __rrr_perl5_deep_dereference(values)) == NULL) {
    	RRR_MSG_0("Could not dereference value in __rrr_perl5_hv_to_message_array_store_field\n");
    	ret = 1;
    	goto out;
    }

    if (SvTYPE(values) != SVt_PVAV) {
    	// Some value has probably been pushed directly onto the control array. We assume that we want to
    	// have only one value set. Create a temporary AV and put the value in it.
    	temporary_av = newAV();
    	av_push(temporary_av, values);
    	SvREFCNT_inc(values);
    }

    if ((ret = type_def->to_value (&new_value, ctx, type_def->definition, (temporary_av != NULL ? temporary_av : (AV *) values))) != 0) {
    	RRR_MSG_0("Could not convert perl5 array item, result was %i\n", ret);
    	ret = 1;
    	goto out;
    }

    STRLEN tag_len;
    char *tag_str = SvPVutf8_force(tag, tag_len);
    if (tag_len > 0) {
		if (rrr_type_value_set_tag(new_value, tag_str, tag_len) != 0) {
			RRR_MSG_0("Could not set tag in __rrr_perl5_hv_to_message_array_store_field\n");
			ret = 1;
			goto out;
		}
    }

    RRR_LL_APPEND(target, new_value);
    new_value = NULL;

    out:
	if (temporary_av != NULL) {
		SvREFCNT_dec(temporary_av);
	}
	if (new_value != NULL) {
		rrr_type_value_destroy(new_value);
	}
    return ret;
}

#define DEFINE_AND_FETCH_FROM_HV(name,hv_name)										\
	SV *name = NULL;																\
	do {SV **tmp = hv_fetch(hv, RRR_QUOTE(name), strlen(RRR_QUOTE(name)), 1);		\
		if (tmp == NULL || *tmp == NULL) {											\
			RRR_MSG_0("Could not fetch SV from HV\n");							\
			ret = 1; goto out;														\
		}																			\
		name = *tmp; (void)(name);													\
	} while(0)

#define CHECK_IS_AV(name)																						\
	do {if (SvTYPE(name) != SVt_PVAV) {																			\
		check_av_error_count++;																					\
		RRR_MSG_0("Warning: " RRR_QUOTE(name) " was not a perl array while extracting array from perl5\n");	\
	}} while (0)

#define DEFINE_AND_FETCH_FROM_AV(name,av_name,i)													\
	SV *name = NULL;																				\
	do {SV **tmp = av_fetch(av_name, i, 1);															\
	if (tmp == NULL || *tmp == NULL) {																\
		RRR_MSG_0("Could not fetch SV from array in __rrr_perl5_hv_to_message_extract_array\n");	\
		ret = 1;																					\
		goto out;																					\
	}																								\
	name = *tmp; } while(0)

static int __rrr_perl5_hv_to_message_extract_array (
		struct rrr_message **target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	struct rrr_message *message_tmp = NULL;
	struct rrr_array array_tmp = {0};
	HV *hv = source->hv;

	DEFINE_AND_FETCH_FROM_HV(array_values, hv);
	DEFINE_AND_FETCH_FROM_HV(array_tags, hv);
	DEFINE_AND_FETCH_FROM_HV(array_types, hv);

	AV *array_values_final = (AV *) __rrr_perl5_deep_dereference(array_values);
	AV *array_tags_final = (AV *) __rrr_perl5_deep_dereference(array_tags);
	AV *array_types_final = (AV *) __rrr_perl5_deep_dereference(array_types);

	if (array_values_final == NULL || array_tags_final == NULL || array_types_final == NULL) {
		RRR_MSG_0("Could not dereference one or more control array values in __rrr_perl5_hv_to_message_extract_array\n");
		ret = 1;
		goto out;
	}

	int check_av_error_count = 0;
	CHECK_IS_AV(array_values_final);
	CHECK_IS_AV(array_tags_final);
	CHECK_IS_AV(array_types_final);

	if (check_av_error_count == 0) {
		// OK, all of the arrays are actually AVs. Continue.
	}
	else if (check_av_error_count == 3) {
		// OK, but some warnings have been produced
		ret = 0;
		goto out;
	}
	else {
		RRR_MSG_0("Could not extract array from perl5: %i of the control arrays were not set correctly. All of them must be either set or unset.\n", check_av_error_count);
		ret = 1;
		goto out;
	}

	if (av_len(array_values_final) != av_len(array_tags_final) || av_len(array_values_final) != av_len(array_types_final)) {
		RRR_MSG_0("Could not extract array from perl5: The three control arrays array_values, array_tags" \
				"and array_types did not have the same number of elements (%li, %li and %li)\n",
				av_len(array_values_final),  av_len(array_tags_final), av_len(array_types_final));
		ret = 1;
		goto out;
	}

	// av_len returns -1 when array is empty
	if (av_len(array_values_final) < 0) {
		// No array values
		ret = 0;
		goto out;
	}

	// av_len returns index of last item, use <=
	for (int i = 0; i <= av_len(array_values_final); i++) {
		SV **tmp;

		DEFINE_AND_FETCH_FROM_AV(value, array_values_final, i);
		DEFINE_AND_FETCH_FROM_AV(tag, array_tags_final, i);
		DEFINE_AND_FETCH_FROM_AV(type, array_types_final, i);

		if (__rrr_perl5_hv_to_message_array_store_field(&array_tmp, ctx, value, tag, type) != 0) {
			RRR_MSG_0("Could not store field from array in __rrr_perl5_hv_to_message_extract_array\n");
			ret = 1;
			goto out;
		}
	}

	if (rrr_array_new_message_from_collection (
			&message_tmp,
			&array_tmp,
			0,
			MSG_TOPIC_PTR(*target),
			MSG_TOPIC_LENGTH(*target)
	) != 0) {
		RRR_MSG_0("Could not create new array message in _rrr_perl5_hv_to_message_extract_array\n");
		ret = 1;
		goto out;
	}

	message_tmp->timestamp = (*target)->timestamp;

	free (*target);
	*target = message_tmp;
	message_tmp = NULL;

	out:
	if (message_tmp != NULL) {
		free(message_tmp);
	}
	rrr_array_clear(&array_tmp);
	return ret;
}

int rrr_perl5_hv_to_message (
		struct rrr_message **target_final,
		struct rrr_message_addr *target_addr,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	struct rrr_message *target = *target_final;
	HV *hv = source->hv;

	DEFINE_AND_FETCH_FROM_HV(data, hv);
	DEFINE_AND_FETCH_FROM_HV(data_length, hv);
	DEFINE_AND_FETCH_FROM_HV(topic, hv);

	STRLEN new_data_len = 0;
	SvUTF8_off(data);
	char *data_str = SvPVbyte_force(data, new_data_len);

	STRLEN new_topic_len = 0;
	SvUTF8_on(topic);
	char *topic_str = SvPVutf8_force(topic, new_topic_len);

	RRR_DBG_3("Perl new hv_to_message reported size of data %lu returned size of data %lu\n",
			SvUV(data_length), new_data_len);

    ssize_t old_total_len = MSG_TOTAL_SIZE(target);

    target->topic_length = new_topic_len;
    target->msg_size =
    		MSG_TOTAL_SIZE(target) -
    		MSG_DATA_LENGTH(target) -
			MSG_TOPIC_LENGTH(target) +
			new_data_len +
			new_topic_len;

    rrr_message_addr_init(target_addr);

	DEFINE_AND_FETCH_FROM_HV(ip_so_type, hv);

	STRLEN ip_so_type_len = 0;
	char *so_type_str = SvPVutf8_force(ip_so_type, ip_so_type_len);

	int protocol = RRR_IP_AUTO;

	if (ip_so_type_len == 0) {
		// Not specified
	}
	else if (ip_so_type_len >= 3) {
		if (rrr_posix_strncasecmp("udp", so_type_str, 3) == 0) {
			protocol = RRR_IP_UDP;
		}
		else if (rrr_posix_strncasecmp("tcp", so_type_str, 3) == 0) {
			protocol = RRR_IP_TCP;
		}
		else {
			RRR_MSG_0("Warning: unknown ip_so_type from perl script, must be 'udp' or 'tcp'\n");
		}
	}
	else if (ip_so_type_len < 3) {
		RRR_MSG_0("Warning: ip_so_type from Perl function was too short\n");
	}

	target_addr->protocol = protocol;

	DEFINE_AND_FETCH_FROM_HV(ip_addr_len, hv);

	uint64_t addr_len_tmp = SvUV(ip_addr_len);
	RRR_MSG_ADDR_SET_ADDR_LEN(target_addr, addr_len_tmp);

	if (addr_len_tmp > 0) {
		if (addr_len_tmp > sizeof(target_addr->addr)) {
			RRR_MSG_0("Address length field from message hash was too big (%" PRIu64 " > %lu)\n",
					addr_len_tmp, sizeof(target_addr->addr));
			ret = 1;
			goto out;
		}

		DEFINE_AND_FETCH_FROM_HV(ip_addr, hv);
		SvUTF8_off(ip_addr);
		char *data_str = SvPVbyte_force(ip_addr, addr_len_tmp);
		memcpy(&target_addr->addr, data_str, addr_len_tmp);
	}

	if (MSG_TOTAL_SIZE(target) > old_total_len) {
		struct rrr_message *new_message = realloc(target, MSG_TOTAL_SIZE(target));
		if (new_message == NULL) {
			RRR_MSG_0("Could not re-allocate memory in rrr_perl5_hv_to_message\n");
			ret = 1;
			goto out;
		}
		target = new_message;
	}

	DEFINE_AND_FETCH_FROM_HV(type_and_class, hv);
	DEFINE_AND_FETCH_FROM_HV(timestamp, hv);

	target->type_and_class = SvUV(type_and_class);
	target->timestamp = SvUV(timestamp);

	memcpy (MSG_TOPIC_PTR(target), topic_str, new_topic_len);
	memcpy (MSG_DATA_PTR(target), data_str, new_data_len);

	// This function will re-allocate the message and erase data if array values are set in the perl5 script
	if (__rrr_perl5_hv_to_message_extract_array(&target, ctx, source)) {
		RRR_MSG_0("Error while converting HV to RRR message in rrr_perl5_hv_to_message\n");
		ret = 1;
		goto out;
	}
// TODO : Data must be written to a tmp buffer then logged
/*
	if (RRR_DEBUGLEVEL_3) {
		RRR_DBG("rrr_perl5_hv_to_message output (data of message only): 0x");
		for (unsigned int i = 0; i < MSG_DATA_LENGTH(target); i++) {
			char c = MSG_DATA_PTR(target)[i];
			if (c < 0x10) {
				RRR_DBG("0");
			}
			RRR_DBG("%x", c);
		}
		RRR_DBG("\n");
	}
*/
	*target_final = target;

	out:
	return ret;
}

static int __rrr_perl5_message_hv_create_array (
		SV **result,
		struct rrr_perl5_message_hv *message_hv,
		struct rrr_perl5_ctx *ctx,
		const char *name
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	AV *array_av = newAV();
	SV *array_ref = newRV_noinc((SV *) array_av);
	SV **tmp = hv_store(message_hv->hv, name, strlen(name), array_ref, 0);

    if (*tmp != array_ref) {
    	SvREFCNT_dec(array_ref);
    	return 1;
    }

    *result = *tmp;

    return 0;
}

#define AV_STORE_OR_FREE(target,i,sv)																\
	do { SV *tmp = (sv);																			\
	if (*av_store(target, i, tmp) != tmp) {															\
		RRR_MSG_0("Could not store item array in __rrr_perl5_message_hv_arrays_populate\n");		\
		sv_free(tmp);																				\
		ret = 1;																					\
		goto out;																					\
	}} while (0)

struct store_element_callback_data {
	AV *target_array;
};

static int __rrr_perl5_message_hv_arrays_populate_store_element_callback(RRR_PERL5_TYPE_TO_SV_CALLBACK_ARGS) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    (void)(idx);
    (void)(def_orig);

	struct store_element_callback_data *callback_data = arg;
	av_push(callback_data->target_array, sv);
	SvREFCNT_inc(sv);

	return 0;
}

static int __rrr_perl5_message_hv_arrays_populate (
		struct rrr_perl5_message_hv *message_hv,
		struct rrr_perl5_ctx *ctx,
		const struct rrr_message *message
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	struct rrr_array array_tmp = {0};

	SV *array_values_ref;
	SV *array_tags_ref;
	SV *array_types_ref;

	ret |= __rrr_perl5_message_hv_create_array(&array_values_ref, message_hv, ctx, "array_values");
	ret |= __rrr_perl5_message_hv_create_array(&array_tags_ref, message_hv, ctx, "array_tags");
	ret |= __rrr_perl5_message_hv_create_array(&array_types_ref, message_hv, ctx, "array_types");

	if (ret != 0) {
		RRR_MSG_0("Could not create new arrays in __rrr_perl5_message_hv_arrays_populate\n");
		ret = 1;
		goto out;
	}

	// If the message is not array, we leave the hv alone with empty arrays
    if (!MSG_IS_ARRAY(message)) {
    	goto not_array;
    }

	AV *array_values = (AV*) SvRV(array_values_ref);
	AV *array_tags = (AV*) SvRV(array_tags_ref);
	AV *array_types = (AV*) SvRV(array_types_ref);

	if (rrr_array_message_to_collection(&array_tmp, message) != 0) {
		RRR_MSG_0("Could not convert message to array collection in __rrr_perl5_message_array_populate\n");
		ret = 1;
		goto out;
	}

	if (array_tmp.version != 7) {
		RRR_BUG("Array version mismatch in __rrr_perl5_message_hv_arrays_populate (%u vs %u), perl5 library must be updated\n",
				array_tmp.version, 7);
	}

	int i = 0;
	RRR_LL_ITERATE_BEGIN(&array_tmp, struct rrr_type_value);
		AV *items = newAV();
		AV_STORE_OR_FREE(array_values, i, newRV_noinc((SV*)items));

		const char *tag_to_use = (node->tag != NULL && *(node->tag) != '\0' ? node->tag : "");
		AV_STORE_OR_FREE(array_tags, i, newSVpvn(tag_to_use, strlen(tag_to_use)));

		AV_STORE_OR_FREE(array_types, i, newSVpvn(node->definition->identifier, strlen(node->definition->identifier)));

		const struct rrr_perl5_type_definition *definition = rrr_perl5_type_get_from_id(node->definition->type);

		if (definition == NULL) {
			RRR_MSG_0("Unknown array value type %u in __rrr_perl5_message_hv_arrays_populate\n",
					node->definition->type);
			ret = 1;
			goto out;
		}

		if (definition->to_sv == NULL) {
			RRR_MSG_0("Cannot convert array value type '%s' to SV in __rrr_perl5_message_hv_arrays_populate, unsupported type\n",
					definition->definition->identifier);
			ret = 1;
			goto out;
		}

		// struct rrr_perl5_ctx *ctx, struct rrr_type_value *value, int *(callback)(RRR_PERL5_TYPE_TO_SV_CALLBACK_ARGS), void *callback_arg

		struct store_element_callback_data callback_data = { items };

		if (definition->to_sv(ctx, node, __rrr_perl5_message_hv_arrays_populate_store_element_callback, &callback_data)) {
			RRR_MSG_0("Error while converting value to SV in __rrr_perl5_message_hv_arrays_populate\n");
			ret = 1;
			goto out;
		}

	 	i++;
	RRR_LL_ITERATE_END();

	not_array:
    out:
	rrr_array_clear(&array_tmp);
	return ret;
}

int rrr_perl5_message_to_hv (
		struct rrr_perl5_message_hv *message_hv,
		struct rrr_perl5_ctx *ctx,
		const struct rrr_message *message,
		struct rrr_message_addr *message_addr
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	if (!RRR_SOCKET_MSG_IS_RRR_MESSAGE(message)) {
		RRR_BUG("Message to rrr_perl5_message_to_hv was not a VL message\n");
	}

    HV *hv = message_hv->hv;

	DEFINE_AND_FETCH_FROM_HV(type_and_class, hv);
	DEFINE_AND_FETCH_FROM_HV(timestamp, hv);
	DEFINE_AND_FETCH_FROM_HV(data, hv);
	DEFINE_AND_FETCH_FROM_HV(data_length, hv);
	DEFINE_AND_FETCH_FROM_HV(topic, hv);

	DEFINE_AND_FETCH_FROM_HV(ip_so_type, hv);
	DEFINE_AND_FETCH_FROM_HV(ip_addr, hv);
	DEFINE_AND_FETCH_FROM_HV(ip_addr_len, hv);

    SvUTF8_off(ip_addr);
    SvUTF8_off(data);
    SvUTF8_on(topic);

    // Make sure that every single field is overwritten to avoid that data from any
    // older message is retained
    sv_setuv(type_and_class, message->type_and_class);
    sv_setuv(timestamp, message->timestamp);
    if (MSG_TOPIC_LENGTH(message) > 0) {
    	sv_setpvn(topic, MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message));
    }
    else {
    	sv_setpv(topic, "");
    }
    sv_setuv(data_length, MSG_DATA_LENGTH(message));
    sv_setpvn(data, MSG_DATA_PTR(message), MSG_DATA_LENGTH(message));

    // Must always be called also when message is not an array
	if (__rrr_perl5_message_hv_arrays_populate(message_hv, ctx, message) != 0) {
		RRR_MSG_0("Could not populate arrays in rrr_perl5_message_to_hv\n");
		ret = 1;
		goto out;
	}

	uint64_t addr_len_tmp;
	if (message_addr != NULL && (addr_len_tmp = RRR_MSG_ADDR_GET_ADDR_LEN(message_addr)) > 0) {
		// Perl needs size of sockaddr struct which is smaller than our internal size
		sv_setpvn(ip_addr, (char *) &message_addr->addr, (STRLEN) sizeof(struct sockaddr));
		sv_setuv(ip_addr_len, addr_len_tmp);
	}
	else {
		sv_setpv(ip_addr, "");
		sv_setuv(ip_addr_len, 0);
	}

	// Default value for protocol type is empty
	sv_setpv(ip_so_type, "");

	if (message_addr != NULL && message_addr->protocol != 0) {
		switch (message_addr->protocol) {
			case RRR_IP_UDP:
				sv_setpv(ip_so_type, "udp");
				break;
			case RRR_IP_TCP:
				sv_setpv(ip_so_type, "tcp");
				break;
			default:
				RRR_MSG_0("Warning: Unknown IP protocol type %i in message to perl5\n", message_addr->protocol);
				break;
		};
	}

    out:
	return ret;
}

int rrr_perl5_message_to_new_hv (
		struct rrr_perl5_message_hv **target,
		struct rrr_perl5_ctx *ctx,
		const struct rrr_message *message,
		struct rrr_message_addr *message_addr
) {
    int ret = 0;

    struct rrr_perl5_message_hv *message_hv = rrr_perl5_allocate_message_hv(ctx);
    if (message_hv == NULL) {
    	ret = 1;
    	goto out;
    }

    if ((ret = rrr_perl5_message_to_hv(message_hv, ctx, message, message_addr)) != 0) {
    	RRR_MSG_0("Error in rrr_perl5_message_to_new_hv\n");
    	goto out;
    }

    *target = message_hv;

    out:
	if (ret != 0) {
		rrr_perl5_destruct_message_hv(ctx, message_hv);
	}
    return ret;
}

int rrr_perl5_message_send (HV *hv) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = __rrr_perl5_find_ctx (my_perl);
	struct rrr_perl5_message_hv *message_new_hv = NULL;

	int ret = TRUE;

	SvREFCNT_inc(hv);
	message_new_hv = __rrr_perl5_allocate_message_hv_with_hv (ctx, hv);
	if (message_new_hv == NULL) {
		RRR_MSG_0("Could not allocate message hv in rrr_perl5_message_send\n");
		ret = FALSE;
		goto out;
	}

	struct rrr_message_addr addr_msg;
	struct rrr_message *message_new = NULL;
	if (rrr_message_new_empty(&message_new, MSG_TYPE_MSG, MSG_CLASS_DATA, rrr_time_get_64(), 0, 0) != 0) {
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

SV *rrr_perl5_settings_get (HV *settings, const char *key) {
	PerlInterpreter *my_perl = PERL_GET_CONTEXT;
	struct rrr_perl5_ctx *ctx = __rrr_perl5_find_ctx (my_perl);

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
	struct rrr_perl5_ctx *ctx = __rrr_perl5_find_ctx (my_perl);

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
