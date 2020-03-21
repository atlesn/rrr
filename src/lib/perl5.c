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

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>

#include <EXTERN.h>
#include <perl.h>

#include "../global.h"
#include "../../build_directory.h"
#include "common.h"
#include "perl5.h"
#include "messages.h"
#include "settings.h"
#include "rrr_socket_msg.h"
#include "rrr_strerror.h"

#define RRR_PERL5_BUILD_LIB_PATH_1 \
	RRR_BUILD_DIR "/src/perl5/xsub/lib/rrr/"

#define RRR_PERL5_BUILD_LIB_PATH_2 \
	RRR_BUILD_DIR "/src/perl5/xsub/lib/"

#define RRR_PERL5_BUILD_LIB_PATH_3 \
	RRR_BUILD_DIR "/src/perl5/xsub/blib/arch/auto/rrr/rrr_helper/rrr_message/"

#define RRR_PERL5_BUILD_LIB_PATH_4 \
	RRR_BUILD_DIR "/src/perl5/xsub/blib/arch/auto/rrr/rrr_helper/rrr_settings/"

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
		RRR_MSG_ERR("Warning: perl5 users was not 0 at program exit in rrr_perl5_program_exit_sys_term\n");
	}

	__rrr_perl5_init_unlock();
}

int rrr_perl5_init3(int argc, char **argv, char **env) {
	__rrr_perl5_init_lock();

	if (++perl5_users == 1 && perl5_initialized == 0) {
		// We do not cart PERL_SYS_TERM untill RRR actually exits
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
		RRR_MSG_ERR("Could not allocate perl5 interpreter in rrr_perl5_construct\n");
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
		int (*send_message) (struct rrr_message *message, void *private_data),
		char *(*get_setting) (const char *key, void *private_data),
		int (*set_setting) (const char *key, const char *value, void *private_data)
) {
	int ret = 0;
	struct rrr_perl5_ctx *ctx = NULL;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		RRR_MSG_ERR("Could not allocate memory in rrr_perl5_new_ctx\n");
		ret = 1;
		goto out;
	}
	memset (ctx, '\0', sizeof(*ctx));

	ctx->interpreter = __rrr_perl5_construct();
	if (ctx->interpreter == NULL) {
		RRR_MSG_ERR("Could not create perl5 interpreter in rrr_perl5_new_ctx\n");
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

static void __rrr_perl5_xs_init(pTHX) {
	xs_init(my_perl);
}

int rrr_perl5_ctx_parse (struct rrr_perl5_ctx *ctx, char *filename) {
	int ret = 0;

	PERL_SET_CONTEXT(ctx->interpreter);

	// Test-open file
	int fd = open(filename, O_RDONLY);
	if (fd < 1) {
		RRR_MSG_ERR("Could not open perl5 file %s: %s\n",
				filename, rrr_strerror(errno));
		ret = 1;
		goto out;
	}
	close(fd);

	char *args[] = {
			"",
			"-I" RRR_PERL5_BUILD_LIB_PATH_1,
			"-I" RRR_PERL5_BUILD_LIB_PATH_2,
			"-I" RRR_PERL5_BUILD_LIB_PATH_3,
			"-I" RRR_PERL5_BUILD_LIB_PATH_4,
			filename,
			NULL
	};

	if (perl_parse(ctx->interpreter, __rrr_perl5_xs_init, 6, args, (char**) NULL) != 0) {
		RRR_MSG_ERR("Could not parse perl5 file %s\n", filename);
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
		RRR_MSG_ERR("Error while calling perl5 function: %s\n", SvPV_nolen(err_tmp));
		ret_tmp = POPs;
		ret = 1;
	}
	else if (numitems == 1) {
		// Perl subs should return 1 on success
		ret_tmp = POPs;
		if (!(SvTRUE(ret_tmp))) {
			RRR_MSG_ERR("perl5 sub %s did not return true (false/0)\n", sub);
			ret = 1;
		}
	}
	else {
		RRR_MSG_ERR("No return value from perl5 sub %s\n", sub);
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


struct rrr_perl5_message_hv *__rrr_perl5_allocate_message_hv (struct rrr_perl5_ctx *ctx, HV *hv) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    struct rrr_perl5_message_hv *message_hv = malloc(sizeof(*message_hv));
    if (message_hv == NULL) {
    	RRR_MSG_ERR("Could not allocate memory in rrr_perl5_message_allocate_hv\n");
    	goto out;
    }

    int use_old_data;
    if (hv != NULL) {
    	use_old_data = 1;
    }
    else {
    	hv = newHV();
    	use_old_data = 0;
    }

	message_hv->hv = hv;

    SV **tmp;

    tmp = hv_fetch(message_hv->hv, "type", strlen("type"), 1);
    message_hv->type = *tmp;

    tmp = hv_fetch(message_hv->hv, "class", strlen("class"), 1);
    message_hv->class = *tmp;

    tmp = hv_fetch(message_hv->hv, "timestamp_from", strlen("timestamp_from"), 1);
    message_hv->timestamp_from = *tmp;

    tmp = hv_fetch(message_hv->hv, "timestamp_to", strlen("timestamp_to"), 1);
    message_hv->timestamp_to = *tmp;

    tmp = hv_fetch(message_hv->hv, "data_numeric", strlen("data_numeric"), 1);
    message_hv->data_numeric = *tmp;

    tmp = hv_fetch(message_hv->hv, "data_length", strlen("data_length"), 1);
    message_hv->data_length = *tmp;

    if (use_old_data) {
        tmp = hv_fetch(message_hv->hv, "data", strlen("data"), 1);
        message_hv->data = *tmp;

        tmp = hv_fetch(message_hv->hv, "topic", strlen("topic"), 1);
        message_hv->topic = *tmp;
    }
    else {
    	message_hv->data = newSV(0);
        SvUTF8_off(message_hv->data);
    	sv_setpvn(message_hv->data, "0", 1);
        tmp = hv_store(message_hv->hv, "data", strlen("data"), message_hv->data, 0);
        message_hv->data = *tmp;

    	message_hv->topic = newSV(0);
        SvUTF8_on(message_hv->topic);
    	sv_setpvn(message_hv->topic, "0", 1);
        tmp = hv_store(message_hv->hv, "topic", strlen("topic"), message_hv->topic, 0);
        message_hv->topic = *tmp;
    }

    out:
    return message_hv;
}

struct rrr_perl5_message_hv *rrr_perl5_allocate_message_hv (struct rrr_perl5_ctx *ctx) {
	return __rrr_perl5_allocate_message_hv(ctx, NULL);
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
		VL_MSG_ERR("Could not allocate memory in __rrr_perl5_settings_to_hv_expand\n");
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
		VL_MSG_ERR("Could not allocate memory in __rrr_perl5_settings_to_hv_expand\n");
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
    	VL_MSG_ERR("Could not allocate memory in __rrr_perl5_settings_to_hv_callback\n");
    	ret = 1;
    	goto out;
    }

    if (rrr_settings_setting_to_string_nolock(&new_value, setting) != 0) {
    	VL_MSG_ERR("Could not get value of setting in __rrr_perl5_settings_to_hv_callback\n");
    	ret = 1;
    	goto out;
    }

	new_entry = newSV(strlen(new_value));
	sv_setpvn(new_entry, new_value, strlen(new_value));
    tmp = hv_store(settings_hv->hv, new_key, strlen(new_key), new_entry, 0);
    if (tmp == NULL) {
    	VL_MSG_ERR("Could not store entry into hv in __rrr_perl5_settings_to_hv_callback\n");
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
		RRR_MSG_ERR("Could not allocate memory in rrr_perl5_config_to_hv\n");
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
		VL_MSG_ERR("Error while converting instance settings to hv in perl5\n");
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

int rrr_perl5_hv_to_message (
		struct rrr_message **target_final,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	int ret = 0;

	struct rrr_message *target = *target_final;

	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	STRLEN new_data_len = 0;
	SvUTF8_off(source->data);
	char *data_str = SvPVbyte_force(source->data, new_data_len);

	STRLEN new_topic_len = 0;
	SvUTF8_on(source->topic);
	char *topic_str = SvPVutf8_force(source->topic, new_topic_len);

	RRR_DBG_3("Perl new hv_to_message reported size of data %lu returned size of data %lu\n",
			SvUV(source->data_length), new_data_len);

    ssize_t old_total_len = MSG_TOTAL_SIZE(target);

    target->topic_length = new_topic_len;
    target->msg_size =
    		MSG_TOTAL_SIZE(target) -
    		MSG_DATA_LENGTH(target) -
			MSG_TOPIC_LENGTH(target) +
			new_data_len +
			new_topic_len;
    target->network_size = target->msg_size;

	if (MSG_TOTAL_SIZE(target) > old_total_len) {
		struct rrr_message *new_message = realloc(target, MSG_TOTAL_SIZE(target));
		if (new_message == NULL) {
			RRR_MSG_ERR("Could not re-allocate memory in rrr_perl5_hv_to_message\n");
			ret = 1;
			goto out;
		}
		target = new_message;
	}

	target->type = SvUV(source->type);
	target->class = SvUV(source->class);
	target->timestamp_from = SvUV(source->timestamp_from);
	target->timestamp_to = SvUV(source->timestamp_to);
	target->data_numeric = SvUV(source->data_numeric);

	memcpy (MSG_TOPIC_PTR(target), topic_str, new_topic_len);
	memcpy (MSG_DATA_PTR(target), data_str, new_data_len);

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

	*target_final = target;

	out:
	return ret;
}

int rrr_perl5_message_to_hv (
		struct rrr_perl5_message_hv *message_hv,
		struct rrr_perl5_ctx *ctx,
		struct rrr_message *message
) {
	int ret = 0;

	if (!RRR_SOCKET_MSG_IS_RRR_MESSAGE(message)) {
		RRR_BUG("Message to rrr_perl5_message_to_hv was not a VL message\n");
	}

	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    sv_setuv(message_hv->type, message->type);
    sv_setuv(message_hv->class, message->class);
    sv_setuv(message_hv->timestamp_from, message->timestamp_from);
    sv_setuv(message_hv->timestamp_to, message->timestamp_to);
    sv_setuv(message_hv->data_numeric, message->data_numeric);
    sv_setpvn(message_hv->topic, MSG_TOPIC_PTR(message), MSG_TOPIC_LENGTH(message));
    sv_setuv(message_hv->data_length, MSG_DATA_LENGTH(message));
    sv_setpvn(message_hv->data, MSG_DATA_PTR(message), MSG_DATA_LENGTH(message));

    out:
	return ret;
}

int rrr_perl5_message_to_new_hv (
		struct rrr_perl5_message_hv **target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_message *message
) {
    int ret = 0;

    struct rrr_perl5_message_hv *message_hv = rrr_perl5_allocate_message_hv(ctx);
    if (message_hv == NULL) {
    	ret = 1;
    	goto out;
    }

    if ((ret = rrr_perl5_message_to_hv(message_hv, ctx, message)) != 0) {
    	RRR_MSG_ERR("Error in rrr_perl5_message_to_new_hv\n");
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

	SvREFCNT_inc(hv);

	struct rrr_perl5_message_hv *message_new_hv = __rrr_perl5_allocate_message_hv (ctx, hv);
	struct rrr_message *message_new = rrr_message_new_reading(0, 0);
	if (rrr_perl5_hv_to_message(&message_new, ctx, message_new_hv) != 0) {
		return FALSE;
	}

	// Takes ownership of memory
	ctx->send_message(message_new, ctx->private_data);

	rrr_perl5_destruct_message_hv(ctx, message_new_hv);

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
