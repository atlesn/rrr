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

#include "../util/posix.h"
#include "../log.h"
#include "../allocator.h"
#include "perl5.h"
#include "perl5_types.h"
#include "perl5_hv_macros.h"

#include "../../build_directory.h"
#include "../common.h"
#include "../settings.h"
#include "../rrr_strerror.h"
#include "../array.h"
#include "../messages/msg.h"
#include "../messages/msg_msg.h"
#include "../messages/msg_addr.h"
#include "../ip/ip.h"
#include "../ip/ip_util.h"
#include "../util/rrr_time.h"

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

struct rrr_perl5_ctx *rrr_perl5_find_ctx (const PerlInterpreter *interpreter) {
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

	RRR_BUG("Context not found in rrr_perl5_find_ctx\n");

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
	rrr_free(ctx);
}

int rrr_perl5_new_ctx (
		struct rrr_perl5_ctx **target,
		void *private_data,
		int (*send_message) (const struct rrr_msg_msg *message, const struct rrr_msg_addr *message_addr, void *private_data),
		char *(*get_setting) (const char *key, void *private_data),
		int (*set_setting) (const char *key, const char *value, void *private_data)
) {
	int ret = 0;
	struct rrr_perl5_ctx *ctx = NULL;

	ctx = rrr_allocate(sizeof(*ctx));
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

int rrr_perl5_call_blessed_hvref_and_sv (struct rrr_perl5_ctx *ctx, const char *sub, const char *class, HV *hv, SV *sv) {
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

    //printf ("A: Blessed a reference, package is %s\n", HvNAME(stash));
    //printf ("B: Blessed a reference, package is %s\n", HvNAME(SvSTASH(SvRV(blessed_ref))));

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(blessed_ref);
	if (sv != NULL) {
		XPUSHs(sv);
	}
	PUTBACK;

	int numitems = call_pv(sub, G_SCALAR|G_EVAL);

	SPAGAIN;

	err_tmp = ERRSV;

	if ((SvTRUE(err_tmp))) {
		RRR_MSG_0("Error while calling perl5 function: %s\n", SvPV_nolen(err_tmp));
		ret_tmp = POPs;
		(void)(ret_tmp);
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

    assert(SvREFCNT(hv) == 2);
    SvREFCNT_dec(ref);

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

#define DEFINE_SCALAR_FIELD(name)                                                       \
  do {tmp = hv_fetch(hv, RRR_QUOTE(name), strlen(RRR_QUOTE(name)), 1);                  \
  if (tmp == NULL || *tmp == NULL) {                                                    \
     RRR_MSG_0("Could not allocate scalar in hv in %s\n", __func__);                    \
     goto out_error; \
  }} while (0)

HV *__rrr_perl5_allocate_message_hv (struct rrr_perl5_ctx *ctx) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

    HV *hv = newHV();

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
	tmp = hv_store(hv, "data", strlen("data"), data, 0);
	if (tmp == NULL || *tmp != data) {
		RRR_MSG_0("Could not allocate field 'data' in hv in %s\n", __func__);
		goto out_error;
	}

	SV *topic = newSV(0);
	SvUTF8_on(topic);
	sv_setpvn(topic, "0", 1);
	tmp = hv_store(hv, "topic", strlen("topic"), topic, 0);
	if (tmp == NULL || *tmp != topic) {
		RRR_MSG_0("Could not allocate field 'data' in hv in %s\n", __func__);
		goto out_error;
	}

    // Don't define the array types here

    goto out;
    out_error:
	SV_DEC_UNLESS_NULL(hv);
	return NULL;
    out:
    	return hv;
}

SV *rrr_perl5_deep_dereference(SV *sv) {
	int max = 50;
	while (SvROK(sv)) {
		sv = SvRV(sv);
		if (--max == 0) {
			RRR_MSG_0("Too many nested references (50 or more) in %s\n", __func__);
			return NULL;
		}
	}
	return sv;
}

void rrr_perl5_destruct_settings_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_settings_hv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	SV_DEC_UNLESS_NULL(source->hv);

	RRR_FREE_IF_NOT_NULL(source->entries);

	for (int i = 0; i < source->allocated_entries; i++) {
		RRR_FREE_IF_NOT_NULL(source->keys[i]);
	}

	RRR_FREE_IF_NOT_NULL(source->keys);

	memset(source, '\0', sizeof(*source));
}

void rrr_perl5_destruct_method_sv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_method_sv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	SV_DEC_UNLESS_NULL(source->sv);

	memset(source, '\0', sizeof(*source));
}

void rrr_perl5_destruct_message_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	SV_DEC_UNLESS_NULL(source->hv);

	memset(source, '\0', sizeof(*source));
}

int rrr_perl5_settings_to_hv (
		struct rrr_perl5_settings_hv *target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_instance_settings *source
) {
	int ret = 0;

	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	assert(target->hv == NULL);

	target->hv = newHV();

	out:
	if (ret != 0) {
		rrr_perl5_destruct_settings_hv(ctx, target);
	}
	return ret;
}

int rrr_perl5_method_to_sv (
		struct rrr_perl5_method_sv *target,
		struct rrr_perl5_ctx *ctx,
		const char *method
) {
	int ret = 0;

	PerlInterpreter *my_perl = ctx->interpreter;
	PERL_SET_CONTEXT(my_perl);

	struct rrr_perl5_method_sv *method_sv;

	if ((target->sv = newSVpv(method, strlen(method))) == NULL) {
		RRR_MSG_0("Failed to create method SV in %s\n", __func__);
		ret = 1;
		goto out;
	}

	SvUTF8_on(target->sv);

	out:
	return ret;
}

static int __rrr_perl5_hv_to_message_process_array (
		struct rrr_msg_msg **target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	struct rrr_msg_msg *message_tmp = NULL;
	struct rrr_array array_tmp = {0};
	HV *hv = source->hv;

	RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv);
	if (array != NULL) {
		if (rrr_array_append_from (
				&array_tmp,
				array
		) != 0) {
			RRR_MSG_0("Failed to clone array values in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if (RRR_LL_COUNT(&array_tmp) == 0) {
		// No array values, make sure class does not have array
		// class set in case it had this from earlier.
		MSG_SET_CLASS(*target, MSG_CLASS_DATA);
		ret = 0;
		goto out;
	}

	if (rrr_array_new_message_from_array (
			&message_tmp,
			&array_tmp,
			0,
			MSG_TOPIC_PTR(*target),
			MSG_TOPIC_LENGTH(*target)
	) != 0) {
		RRR_MSG_0("Could not create new array message in %s\n", __func__);
		ret = 1;
		goto out;
	}

	message_tmp->timestamp = (*target)->timestamp;

	rrr_free (*target);
	*target = message_tmp;
	message_tmp = NULL;

	out:
	if (message_tmp != NULL) {
		rrr_free(message_tmp);
	}
	rrr_array_clear(&array_tmp);
	return ret;
}

int rrr_perl5_hv_to_message (
		struct rrr_msg_msg **target_final,
		struct rrr_msg_addr *target_addr,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	struct rrr_msg_msg *target = *target_final;
	HV *hv = source->hv;

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(data, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(data_length, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(topic, hv);

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

    // Sets default address length to 0
    rrr_msg_addr_init(target_addr);

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_so_type, hv);

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
	else {
		RRR_MSG_0("Warning: ip_so_type from Perl function was too short\n");
	}

	target_addr->protocol = protocol;

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr_len, hv);

	uint64_t addr_len_tmp = SvUV(ip_addr_len);
	if (addr_len_tmp > 0) {
		if (addr_len_tmp > sizeof(target_addr->addr)) {
			RRR_MSG_0("Address length field from message was too big (%" PRIu64 " > %lu)\n",
					addr_len_tmp, sizeof(target_addr->addr));
			ret = 1;
			goto out;
		}

		RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr, hv);
		SvUTF8_off(ip_addr);

		STRLEN addr_len_tmp_actual = 0;
		char *data_str = SvPVbyte_force(ip_addr, addr_len_tmp_actual);

		if (addr_len_tmp > addr_len_tmp_actual) {
			RRR_MSG_0("Address length field from message counts more bytes than the size of the address field (%" PRIu64 " > %" PRIu64 ")\n",
					addr_len_tmp, (uint64_t) addr_len_tmp_actual);
			ret = 1;
			goto out;
		}

		// Use specified length from length field, not actual length
		memcpy(&target_addr->addr, data_str, addr_len_tmp);
		RRR_MSG_ADDR_SET_ADDR_LEN(target_addr, addr_len_tmp);

		if (RRR_DEBUGLEVEL_3) {
			char buf[256];
			rrr_ip_to_str(buf, sizeof(buf), (const struct sockaddr *) target_addr->addr, addr_len_tmp);
			const struct sockaddr_in *sockaddr_in = (const struct sockaddr_in *) target_addr->addr;
			RRR_MSG_3("IP address of message from perl script: %s, family: %i\n", buf, sockaddr_in->sin_family);
		}
	}

	if (MSG_TOTAL_SIZE(target) > old_total_len) {
		struct rrr_msg_msg *new_message = rrr_reallocate_group(target, MSG_TOTAL_SIZE(target), RRR_ALLOCATOR_GROUP_MSG);
		if (new_message == NULL) {
			RRR_MSG_0("Could not re-allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		target = new_message;
		*target_final = target; // Make sure caller does not hold old reference
	}

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(type_and_class, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(timestamp, hv);

	target->type_and_class = SvUV(type_and_class);
	target->timestamp = SvUV(timestamp);

	memcpy (MSG_TOPIC_PTR(target), topic_str, new_topic_len);
	memcpy (MSG_DATA_PTR(target), data_str, new_data_len);

	// This function will re-allocate the message and erase data if array values are set in the perl5 script.
	if (__rrr_perl5_hv_to_message_process_array(&target, ctx, source)) {
		RRR_MSG_0("Error while converting HV to RRR message in %s\n", __func__);
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

int rrr_perl5_message_to_hv (
		struct rrr_perl5_message_hv *target,
		struct rrr_perl5_ctx *ctx,
		const struct rrr_msg_msg *message,
		struct rrr_msg_addr *message_addr,
		struct rrr_array *array
) {
	PerlInterpreter *my_perl = ctx->interpreter;
    PERL_SET_CONTEXT(my_perl);

	int ret = 0;

	assert(RRR_MSG_IS_RRR_MESSAGE(message));
	assert(target->hv == NULL);

	if (!RRR_MSG_IS_RRR_MESSAGE(message)) {
		RRR_BUG("Message to %s was not a message\n", __func__);
	}

	HV *hv = newHV();

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(type_and_class, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(timestamp, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(data, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(data_length, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(topic, hv);

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_so_type, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr, hv);
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(ip_addr_len, hv);

	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(rrr_array_ptr, hv);

	SvFLAGS(rrr_array_ptr) &= ~(SVf_PROTECT|SVf_READONLY);
	sv_setiv(rrr_array_ptr, (intptr_t) array);
	if (SvIV(rrr_array_ptr) != (intptr_t) array) {
		RRR_BUG("BUG: RRR array pointer storage failure in %s, possibly a problem on this particular architecture\n", __func__);
	}
	SvFLAGS(rrr_array_ptr) |= SVf_PROTECT|SVf_READONLY;

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

    // New style array handling
    rrr_array_clear(array);
    if (MSG_IS_ARRAY(message)) {
	    	uint16_t array_version_dummy;
		if (rrr_array_message_append_to_array(&array_version_dummy, array, message) != 0) {
			RRR_MSG_0("Could not convert message to array collection in %s\n", __func__);
			ret = 1;
			goto out;
		}
    }

	uint64_t addr_len_tmp;
	if (message_addr != NULL && (addr_len_tmp = RRR_MSG_ADDR_GET_ADDR_LEN(message_addr)) > 0) {
		// Perl needs size of sockaddr struct which is smaller than our internal size
		sv_setpvn(ip_addr, (char *) &message_addr->addr, (STRLEN) addr_len_tmp);
		sv_setuv(ip_addr_len, addr_len_tmp);

//		char buf[256];
//		rrr_ip_to_str(buf, sizeof(buf), (struct sockaddr *) message_addr->addr, RRR_MSG_ADDR_GET_ADDR_LEN(message_addr));
//		printf("perl5 message to hv: %s family %i socklen %lu\n",
//				buf, ((struct sockaddr *) message_addr->addr)->sa_family, RRR_MSG_ADDR_GET_ADDR_LEN(message_addr));
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

	target->hv = hv;
	hv = NULL;

	out:
	SV_DEC_UNLESS_NULL(hv);
	return ret;
}

