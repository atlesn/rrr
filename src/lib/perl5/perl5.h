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

#ifndef RRR_PERL5_H
#define RRR_PERL5_H

typedef struct av AV;
typedef struct hv HV;
typedef struct sv SV;
typedef struct interpreter PerlInterpreter;

struct rrr_msg;
struct rrr_msg_msg;
struct rrr_msg_addr;
struct rrr_instance_settings;
struct rrr_setting;
struct rrr_array;

struct rrr_perl5_ctx {
	struct rrr_perl5_ctx *next;
	PerlInterpreter *interpreter;
	void *private_data;

	int (*send_message)(const struct rrr_msg_msg *message, const struct rrr_msg_addr *message_addr, void *private_data);
	char *(*get_setting)(const char *key, void *private_data);
	int (*set_setting)(const char *key, const char *value, void *private_data);
};

struct rrr_perl5_message_hv {
	HV *hv;
};

struct rrr_perl5_method_sv {
	SV *sv;
};

struct rrr_perl5_settings_hv {
	HV *hv;
    SV **entries;
    char **keys;

    int allocated_entries;
    int used_entries;
};

int rrr_perl5_init3(int argc, char **argv, char **env);
int rrr_perl5_sys_term(void);

struct rrr_perl5_ctx *rrr_perl5_find_ctx (const PerlInterpreter *interpreter);
void rrr_perl5_destroy_ctx (struct rrr_perl5_ctx *ctx);
int rrr_perl5_new_ctx (
		struct rrr_perl5_ctx **target,
		void *private_data,
		int (*send_message) (const struct rrr_msg_msg *message, const struct rrr_msg_addr *message_addr, void *private_data),
		char *(*get_setting) (const char *key, void *private_data),
		int (*set_setting) (const char *key, const char *value, void *private_data)
);
int rrr_perl5_ctx_parse (struct rrr_perl5_ctx *ctx, char *filename, int include_build_dirs);
int rrr_perl5_ctx_run (struct rrr_perl5_ctx *ctx);
int rrr_perl5_call_blessed_hvref_and_sv (struct rrr_perl5_ctx *ctx, const char *sub, const char *class, HV *hv, SV *sv);

SV *rrr_perl5_deep_dereference(
		SV *sv
);
void rrr_perl5_destruct_settings_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_settings_hv *source
);
void rrr_perl5_destruct_message_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
);
void rrr_perl5_destruct_method_sv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_method_sv *source
);
int rrr_perl5_settings_to_hv (
		struct rrr_perl5_settings_hv *target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_instance_settings *source
);
int rrr_perl5_method_to_sv (
		struct rrr_perl5_method_sv *target,
		struct rrr_perl5_ctx *ctx,
		const char *method
);
int rrr_perl5_hv_to_message (
		struct rrr_msg_msg **target_final,
		struct rrr_msg_addr *target_addr,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
);
int rrr_perl5_message_to_hv (
		struct rrr_perl5_message_hv *target,
		struct rrr_perl5_ctx *ctx,
		const struct rrr_msg_msg *message,
		struct rrr_msg_addr *message_addr,
		struct rrr_array *array
);

#endif /* RRR_PERL5_H */
