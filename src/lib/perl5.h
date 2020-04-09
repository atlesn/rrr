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
struct rrr_message;
struct rrr_instance_settings;
struct rrr_setting;

struct rrr_perl5_ctx {
	struct rrr_perl5_ctx *next;
	PerlInterpreter *interpreter;
	void *private_data;

	int (*send_message)(struct rrr_message *message, void *private_data);
	char *(*get_setting)(const char *key, void *private_data);
	int (*set_setting)(const char *key, const char *value, void *private_data);
};

struct rrr_perl5_message_hv {
	HV *hv;
/*    SV *type;
    SV *class;
    SV *timestamp_from;
    SV *timestamp_to;
    SV *data_numeric;
    SV *topic;
    SV *data_length;
    SV *data;
    AV *array_values;
    AV *array_tags;
    AV *array_types;*/
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

void rrr_perl5_destroy_ctx (struct rrr_perl5_ctx *ctx);
int rrr_perl5_new_ctx (
		struct rrr_perl5_ctx **target,
		void *private_data,
		int (*send_message) (struct rrr_message *message, void *private_data),
		char *(*get_setting) (const char *key, void *private_data),
		int (*set_setting) (const char *key, const char *value, void *private_data)
);
int rrr_perl5_ctx_parse (struct rrr_perl5_ctx *ctx, char *filename);
int rrr_perl5_ctx_run (struct rrr_perl5_ctx *ctx);
int rrr_perl5_call_blessed_hvref (struct rrr_perl5_ctx *ctx, const char *sub, const char *class, HV *hv);

struct rrr_perl5_message_hv *rrr_perl5_allocate_message_hv (struct rrr_perl5_ctx *ctx);

void rrr_perl5_destruct_settings_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_settings_hv *source
);
int rrr_perl5_settings_to_hv (
		struct rrr_perl5_settings_hv **target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_instance_settings *source
);
void rrr_perl5_destruct_message_hv (
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
);
int rrr_perl5_hv_to_message (
		struct rrr_message **target_final,
		struct rrr_perl5_ctx *ctx,
		struct rrr_perl5_message_hv *source
);
int rrr_perl5_message_to_hv (
		struct rrr_perl5_message_hv *message_hv,
		struct rrr_perl5_ctx *ctx,
		struct rrr_message *message
);
int rrr_perl5_message_to_new_hv (
		struct rrr_perl5_message_hv **target,
		struct rrr_perl5_ctx *ctx,
		struct rrr_message *message
);

/* Called from XSUB */
int rrr_perl5_message_send (HV *message);
SV *rrr_perl5_settings_get (HV *settings, const char *key);
int rrr_perl5_settings_set (HV *settings, const char *key, const char *value);

#endif /* RRR_PERL5_H */
