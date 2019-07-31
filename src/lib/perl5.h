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

#ifndef RRR_PERL5_H
#define RRR_PERL5_H

typedef struct hv HV;
typedef struct interpreter PerlInterpreter;
struct vl_message;

struct rrr_perl5_ctx {
	PerlInterpreter *interpreter;
};

int rrr_perl5_init3(int argc, char **argv, char **env);
int rrr_perl5_sys_term(void);

void rrr_perl5_destroy_ctx (struct rrr_perl5_ctx *ctx);
int rrr_perl5_new_ctx (struct rrr_perl5_ctx **target);
int rrr_perl5_ctx_parse (struct rrr_perl5_ctx *ctx, char *filename);
int rrr_perl5_ctx_run (struct rrr_perl5_ctx *ctx);
int rrr_perl5_call_blessed_hvref (struct rrr_perl5_ctx *ctx, const char *sub, const char *class, HV *hv);
int rrr_perl5_message_to_hv (struct rrr_perl5_ctx *ctx, HV **target, struct vl_message *message);

#endif /* RRR_PERL5_H */
