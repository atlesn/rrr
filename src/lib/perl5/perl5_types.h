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

#ifndef RRR_PERL5_TYPES_H
#define RRR_PERL5_TYPES_H

#include "../type.h"
#include "fixed_point.h"

struct rrr_perl5_ctx;
typedef struct sv SV;

#define RRR_PERL5_TYPE_TO_SV_CALLBACK_ARGS \
	struct rrr_perl5_ctx *ctx, SV *sv, int idx, const struct rrr_type_definition *def_orig, void *arg

#define RRR_PERL5_TYPE_TO_SV_ARGS \
	struct rrr_perl5_ctx *ctx, struct rrr_type_value *value, int (*callback)(RRR_PERL5_TYPE_TO_SV_CALLBACK_ARGS), void *callback_arg

#define RRR_PERL5_TYPE_TO_VALUE_ARGS \
	struct rrr_type_value **target, struct rrr_perl5_ctx *ctx, const struct rrr_type_definition *def_orig, AV *values

struct rrr_perl5_type_definition {
	rrr_type type;
	const struct rrr_type_definition *definition;
	int (*to_sv)(RRR_PERL5_TYPE_TO_SV_ARGS);
	int (*to_value)(RRR_PERL5_TYPE_TO_VALUE_ARGS);
};

extern const struct rrr_perl5_type_definition *rrr_perl5_type_definition_string;

int rrr_perl5_type_auto_sv_to_fixp (
		rrr_fixp *result,
		struct rrr_perl5_ctx *ctx,
		SV *sv
);
const struct rrr_perl5_type_definition *rrr_perl5_type_get_from_name (
		const char *name
);
const struct rrr_perl5_type_definition *rrr_perl5_type_get_from_id (
		uint8_t type_in
);
const struct rrr_perl5_type_definition *rrr_perl5_type_get_from_sv (
		SV *sv
);

#endif /* RRR_PERL5_TYPES_H */
