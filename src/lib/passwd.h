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

#ifndef RRR_PASSWD_H
#define RRR_PASSWD_H

#include <stdio.h>

#include "linked_list.h"

struct rrr_passwd_permission {
	RRR_LL_NODE(struct rrr_passwd_permission);
	char *permission;
};

struct rrr_passwd_permission_collection {
	RRR_LL_HEAD(struct rrr_passwd_permission);
};

void rrr_passwd_permission_collection_clear (
		struct rrr_passwd_permission_collection *collection
);
int rrr_passwd_permission_new_and_append (
		struct rrr_passwd_permission_collection *target,
		const char *permission_str
);
int rrr_passwd_permission_add_from_permissions (
		struct rrr_passwd_permission_collection *target,
		const struct rrr_passwd_permission_collection *source
);
void rrr_passwd_permission_collection_remove_duplicates (
		struct rrr_passwd_permission_collection *target
);
int rrr_passwd_check (
		const char *hash,
		const char *password
);
int rrr_passwd_encrypt (
		char **result,
		const char *password
);

#define RRR_PASSWD_ITERATE_OK	0
#define RRR_PASSWD_ITERATE_ERR	1
#define RRR_PASSWD_ITERATE_STOP	2

int rrr_passwd_iterate_lines (
		const char *input_data,
		ssize_t input_data_size,
		int (*line_callback) (
				const char *line,
				const char *username,
				const char *hash_tmp,
				const char *permissions[],
				size_t permissions_count,
				void *arg
		),
		void *line_callback_arg
);
int rrr_passwd_authenticate (
		const char *filename,
		const char *username,
		const char *password,
		const char *permission_name
);

#endif /* RRR_PASSWD_H */
