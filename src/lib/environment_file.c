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

#include <stdlib.h>
#include <stdio.h>

#include "environment_file.h"
#include "log.h"
#include "util/readfile.h"
#include "rrr_strerror.h"
#include "parse.h"
#include "rrr_types.h"
#include "map.h"

static int __rrr_environment_file_parse (
		struct rrr_map *target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	char *line_tmp = NULL;

	char *var_tmp = NULL;
	size_t var_length_tmp;

	char *val_tmp = NULL;

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		rrr_parse_ignore_spaces_and_increment_line(pos);
		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		if (*(pos->data + pos->pos) == '#') {
			rrr_parse_comment(pos);
			continue;
		}

		int line_start;
		int line_end;
		rrr_parse_non_newline(pos, &line_start, &line_end);

		RRR_FREE_IF_NOT_NULL(line_tmp);
		if ((ret = rrr_parse_str_extract(&line_tmp, pos, line_start, line_end - line_start + 1)) != 0) {
			goto out;
		}
		pos->pos = line_start;

		RRR_FREE_IF_NOT_NULL(var_tmp);
		if ((ret = rrr_parse_str_extract_until(&var_tmp, &var_length_tmp, line_tmp, '=')) != 0) {
			goto out;
		}
		pos->pos += var_length_tmp;

		// No equal sign = found ?
		if (var_length_tmp == 0) {
			rrr_parse_str_trim(line_tmp);

			if ((ret = rrr_map_item_add_new(target, line_tmp, "1")) != 0) {
				goto out;
			}
		}
		else {
			rrr_parse_str_trim(var_tmp);

			pos->pos++; // Go beyond =
			rrr_parse_ignore_space_and_tab(pos);
			if (RRR_PARSE_CHECK_EOF(pos) || pos->pos > line_end) {
				RRR_MSG_0("Value missing after = in environment file at line %i\n", pos->line);
				ret = 1;
				goto out;
			}

			RRR_FREE_IF_NOT_NULL(val_tmp);
			if ((ret = rrr_parse_str_extract(&val_tmp, pos, pos->pos, line_end - pos->pos + 1)) != 0) {
				goto out;
			}
			rrr_parse_str_trim(val_tmp);

			if ((ret = rrr_map_item_add_new(target, var_tmp, val_tmp)) != 0) {
				goto out;
			}
		}

		pos->pos = line_end + 1;
	}

	out:
	RRR_FREE_IF_NOT_NULL(line_tmp);
	RRR_FREE_IF_NOT_NULL(var_tmp);
	RRR_FREE_IF_NOT_NULL(val_tmp);
	return ret;
}

int rrr_environment_file_parse (
		struct rrr_map *target,
		const char *environment_file
) {
	int ret = 0;

	rrr_biglength env_data_size;
	char *env_data = NULL;

	if (rrr_readfile_read (
			&env_data,
			&env_data_size,
			environment_file,
			0,
			1 // ENOENT is OK
	) != 0) {
		RRR_MSG_0("Failed to read environment file '%s'\n");
		ret = 1;
		goto out;
	}

	if (env_data_size == 0) {
		// Don't use RRR_DBG_1, debuglevel is not set yet
		RRR_MSG_1("Note: Environment file '%s' not found, not loading.\n", environment_file);
		goto out;
	}

	// Protection before storing to int type in rrr_parse_pos struct
	if (env_data_size > 0xfffffff) { // Seven f's
		RRR_MSG_0("Environment file '%s' too big (was %" PRIrrrbl " bytes)", env_data_size);
		ret = 1;
		goto out;
	}

	struct rrr_parse_pos pos = {0};
	rrr_parse_pos_init(&pos, env_data, env_data_size);

	if ((ret = __rrr_environment_file_parse(target, &pos)) != 0) {
		RRR_MSG_0("Parsing of environment file '%s' failed\n", environment_file);
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(env_data);
	return ret;
}
