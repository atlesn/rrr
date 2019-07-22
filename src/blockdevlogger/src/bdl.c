/*

Block Device Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/bdl.h"
#include "lib/defaults.h"
#include "lib/cmdline.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

int main_loop(struct bdl_session *session, const char *program_name) {
	int ret = 1;

	while (session->usercount > 0 && !feof(stdin)) {
		char cmdline[BDL_MAXIMUM_CMDLINE_LENGTH];
		int argc_new = 0;
		const char *argv_new[CMD_MAXIMUM_CMDLINE_ARGS];

		argv_new[argc_new++] = program_name;

/*		fflush(stderr);
		fflush(stdout);
		printf ("Accepting commands delimeted by LF, CR or NULL\n");*/

		int first = 1;
		int i;
		for (i = 0; i < BDL_MAXIMUM_CMDLINE_LENGTH - 2 && !feof(stdin); i++) {
			char letter = getchar();

			if (first == 1) {
				if (letter == '\n' || letter == '\r' || letter == '\0') {
					i--;
					continue;
				}
			}

			first = 0;

			if (letter == '\n' || letter == '\r' || letter == '\0') {
				cmdline[i] = ' ';
				cmdline[i+1] = '\0';

				char *begin = cmdline;
				char *end = cmdline + i - 1;
				while ((end = strchr(begin, ' ')) != NULL) {
					*end = '\0';

					// Remove extra spaces
					while (*begin == ' ') {
						*begin = '\0';
						begin++;
					}

					if (argc_new == CMD_MAXIMUM_CMDLINE_ARGS) {
						fprintf (stderr, "Maximum command line arguments reached (%i)\n", CMD_MAXIMUM_CMDLINE_ARGS - 1);
						return 1;
					}

					argv_new[argc_new++] = begin;
					begin = end + 1;
				}

				ret = bdl_interpret_command(session, argc_new, argv_new);

				if (ret == 1) {
					return 1;
				}
				else if (session->usercount == 0) {
					return 0;
				}

				break;
			}

			cmdline[i] = letter;
		}
		if (i == BDL_MAXIMUM_CMDLINE_LENGTH - 2) {
			fprintf (stderr, "Maximum command line length reached (%i)\n", BDL_MAXIMUM_CMDLINE_LENGTH - 2);
			return 1;
		}
	}

	return ret;
}

int main(int argc, const char *argv[]) {
	struct bdl_session session;
	bdl_init_session (&session);

	int ret;

	ret = bdl_interpret_command(&session, argc, argv);

	/* And open command increments the user count. Run interactive. */
	if (session.usercount > 0) {
		ret = main_loop(&session, argv[0]);
	}

	// We consider it an error if filehandle is not cleaned up
	while (session.usercount > 0) {
		ret = 1;
		bdl_close_session(&session);
	}

	if (ret != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
