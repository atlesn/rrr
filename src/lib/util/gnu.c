/*

Read Route Record

Copyright (C) 2019-2021 Atle Solbakken atle@goliathdns.no

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

#define _GNU_SOURCE
#define __BSD_VISIBLE 1

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

#include "../../../config.h"
#include "../log.h"
#include "../allocator.h"
#include "gnu.h"
#include "macro_utils.h"

int rrr_vasprintf (char **resultp, const char *format, va_list args) {
	int ret = 0;

/*#if defined HAVE_VASPRINTF && !defined RRR_WITH_GNU_DEBUG
	ret = vasprintf(resultp, format, args);
#else*/
	ssize_t size = strlen(format) * 2;
	char *buf = NULL;

	*resultp = NULL;

	retry:
	RRR_FREE_IF_NOT_NULL(buf);
	if ((buf = rrr_allocate(size)) == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_vasprintf\n");
		ret = -1;
		goto out;
	}

	int retry_count = 0;

	va_list args_tmp;
	va_copy(args_tmp, args);
	ret = vsnprintf(buf, size, format, args_tmp);
	va_end(args_tmp);

	if (ret >= size) {
		if (++retry_count > 1) {
			RRR_MSG_0("More than two attempts to format string in rrr_asprintf\n");
			ret = -1;
			goto out;
		}
		size = ret + 1;
		goto retry;
	}
	else if (ret < 0) {
		RRR_MSG_0("Error returned from vsnprintf in rrr_asprintf\n");
		ret = -1;
		goto out;
	}

	ret = strlen(buf);

	*resultp = buf;
	buf = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(buf);
//#endif
	return ret;
}

int rrr_asprintf (char **resultp, const char *format, ...) {
	int ret = 0;
	va_list args;
	va_start (args, format);

	ret = rrr_vasprintf(resultp, format, args);

	va_end (args);

	return ret;
}

char *rrr_strcasestr (const char *haystack, const char *needle) {
	char *ret = NULL;

#if defined HAVE_STRCASESTR && !defined RRR_WITH_GNU_DEBUG
	ret = strcasestr(haystack, needle);
#else
	const char *haystack_pos = haystack;
	while (1) {
		char tmp1 = *haystack_pos;
		if (tmp1 == '\0') {
			break;
		}
		if (tmp1 >= 'A' && tmp1 <= 'Z') {
			tmp1 -= 'Z' - 'z';
		}

		const char *needle_pos = needle;
		while (1) {
			char tmp2 = *needle_pos;
			if (tmp2 == '\0') {
				break;
			}
			if (tmp2 >= 'A' && tmp2 <= 'Z') {
				tmp2 -= 'Z' - 'z';
			}
			if (tmp2 == tmp1 && ret == NULL) {
				ret = (char *) haystack_pos;
			}
			else if (tmp2 != tmp1) {
				ret = NULL;
				break;
			}
		}

		if (ret != NULL) {
			break;
		}

		haystack_pos++;
	}

#endif
	return ret;
}

pid_t rrr_gettid(void) {
#ifdef RRR_HAVE_GETTID
	return gettid();
#else
	return getpid();
#endif
}

