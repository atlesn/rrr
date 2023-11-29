/*

Read Route Record

Copyright (C) 2023 Atle Solbakken atle@goliathdns.no

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

#ifdef RRR_WITH_JEMALLOC
#include <jemalloc/jemalloc.h>
#include <unistd.h>
#endif

#include "profiling.h"

#include "log.h"
#include "rrr_strerror.h"

#ifdef RRR_WITH_JEMALLOC
static int __rrr_profiling_mallctl_inspect_bool (int *result, const char *name) {
	bool value;
	size_t value_size = sizeof(value);

	if (mallctl(name, &value, &value_size, NULL, 0) != 0) {
		RRR_MSG_0("Warning: mallctl failed for %s\n", name);
		return 1;
	}

	*result = value;
	return 0;
}

static int __rrr_profiling_mallctl_set_bool (const char *name, bool value) {
	value = value != 0;

	if (mallctl(name, NULL, 0, &value, sizeof(value)) != 0) {
		RRR_MSG_0("Warning: mallctl failed for %s\n", name);
		return 1;
	}

	return 0;
}

static int __rrr_profiling_mallctl_call (const char *name) {
	if (mallctl(name, NULL, 0, NULL, 0) != 0) {
		RRR_MSG_0("Warning: mallctl failed for %s\n", name);
		return 1;
	}

	return 0;
}
#endif

void rrr_profiling_dump (void) {
#ifdef RRR_WITH_JEMALLOC
	int value;
	char buf[256];

	if (__rrr_profiling_mallctl_inspect_bool(&value, "config.prof") != 0) {
		return;
	}

	if (!value) {
		RRR_MSG_0("Memory profiling requested by signal SIGUSR2 but jemalloc was not built with profiling support.\n");
		return;
	}

	if (__rrr_profiling_mallctl_inspect_bool(&value, "opt.prof") != 0) {
		return;
	}

	if (!value) {
		RRR_MSG_0("Memory profiling requested by signal SIGUSR2 but jemalloc profiling is not enabled. " \
			"Try to start RRR with environment MALLOC_CONF=\"prof:true\".\n");
		return;
	}

	if (__rrr_profiling_mallctl_set_bool("prof.active",        1) != 0 ||
	    __rrr_profiling_mallctl_set_bool("thread.prof.active", 1) != 0
	) {
		return;
	}

	*buf = '\0';
	if (getcwd(buf, sizeof(buf)) == NULL) {
		RRR_MSG_0("Warning: getcwd() failed in %s: %s\n", __func__, buf);
	}

	RRR_MSG_1("Dumping memory profile in pid %lli as instructed by signal SIGUSR2. " \
		"Current working directory is '%s', expect dump files to be placed here.\n",
		(long long int) getpid(), buf);

	if (__rrr_profiling_mallctl_call("prof.dump")) {
		return;
	}

#else

	RRR_MSG_0("Memory profiling requested by signal SIGUSR2, but RRR is not built with jemalloc.\n");

#endif
}
