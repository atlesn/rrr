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
#include "rrr_config.h"
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

static int __rrr_profiling_mallctl_set_string (const char *name, const char *str) {
	if (mallctl(name, NULL, 0, &str, sizeof(str)) != 0) {
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

static void __rrr_profiling_stats_callback (void *opaque_data, const char *str) {
	(void)(opaque_data);
	RRR_MSG_1("Heap statistics for pid %lli:\n%s\n", (long long int) getpid(), str);
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

	if (snprintf(buf, sizeof(buf), "%s/%s", rrr_config_global.run_directory, "jeprof") >= (int) sizeof(buf)) {
		sprintf(buf, "/tmp/jeprof");

		RRR_MSG_0("Warning: Path trunctation in %s, cannot use current run directory to store profiling dumps. " \
			"Falling back to %s\n", __func__, buf);
	}

	buf[sizeof(buf) - 1] = '\0';

	if (__rrr_profiling_mallctl_set_string ("prof.prefix", buf) != 0) {
		return;
	}

	RRR_MSG_1("Dumping memory profile in pid %lli as instructed by signal SIGUSR2. " \
		"Prefix for dump files is '%s'\n",
		(long long int) getpid(), buf);

	if (__rrr_profiling_mallctl_call("prof.dump")) {
		RRR_MSG_0("Warning: Memory profiling dump failed. Verify hat the prefix '%s' is valid and that the containing directory is writable.\n",
			buf);
		return;
	}

	RRR_MSG_1("Dumping memory stats for pid %lli\n", (long long int) getpid());
	malloc_stats_print(__rrr_profiling_stats_callback, NULL, NULL);
#else

	RRR_MSG_0("Memory profiling requested by signal SIGUSR2, but RRR is not built with jemalloc.\n");

#endif
}
