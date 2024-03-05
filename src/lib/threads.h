/*

Read Route Record

Copyright (C) 2018-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_THREADS_H
#define RRR_THREADS_H

#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "read_constants.h"

#include "util/atomic.h"
#include "util/posix.h"
#include "util/linked_list.h"
#include "util/rrr_time.h"

/* Tell a thread to start initialization */
#define RRR_THREAD_SIGNAL_START_INITIALIZE      (1<<16)

/* Tell a thread to start after initializing */
#define RRR_THREAD_SIGNAL_START_BEFOREFORK      (1<<17)

/* Tell a thread to proceed after it has reached RUNNING_FORKED */
#define RRR_THREAD_SIGNAL_START_AFTERFORK       (1<<18)

/* Watchdogs only use the last start signal */
#define RRR_THREAD_SIGNAL_START_WATCHDOG	RRR_THREAD_SIGNAL_START_AFTERFORK

/* Tell a thread politely to cancel */
#define RRR_THREAD_SIGNAL_ENCOURAGE_STOP        (1<<19)

/* Inform a thread that it is being run in single thread mode */
#define RRR_THREAD_SIGNAL_START_SINGLE_MODE     (1<<20)

/* Can only be set in thread control */
#define RRR_THREAD_STATE_NEW                    (1<<0)

/* Set by the thread when done */
#define RRR_THREAD_STATE_STOPPED                (1<<1)

/* Set after the thread is finished with initializing and is waiting for start signal */
#define RRR_THREAD_STATE_INITIALIZED            (1<<2)

/* Set by the thread itself when it has started and has completed forking (if it forks)
 * We only check for this if thread is started with INSTANCE_START_PRIORITY_FORK */
#define RRR_THREAD_STATE_RUNNING_FORKED         (1<<3)

/* Thread may set this if it has to do a few cleanup operations before stopping, WD will
 * be more patient when waiting for STOPPED (KILLTIME_PATIENT_LIMIT will be used). Thread must set
 * this within the ordinary KILLTIME_LIMIT */
#define RRR_THREAD_STATE_STOPPING               (1<<3)

/* Set if the thread does not respond to signals or being cancelled.
 * If a thread becomes ghost (tagged by the watchdog as such):
 * - Parent process should usually exit at the thread, if it wakes up, may try
 *   to use resources which are not longer available.
 * - Parent should shutdown other threads normally and then do an abort() or assert(0)
 *   to produce a useful core dump of the ghost situation. */
#define RRR_THREAD_STATE_GHOST                  (1<<4)

/* Set when both a thread and its watchdog are ready to be destroyed */
#define RRR_THREAD_STATE_READY_TO_DESTROY	(1<<5)

#define RRR_THREAD_SIGNAL_MASK                  0xffff0000
#define RRR_THREAD_STATE_MASK                   0x0000ffff

// Milliseconds
#define RRR_THREAD_WATCHDOG_KILLTIME_LIMIT 2000
#define RRR_THREAD_WATCHDOG_KILLTIME_PATIENT_LIMIT 5000

#define RRR_THREAD_NAME_MAX_LENGTH 64

#define RRR_THREAD_OK     RRR_READ_OK
#define RRR_THREAD_STOP   RRR_READ_EOF

struct rrr_thread_managed_data {
	RRR_LL_NODE(struct rrr_thread_managed_data);
	void *data;
	void (*destroy)(void *data);
};

struct rrr_thread_managed_data_collection {
	RRR_LL_HEAD(struct rrr_thread_managed_data);
};

struct rrr_thread {
	RRR_LL_NODE(struct rrr_thread);

	// Runtime control variables
	rrr_atomic_u64_t watchdog_time;
	rrr_atomic_u32_t state_and_signal;

	// Persistent variables
	pthread_t thread;
	uint64_t watchdog_timeout_us;
	char name[RRR_THREAD_NAME_MAX_LENGTH];
	// TODO : Have only the pointer
	int is_watchdog;
	struct rrr_thread *watchdog;

	// Private data accessed by thread only
	void *private_data;

	// Sync variables
	pthread_mutex_t signal_cond_mutex;
	pthread_cond_t signal_cond;

	// Routines
	int (*init)(struct rrr_thread *);
	int (*run)(struct rrr_thread *);

	// Cleanup control
	volatile int started;

	// External data to clean up
	struct rrr_thread_managed_data_collection managed_data;
};

struct rrr_thread_collection {
	RRR_LL_HEAD(struct rrr_thread);
};

int rrr_thread_managed_data_push (
		struct rrr_thread *thread,
		void *data,
		void (*destroy)(void *data)
);

static inline int rrr_thread_signal_check (
		struct rrr_thread *thread,
		uint32_t signal
) {
	signal &= RRR_THREAD_SIGNAL_MASK;
	assert(signal != 0);
	return (rrr_atomic_u32_load(&thread->state_and_signal) & signal) != 0;
}

static inline int rrr_thread_signal_check_other_than (
		struct rrr_thread *thread,
		uint32_t signal
) {
	signal &= RRR_THREAD_SIGNAL_MASK;
	assert(signal != 0);
	return (rrr_atomic_u32_load(&thread->state_and_signal) & ~signal & RRR_THREAD_SIGNAL_MASK) != 0;
}

static inline int rrr_thread_state_check (
		struct rrr_thread *thread,
		uint32_t state
) {
	state &= RRR_THREAD_STATE_MASK;
	assert(state != 0);
	// Callers may OR states together in the argument
	return (rrr_atomic_u32_load(&thread->state_and_signal) & state) != 0;
}

static inline int rrr_thread_state_and_signal_check (
		struct rrr_thread *thread,
		uint32_t state,
		uint32_t signal
) {
	state &= RRR_THREAD_STATE_MASK;
	signal &= RRR_THREAD_SIGNAL_MASK;
	assert(state != 0);
	assert(signal != 0);

	uint32_t tmp = rrr_atomic_u32_load(&thread->state_and_signal);
	return (tmp & state) != 0 && (tmp & signal) != 0;
}

/* Threads need to update this once in a while, if not it get's killed by watchdog */
static inline void rrr_thread_watchdog_time_update(struct rrr_thread *thread) {
	rrr_atomic_u64_store_relaxed(&thread->watchdog_time, rrr_time_get_64());
}

/* Threads should check this once in awhile to see if it should exit,
 * set by watchdog after it detects kill signal. */
static inline int rrr_thread_signal_encourage_stop_check(struct rrr_thread *thread) {
	if (rrr_thread_signal_check(thread, RRR_THREAD_SIGNAL_ENCOURAGE_STOP))
		return RRR_THREAD_STOP;
	return 0;
}

static inline int rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(struct rrr_thread *thread) {
	if (rrr_thread_signal_check(thread, RRR_THREAD_SIGNAL_ENCOURAGE_STOP))
		return RRR_THREAD_STOP;
	rrr_thread_watchdog_time_update(thread);
	return 0;
}

static inline int rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(void *arg) {
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer((struct rrr_thread *) arg);
}

void rrr_thread_signal_set (
		struct rrr_thread *thread,
		uint32_t signal
);
void rrr_thread_signal_wait_busy (
		struct rrr_thread *thread,
		uint32_t signal
);
void rrr_thread_signal_wait_cond_with_watchdog_update (
		struct rrr_thread *thread,
		uint32_t signal
);
void rrr_thread_signal_wait_cond (
		struct rrr_thread *thread,
		uint32_t signal
);
void rrr_thread_state_set (
		struct rrr_thread *thread,
		uint32_t state
);
int rrr_thread_collection_count (
		struct rrr_thread_collection *collection
);
int rrr_thread_collection_new (
		struct rrr_thread_collection **target
);
void rrr_thread_collection_destroy (
		int *ghost_count,
		struct rrr_thread_collection *collection
);
/* TODO : Rename, replace 'start' with 'signal' */
void rrr_thread_start_condition_helper_nofork (
		struct rrr_thread *thread
);
void rrr_thread_start_condition_helper_nofork_nice (
		struct rrr_thread *thread
);
int rrr_thread_start_condition_helper_fork (
		struct rrr_thread *thread,
		int (*fork_callback)(void *arg),
		void *callback_arg
);
void rrr_thread_collection_signal_start_no_procedure_all (
		struct rrr_thread_collection *collection
);
int rrr_thread_collection_signal_start_procedure_all (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
);
void rrr_thread_signal_start_now_with_watchdog (
		struct rrr_thread *thread
);
void rrr_thread_signal_initialize_now_with_watchdog (
		struct rrr_thread *thread
);
struct rrr_thread *rrr_thread_collection_thread_create_and_preload (
		struct rrr_thread_collection *collection,
		int (*init)(struct rrr_thread *),
		int (*run)(struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		const char *name,
		uint64_t watchdog_timeout_us,
		void *private_data
);
int rrr_thread_collection_start_all (
		struct rrr_thread_collection *collection
);
void rrr_thread_run (
		struct rrr_thread *thread
);
int rrr_thread_collection_init_all (
		struct rrr_thread_collection *collection,
		void (*fail_cb)(struct rrr_thread *thread)
);
int rrr_thread_collection_check_any_stopped (
		struct rrr_thread_collection *collection
);

#endif /* RRR_THREADS_H */
