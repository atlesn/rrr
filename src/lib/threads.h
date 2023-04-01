/*

Read Route Record

Copyright (C) 2018-2021 Atle Solbakken atle@goliathdns.no

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

#include "util/posix.h"
#include "util/linked_list.h"
#include "util/rrr_time.h"

/* Uncomment to enable errorchecking on mutexes */
#define RRR_THREAD_DEBUG_MUTEX

/* Tell a thread to start initialization */
#define RRR_THREAD_SIGNAL_START_INITIALIZE	(1<<0)

/* Tell a thread to start after initializing */
#define RRR_THREAD_SIGNAL_START_BEFOREFORK	(1<<1)

/* Tell a thread to proceed after it has reached RUNNING_FORKED */
#define RRR_THREAD_SIGNAL_START_AFTERFORK	(1<<2)

/* Watchdogs only use the last start signal */
#define RRR_THREAD_SIGNAL_START_WATCHDOG	RRR_THREAD_SIGNAL_START_AFTERFORK

/* Tell a thread politely to cancel */
#define RRR_THREAD_SIGNAL_ENCOURAGE_STOP	(1<<3)

/* Can only be set in thread control */
#define RRR_THREAD_STATE_NEW 0

/* Set by the thread when done */
#define RRR_THREAD_STATE_STOPPED 1

/* Set after the thread is finished with initializing and is waiting for start signal */
#define RRR_THREAD_STATE_INITIALIZED 3

/* Set by the thread itself when it has started and has completed forking (if it forks)
 * We only check for this if thread is started with INSTANCE_START_PRIORITY_FORK */
#define RRR_THREAD_STATE_RUNNING_FORKED 5

/* Thread may set this if it has to do a few cleanup operations before stopping, WD will
 * be more patient when waiting for STOPPED (KILLTIME_PATIENT_LIMIT will be used). Thread must set
 * this within the ordinary KILLTIME_LIMIT */
#define RRR_THREAD_STATE_STOPPING 6

// Milliseconds
#define RRR_THREAD_WATCHDOG_KILLTIME_LIMIT 2000
#define RRR_THREAD_WATCHDOG_KILLTIME_PATIENT_LIMIT 5000

#define RRR_THREAD_NAME_MAX_LENGTH 64

#define RRR_THREAD_OK     RRR_READ_OK
#define RRR_THREAD_STOP   RRR_READ_EOF

struct rrr_thread_ghost_data {
	struct rrr_thread_ghost_data *next;
	struct rrr_thread *thread;
	void (*poststop_routine)(const struct rrr_thread *);
};

struct rrr_thread {
	RRR_LL_NODE(struct rrr_thread);
	pthread_t thread;
	uint64_t watchdog_time;
	uint64_t watchdog_timeout_us;
	pthread_mutex_t mutex;
	pthread_cond_t signal_cond;
	int signal;
	int state;
	int is_watchdog;
	char name[RRR_THREAD_NAME_MAX_LENGTH];
	void *private_data;

	// Helper function to find rrr_thread struct in difficult callback conditions
	pthread_t self;

	// Set when we tried to cancel a thread but we couldn't join
	int is_ghost;

	// If the thread is to be destroy without stopping the program, both
	// the thread and it's watchdog must be destroyed at the same time, after
	// both being stopped. This value is set when both have reached STOPPED,
	// tagging them to be freed.
	int ready_to_destroy;

	// Start/stop routines
	int (*cancel_function)(struct rrr_thread *);
	void (*poststop_routine)(const struct rrr_thread *);
	void *(*start_routine) (struct rrr_thread *);

	// Pointer to watchdog thread
	struct rrr_thread *watchdog;
};

struct rrr_thread_collection {
	RRR_LL_HEAD(struct rrr_thread);
	pthread_mutex_t threads_mutex;
};

#include "log.h"

#ifdef RRR_THREAD_DEBUG_MUTEX
#	include "rrr_strerror.h"
#endif

static inline void rrr_thread_lock (
		struct rrr_thread *thread
) {
#ifdef RRR_THREAD_DEBUG_MUTEX
	int err;
	if ((err = pthread_mutex_lock(&thread->mutex)) != 0) {
		RRR_BUG("BUG: Locking failed in rrr_thread_lock for thread %p name %s: %s\n",
				thread, thread->name, rrr_strerror(err));
	}
#else
	pthread_mutex_lock(&thread->mutex);
#endif
}

static inline void rrr_thread_unlock (
		struct rrr_thread *thread
) {
#ifdef RRR_THREAD_DEBUG_MUTEX
	int err;
	if ((err = pthread_mutex_unlock(&thread->mutex)) != 0) {
		RRR_BUG("BUG: Unlocking failed in rrr_thread_unlock for thread %p name %s: %s\n",
				thread, thread->name, rrr_strerror(err));
	}
#else
	pthread_mutex_unlock(&thread->mutex);
#endif
}

static inline void rrr_thread_unlock_void (
		void *thread
) {
	rrr_thread_unlock((struct rrr_thread *) thread);
}

/* Threads need to update this once in a while, if not it get's killed by watchdog */
static inline void rrr_thread_watchdog_time_update(struct rrr_thread *thread) {
	rrr_thread_lock(thread);
	thread->watchdog_time = rrr_time_get_64();
	rrr_thread_unlock(thread);
}

/* Threads should check this once in awhile to see if it should exit,
 * set by watchdog after it detects kill signal. */
static inline int rrr_thread_signal_encourage_stop_check(struct rrr_thread *thread) {
	int signal;
	rrr_thread_lock(thread);
	signal = thread->signal;
	rrr_thread_unlock(thread);
	return ((signal & (RRR_THREAD_SIGNAL_ENCOURAGE_STOP)) != 0) ? RRR_THREAD_STOP : 0;
}

static inline int rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer(struct rrr_thread *thread) {
	int signal;
	rrr_thread_lock(thread);
	thread->watchdog_time = rrr_time_get_64();
	signal = thread->signal;
	rrr_thread_unlock(thread);
	return ((signal & (RRR_THREAD_SIGNAL_ENCOURAGE_STOP)) != 0) ? RRR_THREAD_STOP : 0;
}

static inline int rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer_void(void *arg) {
	return rrr_thread_signal_encourage_stop_check_and_update_watchdog_timer((struct rrr_thread *) arg);
}

void rrr_thread_signal_set (
		struct rrr_thread *thread,
		int signal
);
int rrr_thread_signal_check (
		struct rrr_thread *thread,
		int signal
);
void rrr_thread_signal_wait_busy (
		struct rrr_thread *thread,
		int signal
);
void rrr_thread_signal_wait_cond_with_watchdog_update (
		struct rrr_thread *thread,
		int signal
);
void rrr_thread_signal_wait_cond (
		struct rrr_thread *thread,
		int signal
);
int rrr_thread_ghost_check (
		struct rrr_thread *thread
);
int rrr_thread_state_get (
		struct rrr_thread *thread
);
int rrr_thread_state_check (
		struct rrr_thread *thread,
		int state
);
void rrr_thread_state_set (
		struct rrr_thread *thread,
		int state
);
void rrr_thread_cleanup_postponed_run (
		int *count
);
int rrr_thread_collection_count (
		struct rrr_thread_collection *collection
);
int rrr_thread_collection_new (
		struct rrr_thread_collection **target
);
void rrr_thread_collection_destroy (
		struct rrr_thread_collection *collection
);
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
int rrr_thread_collection_start_all (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
);
void rrr_thread_start_now_with_watchdog (
		struct rrr_thread *thread
);
void rrr_thread_initialize_now_with_watchdog (
		struct rrr_thread *thread
);
int rrr_thread_with_lock_do (
		struct rrr_thread *thread,
		int (*callback)(struct rrr_thread *thread, void *arg),
		void *callback_arg
);
struct rrr_thread *rrr_thread_collection_thread_new (
		struct rrr_thread_collection *collection,
		void *(*start_routine) (struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		void (*poststop_routine) (const struct rrr_thread *),
		int (*cancel_function) (struct rrr_thread *),
		const char *name,
		uint64_t watchdog_timeout_us,
		void *private_data
);
int rrr_thread_collection_check_any_stopped (
		struct rrr_thread_collection *collection
);
int rrr_thread_collection_iterate_non_wd_and_not_started_by_state (
		struct rrr_thread_collection *collection,
		int state,
		int (*callback)(struct rrr_thread *locked_thread, void *arg),
		void *callback_data
);

#endif /* RRR_THREADS_H */
