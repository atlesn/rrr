/*

Read Route Record

Copyright (C) 2018-2020 Atle Solbakken atle@goliathdns.no

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

#include "util/posix.h"
#include "util/linked_list.h"
#include "util/rrr_time.h"

// #define RRR_THREADS_MAX 32

/* Tell a thread to start after initializing */
#define RRR_THREAD_SIGNAL_START_BEFOREFORK	(1<<0)

/* Tell a thread to cancel */
#define RRR_THREAD_SIGNAL_KILL_				(1<<1)

/* Tell a thread politely to cancel */
#define RRR_THREAD_SIGNAL_ENCOURAGE_STOP	(1<<2)

/* Tell a thread to proceed after all forking threads have reached RUNNING_FORKED */
#define RRR_THREAD_SIGNAL_START_AFTERFORK	(1<<3)

/* Can only be set in thread control */
#define RRR_THREAD_STATE_NEW 0

/* Set by the thread when done */
#define RRR_THREAD_STATE_STOPPED 1

/* Set after the thread is finished with initializing and is waiting for start signal */
#define RRR_THREAD_STATE_INITIALIZED 3

/* Set by the thread itself when it has started and has completed forking (if it forks)
 * We only check for this if thread is started with INSTANCE_START_PRIORITY_FORK */
#define RRR_THREAD_STATE_RUNNING_FORKED 5

/* Thread has to do a few cleanup operations before stopping */
// #define RRR_THREAD_STATE_STOPPING 6

// Milliseconds
#define RRR_THREAD_WATCHDOG_KILLTIME_LIMIT 2000

#define RRR_THREAD_NAME_MAX_LENGTH 64

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

static inline void rrr_thread_lock(struct rrr_thread *thread) {
//	RRR_DBG_8 ("Thread %s lock\n", thread->name);
	pthread_mutex_lock(&thread->mutex);
}

static inline void rrr_thread_unlock(struct rrr_thread *thread) {
//	RRR_DBG_8 ("Thread %s unlock\n", thread->name);
	pthread_mutex_unlock(&thread->mutex);
}

static inline void rrr_thread_unlock_if_locked(struct rrr_thread *thread) {
//	RRR_MSG_4 ("Thread %s test unlock\n", thread->name);
	if (pthread_mutex_trylock(&thread->mutex) != 0) {
//		RRR_MSG_4 ("Thread %s was locked, unlock now\n", thread->name);
	}
	pthread_mutex_unlock(&thread->mutex);
}

static inline int rrr_thread_check_signal(struct rrr_thread *thread, int signal) {
	int ret;
	rrr_thread_lock(thread);
	ret = (thread->signal & signal) == signal ? 1 : 0;
	rrr_thread_unlock(thread);;
	return ret;
}

static inline void rrr_thread_signal_wait(struct rrr_thread *thread, int signal) {
	while (1) {
		rrr_thread_lock(thread);
		int signal_test = thread->signal;
		rrr_thread_unlock(thread);
		if ((signal_test & signal) == signal) {
			break;
		}
		rrr_posix_usleep (10000); // 10ms
	}
}

static inline void rrr_thread_signal_wait_with_watchdog_update(struct rrr_thread *thread, int signal) {
	while (1) {
		rrr_thread_lock(thread);
		int signal_test = thread->signal;
		thread->watchdog_time = rrr_time_get_64();
		rrr_thread_unlock(thread);
		if ((signal_test & signal) == signal) {
			break;
		}
		rrr_posix_usleep (10000); // 10ms
	}
}

/* Threads should check this once in awhile to see if it should exit,
 * set by watchdog after it detects kill signal. */
static inline int rrr_thread_check_encourage_stop(struct rrr_thread *thread) {
	int signal;
	rrr_thread_lock(thread);
	signal = thread->signal;
	rrr_thread_unlock(thread);
	return ((signal & (RRR_THREAD_SIGNAL_ENCOURAGE_STOP)) > 0);
}

/* Threads need to update this once in a while, if not it get's killed by watchdog */
static inline void rrr_thread_update_watchdog_time(struct rrr_thread *thread) {
	rrr_thread_lock(thread);
	thread->watchdog_time = rrr_time_get_64();
	rrr_thread_unlock(thread);;
}

static inline int rrr_thread_is_ghost(struct rrr_thread *thread) {
	int ret;
	rrr_thread_lock(thread);
	ret = thread->is_ghost;
	rrr_thread_unlock(thread);
	return ret;
}

static inline void rrr_thread_set_ghost(struct rrr_thread *thread) {
	rrr_thread_lock(thread);
	thread->is_ghost = 1;
	rrr_thread_unlock(thread);
}

static inline uint64_t rrr_get_watchdog_time(struct rrr_thread *thread) {
	uint64_t ret;
	rrr_thread_lock(thread);
	ret = thread->watchdog_time;
	rrr_thread_unlock(thread);;
	return ret;
}

void rrr_thread_set_signal(struct rrr_thread *thread, int signal);
int rrr_thread_get_state(struct rrr_thread *thread);
int rrr_thread_check_state(struct rrr_thread *thread, int state);
void rrr_thread_set_state(struct rrr_thread *thread, int state);

/*static inline void rrr_thread_set_stopping(void *arg) {
	struct rrr_thread *thread = arg;
	rrr_thread_set_state(thread, RRR_THREAD_STATE_STOPPING);
}*/

static inline void rrr_thread_set_stopped(void *arg) {
	struct rrr_thread *thread = arg;
	rrr_thread_set_state(thread, RRR_THREAD_STATE_STOPPED);
}

void rrr_thread_postponed_cleanup_run(int *count);
static inline int rrr_thread_collection_count (
		struct rrr_thread_collection *collection
) {
	int count = 0;

	pthread_mutex_lock(&collection->threads_mutex);
	count = RRR_LL_COUNT(collection);
	pthread_mutex_unlock(&collection->threads_mutex);

	return count;
}
int rrr_thread_new_collection (
		struct rrr_thread_collection **target
);
void rrr_thread_destroy_collection (
		struct rrr_thread_collection *collection
);
void rrr_thread_start_condition_helper_nofork (
		struct rrr_thread *thread
);
int rrr_thread_start_condition_helper_fork (
		struct rrr_thread *thread,
		int (*fork_callback)(void *arg),
		void *callback_arg
);
int rrr_thread_start_all_after_initialized (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
);
void rrr_thread_stop_and_join_all_no_unlock (
		struct rrr_thread_collection *collection
);
int rrr_thread_start (
		struct rrr_thread *thread
);
int rrr_thread_with_lock_do (
		struct rrr_thread *thread,
		int (*callback)(struct rrr_thread *thread, void *arg),
		void *callback_arg
);
struct rrr_thread *rrr_thread_allocate_preload_and_register (
		struct rrr_thread_collection *collection,
		void *(*start_routine) (struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		void (*poststop_routine) (const struct rrr_thread *),
		int (*cancel_function) (struct rrr_thread *),
		const char *name,
		uint64_t watchdog_timeout_us,
		void *private_data
);
int rrr_thread_check_any_stopped (
		struct rrr_thread_collection *collection
);
void rrr_thread_join_and_destroy_stopped_threads (
		int *count,
		struct rrr_thread_collection *collection
);
int rrr_thread_iterate_non_wd_and_not_signalled_by_state (
		struct rrr_thread_collection *collection,
		int state,
		int (*callback)(struct rrr_thread *locked_thread, void *arg),
		void *callback_data
);

#endif /* RRR_THREADS_H */
