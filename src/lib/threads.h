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

#include "posix.h"
#include "vl_time.h"
#include "linked_list.h"
#include "../global.h"

// #define RRR_THREADS_MAX 32

/* Tell a thread to start after initializing */
#define RRR_THREAD_SIGNAL_START	(1<<0)

/* Tell a thread to cancel */
#define RRR_THREAD_SIGNAL_KILL	(1<<1)

/* Tell a thread politely to cancel */
#define RRR_THREAD_SIGNAL_ENCOURAGE_STOP	(1<<2)

/* Can only be set in thread control */
#define RRR_THREAD_STATE_FREE 0

/* Set by the thread after we reserved it and by thread cleanup */
#define RRR_THREAD_STATE_STOPPED 1

/* Set after the thread is initializing */
#define RRR_THREAD_STATE_INIT 2

/* Set after the thread is finished with initializing and is waiting for start signal */
#define RRR_THREAD_STATE_INITIALIZED 3

/* Set by the thread itself when started */
#define RRR_THREAD_STATE_RUNNING 4

/* Set by the thread itself when it has started and has completed forking (if it forks)
 * We only check for this if thread is started with INSTANCE_START_PRIORITY_FORK */
#define RRR_THREAD_STATE_RUNNING_FORKED 5

/* Thread has to do a few cleanup operations before stopping */
// #define RRR_THREAD_STATE_STOPPING 6

/* Priority 0 threads are started first. They have no wait points. This need not to be set, zero is default. */
#define RRR_THREAD_START_PRIORITY_NORMAL 0

/* Modules which forks are started at the same time as NORMAL. They first set RUNNING when they receive start signal,
 * and after forking the must set RUNNING_FORKED.
 * Modules should not fork again without a restart of all modules unless the forked process only is short-lived. */
#define RRR_THREAD_START_PRIORITY_FORK 1

/* Network modules must start after fork modules to prevent forked process to inherit file handles.
 * This also goes for other modules which use open(). */
#define RRR_THREAD_START_PRIORITY_NETWORK 2

/* Used for error-checking */
#define RRR_THREAD_START_PRIORITY_MAX RRR_THREAD_START_PRIORITY_NETWORK

// Milliseconds
#define RRR_THREAD_WATCHDOG_FREEZE_LIMIT 5000
#define RRR_THREAD_WATCHDOG_KILLTIME_LIMIT 2000

#define RRR_THREAD_NAME_MAX_LENGTH 64

struct rrr_thread_double_pointer {
	void **ptr;
};

#define RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER_CUSTOM(name,free_function,pointer) \
	struct rrr_thread_double_pointer __##name##_double_pointer = {(void**) &(pointer)}; \
	pthread_cleanup_push(free_function, &__##name##_double_pointer)

#define RRR_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(name,pointer) \
	struct rrr_thread_double_pointer __##name##_double_pointer = {(void**) &(pointer)}; \
	pthread_cleanup_push(rrr_thread_free_double_pointer, &__##name##_double_pointer)

#define RRR_THREAD_CLEANUP_PUSH_FREE_SINGLE_POINTER(name) \
	pthread_cleanup_push(rrr_thread_free_single_pointer, name)

struct rrr_thread_ghost_data {
	struct rrr_thread_ghost_data *next;

	struct rrr_thread *thread;

	// Main thread may set this value if a thread doesn't respond and
	// we wish to forget about it. If the thread awakes, it will run
	// it's cleanup procedure and free this pointer
	void *ghost_cleanup_pointer;
	void (*poststop_routine)(const struct rrr_thread *);
};

struct rrr_thread {
	RRR_LL_NODE(struct rrr_thread);
	pthread_t thread;
	uint64_t watchdog_time;
	pthread_mutex_t mutex;
	int signal;
	int state;
	int start_signal_sent;
	int is_watchdog;
	int start_priority;
	char name[RRR_THREAD_NAME_MAX_LENGTH];
	void *private_data;

	// Set when we tried to cancel a thread but we couldn't join
	int is_ghost;

	// If the thread is a ghost, we can't free this struct. Ghost does it.
	int free_by_ghost;
	int free_private_data_by_ghost;
	void (*private_data_destroy_function)(void *private_data);

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

static inline void rrr_thread_lock(struct rrr_thread *thread) {
//	RRR_MSG_4 ("Thread %s lock\n", thread->name);
	pthread_mutex_lock(&thread->mutex);
}

static inline void rrr_thread_unlock(struct rrr_thread *thread) {
//	RRR_MSG_4 ("Thread %s unlock\n", thread->name);
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

/* Watchdog checks if thread should be killed */
static inline int rrr_thread_check_kill_signal(struct rrr_thread *thread) {
	return rrr_thread_check_signal(thread, RRR_THREAD_SIGNAL_KILL);
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

static inline void rrr_thread_set_signal(struct rrr_thread *thread, int signal) {
	RRR_DBG_4 ("Thread %s set signal %d\n", thread->name, signal);
	rrr_thread_lock(thread);
	thread->signal |= signal;
	rrr_thread_unlock(thread);
}

static inline int rrr_thread_get_state(struct rrr_thread *thread) {
	int state;
	rrr_thread_lock(thread);
	state = thread->state;
	rrr_thread_unlock(thread);;
	return state;
}

static inline int rrr_thread_check_state(struct rrr_thread *thread, int state) {
	return (rrr_thread_get_state(thread) == state);
}

void rrr_thread_set_state(struct rrr_thread *thread, int state);

/*static inline void rrr_thread_set_stopping(void *arg) {
	struct rrr_thread *thread = arg;
	rrr_thread_set_state(thread, RRR_THREAD_STATE_STOPPING);
}*/

static inline void rrr_thread_set_stopped(void *arg) {
	struct rrr_thread *thread = arg;
	rrr_thread_set_state(thread, RRR_THREAD_STATE_STOPPED);
}

int rrr_thread_run_ghost_cleanup(int *count);
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
		struct rrr_thread_collection *collection,
		int do_destroy_private_data
);
int rrr_thread_start_all_after_initialized (
		struct rrr_thread_collection *collection,
		int (*start_check_callback)(int *do_start, struct rrr_thread *thread, void *arg),
		void *callback_arg
);
void rrr_thread_stop_and_join_all (
		struct rrr_thread_collection *collection,
		void (*upstream_ghost_handler)(struct rrr_thread *thread)
);
int rrr_thread_start (
		struct rrr_thread *thread
);
struct rrr_thread *rrr_thread_preload_and_register (
		struct rrr_thread_collection *collection,
		void *(*start_routine) (struct rrr_thread *),
		int (*preload_routine) (struct rrr_thread *),
		void (*poststop_routine) (const struct rrr_thread *),
		int (*cancel_function) (struct rrr_thread *),
		void (*private_data_destroy_function)(void *),
		int start_priority,
		void *private_data,
		const char *name
);
int rrr_thread_check_any_stopped (
		struct rrr_thread_collection *collection
);
void rrr_thread_join_and_destroy_stopped_threads (
		int *count,
		struct rrr_thread_collection *collection,
		int do_destroy_private_data
);
int rrr_thread_iterate_non_wd_and_not_signalled_by_state (
		struct rrr_thread_collection *collection,
		int state,
		int (*callback)(struct rrr_thread *locked_thread, void *arg),
		void *callback_data
);
void rrr_thread_free_double_pointer(void *arg);

//void thread_destroy (struct rrr_thread_collection *collection, struct rrr_thread *thread);

#endif /* RRR_THREADS_H */
