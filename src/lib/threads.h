/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef VL_THREADS_H
#define VL_THREADS_H

#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "vl_time.h"
#include "../global.h"

#define VL_THREADS_MAX 32

/* Tell a thread to start after initializing */
#define VL_THREAD_SIGNAL_START	(1<<0)

/* Tell a thread to cancel */
#define VL_THREAD_SIGNAL_KILL	(1<<1)

/* Tell a thread politely to cancel */
#define VL_THREAD_SIGNAL_ENCOURAGE_STOP	(1<<2)

/* Can only be set in thread control */
#define VL_THREAD_STATE_FREE 0

/* Set by the thread after we reserved it and by thread cleanup */
#define VL_THREAD_STATE_STOPPED 1

/* Set after the thread is initializing */
#define VL_THREAD_STATE_INIT 2

/* Set after the thread is finished with initializing and is waiting for start signal */
#define VL_THREAD_STATE_INITIALIZED 3

/* Set by the thread itself when started */
#define VL_THREAD_STATE_RUNNING 4

/* Set by the thread itself when it has started and has completed forking (if it forks)
 * We only check for this if thread is started with INSTANCE_START_PRIORITY_FORK */
#define VL_THREAD_STATE_RUNNING_FORKED 5

/* Thread has to do a few cleanup operations before stopping */
#define VL_THREAD_STATE_STOPPING 6

/* Priority 0 threads are started first. They have no wait points. This need not to be set, zero is default. */
#define VL_THREAD_START_PRIORITY_NORMAL 0

/* Modules which forks are started at the same time as NORMAL. They first set RUNNING when they receive start signal,
 * and after forking the must set RUNNING_FORKED.
 * Modules should not fork again without a restart of all modules unless the forked process only is short-lived. */
#define VL_THREAD_START_PRIORITY_FORK 1

/* Network modules must start after fork modules to prevent forked process to inherit file handles.
 * This also goes for other modules which use open(). */
#define VL_THREAD_START_PRIORITY_NETWORK 2

/* Used for error-checking */
#define VL_THREAD_START_PRIORITY_MAX VL_THREAD_START_PRIORITY_NETWORK

// Milliseconds
#define VL_THREAD_WATCHDOG_FREEZE_LIMIT 5000
#define VL_THREAD_WATCHDOG_KILLTIME_LIMIT 2000

#define VL_THREAD_NAME_MAX_LENGTH 64

struct vl_thread_double_pointer {
	void **ptr;
};

#define VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER_CUSTOM(name,free_function,pointer) \
	struct vl_thread_double_pointer __##name##_double_pointer = {(void**) &(pointer)}; \
	pthread_cleanup_push(free_function, &__##name##_double_pointer)

#define VL_THREAD_CLEANUP_PUSH_FREE_DOUBLE_POINTER(name,pointer) \
	struct vl_thread_double_pointer __##name##_double_pointer = {(void**) &(pointer)}; \
	pthread_cleanup_push(thread_free_double_pointer, &__##name##_double_pointer)

#define VL_THREAD_CLEANUP_PUSH_FREE_SINGLE_POINTER(name) \
	pthread_cleanup_push(thread_free_single_pointer, name)

struct vl_thread_ghost_data {
	struct vl_thread_ghost_data *next;

	struct vl_thread *thread;

	// Main thread may set this value if a thread doesn't respond and
	// we wish to forget about it. If the thread awakes, it will run
	// it's cleanup procedure and free this pointer
	void *ghost_cleanup_pointer;
	void (*poststop_routine)(const struct vl_thread *);
};

struct vl_thread {
	struct vl_thread *next;
	pthread_t thread;
	uint64_t watchdog_time;
	pthread_mutex_t mutex;
	int signal;
	int state;
	int is_watchdog;
	int start_priority;
	char name[VL_THREAD_NAME_MAX_LENGTH];
	void *private_data;

	// Set when we tried to cancel a thread but we couldn't join
	int is_ghost;

	// If the thread is a ghost, we can't free this struct. Ghost does it.
	int free_by_ghost;
	int free_private_data_by_ghost;

	// Start/stop routines
	int (*cancel_function)(struct vl_thread *);
	void (*poststop_routine)(const struct vl_thread *);
	void *(*start_routine) (struct vl_thread *);

	// Pointer to watchdog thread
	struct vl_thread *watchdog;
};

struct vl_thread_collection {
	struct vl_thread *first;
	pthread_mutex_t threads_mutex;
};

#define VL_THREADS_LOOP(target,collection) \
	for(struct vl_thread *target = collection->first; target != NULL; target = target->next)


void thread_clear_ghosts(void);
int thread_has_ghosts(void);
int thread_run_ghost_cleanup(int *count);
void thread_set_state(struct vl_thread *thread, int state);
int thread_new_collection (struct vl_thread_collection **target);
void thread_destroy_collection (struct vl_thread_collection *collection);
int thread_start_all_after_initialized (struct vl_thread_collection *collection);
void threads_stop_and_join (
		struct vl_thread_collection *collection,
		void (*upstream_ghost_handler)(struct vl_thread *thread)
);

static inline void thread_lock(struct vl_thread *thread) {
//	VL_DEBUG_MSG_4 ("Thread %s lock\n", thread->name);
	pthread_mutex_lock(&thread->mutex);
}

static inline void thread_unlock(struct vl_thread *thread) {
//	VL_DEBUG_MSG_4 ("Thread %s unlock\n", thread->name);
	pthread_mutex_unlock(&thread->mutex);
}

static inline void thread_unlock_if_locked(struct vl_thread *thread) {
//	VL_DEBUG_MSG_4 ("Thread %s test unlock\n", thread->name);
	if (pthread_mutex_trylock(&thread->mutex) == EBUSY) {
//		VL_DEBUG_MSG_4 ("Thread %s was locked, unlock now\n", thread->name);
		pthread_mutex_unlock(&thread->mutex);
	}
}

static inline int thread_check_signal(struct vl_thread *thread, int signal) {
	int ret;
	thread_lock(thread);
	ret = (thread->signal & signal) == signal ? 1 : 0;
	thread_unlock(thread);;
	return ret;
}

static inline void thread_signal_wait(struct vl_thread *thread, int signal) {
	while (1) {
		thread_lock(thread);
		int signal_test = thread->signal;
		thread_unlock(thread);
		if ((signal_test & signal) == signal) {
			break;
		}
		usleep (10000); // 10ms
	}
}

/* Watchdog checks if thread should be killed */
static inline int thread_check_kill_signal(struct vl_thread *thread) {
	return thread_check_signal(thread, VL_THREAD_SIGNAL_KILL);
}

/* Threads should check this once in awhile to see if it should exit,
 * set by watchdog after it detects kill signal. */
static inline int thread_check_encourage_stop(struct vl_thread *thread) {
	int signal;
	thread_lock(thread);
	signal = thread->signal;
	thread_unlock(thread);
	return ((signal & (VL_THREAD_SIGNAL_ENCOURAGE_STOP)) > 0);
}

/* Threads need to update this once in a while, if not it get's killed by watchdog */
static inline void update_watchdog_time(struct vl_thread *thread) {
	thread_lock(thread);
	thread->watchdog_time = time_get_64();
	thread_unlock(thread);;
}

static inline int thread_is_ghost(struct vl_thread *thread) {
	int ret;
	thread_lock(thread);
	ret = thread->is_ghost;
	thread_unlock(thread);
	return ret;
}

static inline void thread_set_ghost(struct vl_thread *thread) {
	thread_lock(thread);
	thread->is_ghost = 1;
	thread_unlock(thread);
}

static inline uint64_t get_watchdog_time(struct vl_thread *thread) {
	uint64_t ret;
	thread_lock(thread);
	ret = thread->watchdog_time;
	thread_unlock(thread);;
	return ret;
}

static inline void thread_set_signal(struct vl_thread *thread, int signal) {
	VL_DEBUG_MSG_4 ("Thread %s set signal %d\n", thread->name, signal);
	thread_lock(thread);
	thread->signal |= signal;
	thread_unlock(thread);
}

static inline int thread_get_state(struct vl_thread *thread) {
	int state;
	thread_lock(thread);
	state = thread->state;
	thread_unlock(thread);;
	return state;
}

static inline int thread_check_state(struct vl_thread *thread, int state) {
	return (thread_get_state(thread) == state);
}

static inline void thread_set_running(void *arg) {
	struct vl_thread *thread = arg;
	thread_set_state(thread, VL_THREAD_STATE_RUNNING);
}

static inline void thread_set_running_forked(void *arg) {
	struct vl_thread *thread = arg;
	thread_set_state(thread, VL_THREAD_STATE_RUNNING_FORKED);
}

static inline void thread_set_stopping(void *arg) {
	struct vl_thread *thread = arg;
	thread_set_state(thread, VL_THREAD_STATE_STOPPING);
}

static inline void thread_set_stopped(void *arg) {
	struct vl_thread *thread = arg;
	thread_set_state(thread, VL_THREAD_STATE_STOPPED);
}

int thread_start (
		struct vl_thread *thread
);

struct vl_thread *thread_preload_and_register (
		struct vl_thread_collection *collection,
		void *(*start_routine) (struct vl_thread *),
		int (*preload_routine) (struct vl_thread *),
		void (*poststop_routine) (const struct vl_thread *),
		int (*cancel_function) (struct vl_thread *),
		int start_priority,
		void *arg, const char *name
);
int thread_check_any_stopped (struct vl_thread_collection *collection);
void thread_free_double_pointer(void *arg);
void thread_free_single_pointer(void *arg);

//void thread_destroy (struct vl_thread_collection *collection, struct vl_thread *thread);

#endif
