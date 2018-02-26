/*

Voltage Logger

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

#ifndef VL_THREADS_H
#define VL_THREADS_H

#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "vl_time.h"

#define VL_THREADS_MAX 32

/* Tell a thread to cancel */
#define VL_THREAD_SIGNAL_KILL 9

/* Can only be set in thread control */
#define VL_THREAD_STATE_FREE 0

/* Set by the thread after we reserved it and by thread cleanup */
#define VL_THREAD_STATE_STOPPED 1

/* Set after the thread is ready to start */
#define VL_THREAD_STATE_STARTING 2

/* Set by the thread itself when started */
#define VL_THREAD_STATE_RUNNING 3

/* Thread has been asked to stop, set by watchdog */
#define VL_THREAD_STATE_ENCOURAGE_STOP 4

/* Thread has to do a few cleanup operations before stopping */
#define VL_THREAD_STATE_STOPPING 5

// Milliseconds
#define VL_THREAD_WATCHDOG_FREEZE_LIMIT 5000
#define VL_THREAD_WATCHDOG_KILLTIME_LIMIT 1000

/* Initialize mutexes */
void threads_init();

/* Stop threads */
void threads_stop();

/* Free resources - RUN STOP FIRST */
void threads_destroy();

struct vl_thread {
	pthread_t thread;
	uint64_t watchdog_time;
	pthread_mutex_t mutex;
	int signal;
	int state;
	int is_watchdog;
	char thread_private_memory[];
};

struct vl_thread_start_data {
	void *(*start_routine) (struct vl_thread_start_data *);
	struct vl_thread *thread;
	void *private_arg;
};

static inline void thread_lock(struct vl_thread *thread) {
	//printf ("Thread %p lock\n", thread);
	pthread_mutex_lock(&thread->mutex);
}

static inline void thread_unlock(struct vl_thread *thread) {
//	printf ("Thread %p unlock\n", thread);
	pthread_mutex_unlock(&thread->mutex);
}

/* Watchdog checks if thread should be killed */
static inline int thread_check_kill_signal(struct vl_thread *thread) {
	int signal;
	thread_lock(thread);
	signal = thread->signal;
	thread_unlock(thread);;
	return signal == VL_THREAD_SIGNAL_KILL;
}

/* Threads should check this once in awhile to see if it should exit,
 * set by watchdog after it detects kill signal. */
static inline int thread_check_encourage_stop(struct vl_thread *thread) {
	int state;
	thread_lock(thread);
	state = thread->state;
	thread_unlock(thread);;
	return state == VL_THREAD_STATE_ENCOURAGE_STOP;
}

/* Threads need to update this once in a while, if not it get's killed by watchdog */
static inline void update_watchdog_time(struct vl_thread *thread) {
	thread_lock(thread);
	thread->watchdog_time = time_get_64();
	thread_unlock(thread);;
}

static inline uint64_t get_watchdog_time(struct vl_thread *thread) {
	uint64_t ret;
	thread_lock(thread);
	ret = thread->watchdog_time;
	thread_unlock(thread);;
	return ret;
}

static void thread_set_state(struct vl_thread *thread, int state) {
	thread_lock(thread);

	printf ("Thread %p set state %i\n", thread, state);

	if (state == VL_THREAD_STATE_STARTING) {
		fprintf (stderr, "Attempted to set STARTING state of thread outside reserve_thread function\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_FREE) {
		fprintf (stderr, "Attempted to set FREE state of thread outside reserve_thread function\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_RUNNING && thread->state != VL_THREAD_STATE_STARTING) {
		fprintf (stderr, "Attempted to set RUNNING state of thread while it was not in STARTING state\n");
		exit (EXIT_FAILURE);
	}
	if (state == VL_THREAD_STATE_ENCOURAGE_STOP && thread->state != VL_THREAD_STATE_RUNNING) {
		fprintf (stderr, "Warning: Attempted to set ENCOURAGE STOP state of thread while it was not in RUNNING state\n");
		goto nosetting;
	}
	if (state == VL_THREAD_STATE_STOPPING && (thread->state != VL_THREAD_STATE_ENCOURAGE_STOP && thread->state != VL_THREAD_STATE_RUNNING)) {
		fprintf (stderr, "Warning: Attempted to set STOPPING state of thread %p while it was not in ENCOURAGE STOP or RUNNING state\n", thread);
		goto nosetting;
	}
	if (state == VL_THREAD_STATE_STOPPED && (thread->state != VL_THREAD_STATE_ENCOURAGE_STOP && thread->state != VL_THREAD_STATE_STOPPING)) {
		fprintf (stderr, "Warning: Attempted to set STOPPED state of thread %p while it was not in ENCOURAGE STOP or STOPPING state\n", thread);
		goto nosetting;
	}


	thread->state = state;

	nosetting:
	thread_unlock(thread);;
}

static inline void thread_set_signal(struct vl_thread *thread, int signal) {
	printf ("Thread %p set signal %d\n", thread, signal);
	thread_lock(thread);
	thread->signal = signal;
	thread_unlock(thread);
}

static inline int thread_get_state(struct vl_thread *thread) {
	int state;
	thread_lock(thread);
	state = thread->state;
	thread_unlock(thread);;
	return state;
}

static inline int thread_get_signal(struct vl_thread *thread) {
	int signal;
	thread_lock(thread);
	signal = thread->signal;
	thread_unlock(thread);;
	return signal;
}

static inline void thread_set_stopping(void *arg) {
	struct vl_thread *thread = arg;
	thread_set_state(thread, VL_THREAD_STATE_STOPPING);
}

struct vl_thread *thread_start (void *(*start_routine) (struct vl_thread_start_data *), void *arg);

#endif
