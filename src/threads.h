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
#include <sys/time.h>
#include <errno.h>


#define VL_THREADS_MAX 32

/* Tell a thread to cancel */
#define VL_THREAD_SIGNAL_KILL 9

/* Can only be set in thread control */
#define VL_THREAD_STATE_FREE 0

/* Set by the thread after we reserved it and by watchdog after thread has stopped after running */
#define VL_THREAD_STATE_STOPPED 1

/* Set after the thread is ready to start */
#define VL_THREAD_STATE_STARTING 2

/* Set by the thread itself when started */
#define VL_THREAD_STATE_RUNNING 3

/* Set by the thread itself after kill signal is detected, then looked for by watchdog */
#define VL_THREAD_STATE_STOPPING 4

/* Initialize mutexes */
void threads_init();

void threads_free();

struct vl_thread {
	pthread_t thread;
	uint64_t watchdog_time;
	pthread_mutex_t mutex;
	int signal;
	int state;
};

static inline uint64_t time_get_64() {
	struct timeval tv;
	double time_tmp;

	if (gettimeofday(&tv, NULL) != 0) {
		fprintf (stderr, "Error while getting time, cannot recover from this: %s\n", strerror(errno));
		exit (EXIT_FAILURE);
	}

	time_tmp = (tv.tv_sec * 1000000.0) + (tv.tv_usec);

	return time_tmp;
}

/* Threads should check this once in awhile to see if it should exit */
static inline int thread_check_kill_signal(struct vl_thread *thread) {
	int signal;
	pthread_mutex_lock(&thread->mutex);
	signal = thread->signal;
	pthread_mutex_unlock(&thread->mutex);
	return signal == VL_THREAD_SIGNAL_KILL;
}

/* Threads need to update this once in a while, if not it get's killed by watchdog */
static inline void update_watchdog_time(struct vl_thread *thread) {
	pthread_mutex_lock(&thread->mutex);
	thread->watchdog_time = time_get_64();
	pthread_mutex_unlock(&thread->mutex);
}

static inline uint64_t get_watchdog_time(struct vl_thread *thread) {
	uint64_t ret;
	pthread_mutex_lock(&thread->mutex);
	ret = thread->watchdog_time;
	pthread_mutex_unlock(&thread->mutex);
	return ret;
}

void thread_set_state(struct vl_thread *thread, int state);
void thread_set_signal(struct vl_thread *thread, int signal);
void thread_wait_state(struct vl_thread *thread, int signal);
int thread_start (void *(*start_routine) (void*), void *arg);


#endif
