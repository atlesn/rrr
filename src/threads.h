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

#define VL_THREADS_MAX 32

#define VL_THREAD_SIGNAL_KILL 9

#define VL_THREAD_STATE_FREE 0
#define VL_THREAD_STATE_RUNNING 1
#define VL_THREAD_STATE_STARTING 1

struct vl_thread {
	pthread_t thread;
	int watchdog_counter;
	pthread_mutex_t mutex;
	int signal;
	int state;
};

void thread_watchdog(void *arg);
int thread_wait_signal(struct vl_thread *thread);
int thread_start (void *(*start_routine) (void*), void *arg);


#endif
