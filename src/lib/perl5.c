/*

Read Route Record

Copyright (C) 2019 Atle Solbakken atle@goliathdns.no

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

#include <pthread.h>
#include <stddef.h>

#include <EXTERN.h>
#include <perl.h>

#include "perl5.h"

static pthread_mutex_t main_python_lock = PTHREAD_MUTEX_INITIALIZER;
static int perl5_users = 0;

static void __rrr_perl5_global_lock(void) {
	pthread_mutex_lock(&main_python_lock);
}

static void __rrr_perl5_global_unlock(void) {
	pthread_mutex_unlock(&main_python_lock);
}

int rrr_perl5_init3(int argc, char **argv, char **env) {
	__rrr_perl5_global_lock();
	if (++perl5_users == 1) {
		PERL_SYS_INIT3(&argc, &argv, &env);
	}
	__rrr_perl5_global_unlock();
	return 0;
}

int rrr_perl5_sys_term(void) {
	__rrr_perl5_global_lock();
	if (--perl5_users == 0) {
		PERL_SYS_TERM();
	}
	__rrr_perl5_global_unlock();
	return 0;
}

PerlInterpreter *rrr_perl5_construct(int argc, char **argv, char **env) {
	PerlInterpreter *ret = NULL;

	__rrr_perl5_global_lock();

	ret = perl_alloc();
	if (ret == NULL) {
		VL_MSG_ERR("Could not allocate perl5 interpreter in rrr_perl5_construct\n");
		goto out_unlock;
	}

	perl_construct(ret);
//	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	out_unlock:
	__rrr_perl5_global_unlock();

	out:
	return ret;
}

void rrr_perl5_destruct (PerlInterpreter *interpreter) {
	__rrr_perl5_global_lock();
	perl_destruct(interpreter);
	perl_free(interpreter);
	__rrr_perl5_global_unlock();
}
