/*

Voltage Logger

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

#include "global.h"

struct rrr_global_config rrr_global_config;

void rrr_init_global_config(unsigned int debuglevel, unsigned int no_watcdog_timers, unsigned int no_thread_restart) {
	rrr_global_config.debuglevel = debuglevel;
	rrr_global_config.no_watchdog_timers = no_watcdog_timers;
	rrr_global_config.no_thread_restart = no_thread_restart;
}
