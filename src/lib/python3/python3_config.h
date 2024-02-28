/*

Read Route Record

Copyright (C) 2019-2024 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_PYTHON3_CONFIG_H
#define RRR_PYTHON3_CONFIG_H

#include "python3_headers.h"

struct rrr_settings;
struct rrr_settings_used;

PyObject *rrr_python3_config_new (struct rrr_settings *settings, struct rrr_settings_used *settings_used);

#endif /* RRR_PYTHON3_CONFIG_H */
