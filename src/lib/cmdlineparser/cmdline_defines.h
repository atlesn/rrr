/*

Command Line Parser

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

#ifndef CMDLINE_DEFINES_H
#define CMDLINE_DEFINES_H

typedef unsigned long int cmd_arg_count;
typedef unsigned long int cmd_arg_size;
typedef unsigned long int cmd_conf;

#define CMD_CONFIG_DEFAULTS			0
#define CMD_CONFIG_COMMAND			(1<<0)

#define CMD_ARG_FLAG_NO_ARGUMENT	(0)
#define CMD_ARG_FLAG_HAS_ARGUMENT	(1<<0)
#define CMD_ARG_FLAG_SPLIT_COMMA	(1<<1)
#define CMD_ARG_FLAG_NO_FLAG		(1<<2)
#define CMD_ARG_FLAG_NO_FLAG_MULTI	(1<<4)
#define CMD_ARG_FLAG_ALLOW_EMPTY	(1<<5)

#endif /* CMDLINE_DEFINES_H */
