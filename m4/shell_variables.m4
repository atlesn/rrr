dnl 
dnl Read Route Record
dnl 
dnl Copyright (C) 2020 Atle Solbakken atle@goliathdns.no
dnl 
dnl This program is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl 
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl  

dnl Use /bin/echo to avoid problems with -e flag

# SHELL_VARS_INIT(FILENAME)
# --------------
AC_DEFUN([SHELL_VARS_INIT], [
	shell_vars_in_reset () {
		/bin/echo -e "#!/bin/sh\n\n# DO NOT DELETE THIS FILE\n" > $1.in
	}
	SHELL_VARS_FILENAME=$1
	/bin/echo -e "#!/bin/sh\n\nSHELL_VARS_SET=1\n" > $SHELL_VARS_FILENAME.in
])

# SHELL_VARS_EXPORT(VARIABLE, VALUE)
# --------------
AC_DEFUN([SHELL_VARS_EXPORT], [
	/bin/echo -n $1 >> $SHELL_VARS_FILENAME.in
	/bin/echo -n "=" >> $SHELL_VARS_FILENAME.in
	/bin/echo $2 >> $SHELL_VARS_FILENAME.in
])

# SHELL_VARS_OUTPUT()
# --------------
AC_DEFUN([SHELL_VARS_OUTPUT], [
	AC_CONFIG_FILES([variables.sh],[chmod +x variables.sh])
])

# SHELL_VARS_CLEANUP()
# --------------
AC_DEFUN([SHELL_VARS_CLEANUP], [
	shell_vars_in_reset $SHELL_VARS_FILENAME
])

