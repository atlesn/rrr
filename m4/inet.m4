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

# INET_CHECKS()
# -------------
AC_DEFUN([INET_CHECKS], [
	AC_MSG_CHECKING([for Linux struct sockaddr_in6])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <netinet/in.h>
			#include <arpa/inet.h>
			#include <stdio.h>
			int main (int argc, char *argv[]) {
				struct sockaddr_in6 source_in6 = { 0 };
				source_in6.sin6_addr.__in6_u.__u6_addr32[0] = 0;
				return 0;
			}
		]])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_INET_IN6_LINUX], [1], [Linux-style struct sockaddr_in6 present])
	], [
		AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([for BSD struct sockaddr_in6])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <netinet/in.h>
			#include <arpa/inet.h>
			#include <stdio.h>
			int main (int argc, char *argv[]) {
				struct sockaddr_in6 source_in6 = { 0 };
				source_in6.sin6_addr.__u6_addr.__u6_addr32[0] = 0;
				return 0;
			}
		]])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_INET_IN6_BSD], [1], [BSD-style struct sockaddr_in6 present])
	], [
		AC_MSG_RESULT([no])
	])
])
