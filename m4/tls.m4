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

# TLS_CHECKS()
# ------------
AC_DEFUN([TLS_CHECKS], [
	AC_MSG_CHECKING([for TLS implementation TLS1_3_VERSION])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/ssl.h>
			int main (int argc, char *argv[]) {
				int a = TLS1_3_VERSION;
				return 0;
			}
		]])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_TLS1_3_VERSION], [1], [TLS implementation supports OpenSSL-style TLSv1.3])
	], [
		AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([for TLS implementation TLS1_2_VERSION])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <openssl/ssl.h>
			int main (int argc, char *argv[]) {
				int a = TLS1_2_VERSION;
				return 0;
			}
		]])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_TLS1_2_VERSION], [1], [TLS implementation supports OpenSSL-style TLSv1.2])
	], [
		AC_MSG_RESULT([no])
	])
])
