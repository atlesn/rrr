AC_DEFUN([CHECK_LIBRESSL_LIBTLS], [
	AC_MSG_CHECKING([LibreSSL header search paths])
	libressl_header_search_paths="/usr/include /usr/include/libressl /usr/local/include /usr/local/include/libressl"
	AC_MSG_RESULT([$libressl_header_search_paths])

	AC_MSG_CHECKING([LibreSSL headers])
	for path in $libressl_header_search_paths; do
		path_full=$path/tls.h
		if test -f $path_full; then
			libressl_header_path=$path
			break
		fi
	done

	if test "x$libressl_header_path" != "x"; then
		LIBRESSL_LIBTLS_CFLAGS=-I$libressl_header_path
		AC_MSG_RESULT([$libressl_header_path])
		AC_DEFINE(HAVE_LIBRESSL_LIBTLS, [1], [LibreSSL libtls found])
	fi

	AC_MSG_CHECKING([LibreSSL library search paths])
	libressl_library_search_paths="/usr/lib /usr/lib64 /usr/lib/libressl /usr/lib64/libressl /usr/local/lib /usr/local/lib64 /usr/local/lib"
	AC_MSG_RESULT([$libressl_library_search_paths])

	for path in $libressl_library_search_paths; do
		ldflags_orig=$LDFLAGS
		LDFLAGS=-L$path

		AC_CHECK_LIB(tls, tls_init, [ libressl_path=$path ], [])
		unset ac_cv_lib_tls_tls_init

		LDFLAGS=$ldflags_orig

		if test "x$libressl_path" != "x"; then
			break
		fi
	done

	AC_MSG_CHECKING([LibreSSL library by -ltls])
	if test "x$libressl_path" != "x"; then
		HAVE_LIBRESSL_LIBTLS=yes
		LIBRESSL_LIBTLS_LDFLAGS="-L$libressl_path -Wl,-rpath,$libressl_path"
		LIBRESSL_LIBTLS_LIBADD="-ltls"
		AC_MSG_RESULT([found])
	else
		AC_MSG_RESULT([not found])
		AC_MSG_CHECKING([LibreSSL library long name])
		for path in $libressl_search_paths; do
			for path_full in $path/libtls.*; do
				cflags_orig=$CFLAGS
				ldflags_orig=$LDFLAGS
				CFLAGS=-I$libressl_header_path
				LDFLAGS=-l$path_full

				AC_RUN_IFELSE([
					AC_LANG_SOURCE([[
						#include <tls.h>
						int main(int argc, const char **argv) {
							tls_init();
							return 0;
						}
					]])
				], [ libressl_path_full=$path ], [])

				CFLAGS=$cflags_orig
				LDFLAGS=$ldflags_orig

				if test "x$libressl_path_full" != "x"; then
					break
				fi
			done
			if test "x$libressl_path_full" != "x"; then
				break
			fi
		done
		if test "x$libressl_path_full" != "x"; then
			AC_MSG_RESULT([$libressl_path_full])
			HAVE_LIBRESSL_LIBTLS=yes
			LIBRESSL_LIBTLS_LDFLAGS=""
			LIBRESSL_LIBTLS_LIBADD="$libressl_path_full"
		else
			AC_MSG_RESULT([not found])
		fi
	fi
])
