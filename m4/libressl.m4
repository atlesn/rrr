AC_DEFUN([CHECK_LIBRESSL_LIBTLS], [
	for path in /usr/lib /usr/lib64 /usr/lib/libressl /usr/lib64/libressl /usr/local/lib /usr/local/lib64 /usr/local/lib/libressl /usr/local/lib64/libressl; do
		ldflags_orig=$LDFLAGS
		LDFLAGS=-L$path
		AC_CHECK_LIB(tls, tls_init, [ libressl_path=$path ], [])
		unset ac_cv_lib_tls_tls_init
		LDFLAGS=$ldflags_orig
	done
	if test "x$libressl_path" != "x"; then
		HAVE_LIBRESSL_LIBTLS=yes
		AC_DEFINE(HAVE_LIBRESSL_LIBTLS, [1], [LibreSSL libtls found])
		LIBRESSL_LIBTLS_LDFLAGS="-L$libressl_path -Wl,-rpath,$libressl_path"
		LIBRESSL_LIBTLS_LIBADD="-ltls"
	fi
])
