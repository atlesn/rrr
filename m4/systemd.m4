# SYSTEMD_INIT()
# --------------
AC_DEFUN([SYSTEMD_INIT], [[

pkg-config systemd
if [ $? -eq 0 ]; then
	SYSTEMD_all_variables=$(pkg-config --print-variables systemd)
	for var in $SYSTEMD_all_variables; do
		value=$(pkg-config --variable="$var" systemd)
		if [ $? -ne 0 ]; then
			] AS_MESSAGE([error: Could not get systemd variable '$var' from pkg-config], [2]) [
			exit 1
		fi
		declare "SYSTEMD_$var=$value"
	done
	SYSTEMD_init=1
else
	] AS_MESSAGE([error: pkg-config for systemd failed in SYSTEMD@&t@_INIT], [2]) [
	exit 1
fi

]])

# SYSTEMD_DUMP_VARIABLES()
# ------------------------
AC_DEFUN([SYSTEMD_DUMP_VARIABLES], [[
	if [ "x$SYSTEMD_init" -ne "x1" ]; then
		] AC_MESSAGE([error: SYSTEMD_@&t@DUMP_VARIABLES used before SYSTEMD_@&t@INIT]) [
		exit 1
	fi
	for var in $SYSTEMD_all_variables; do
		magic_var="SYSTEMD_$var"
		echo "$magic_var=${!magic_var}"
	done
]])

# SYSTEMD_SYSTEM_UNIT_DIR()
# -------------------------
AC_DEFUN([SYSTEMD_SYSTEM_UNIT_DIR], [[$(
	if [ "x$SYSTEMD_init" -ne "x1" ]; then
		>&2 echo "SYSTEMD_@&t@SYSTEM_UNIT_DIR used before SYSTEMD_@&t@INIT";
		exit 1
	fi;
	echo "$SYSTEMD_systemdsystemunitdir")
]])
