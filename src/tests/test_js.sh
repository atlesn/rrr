#!/usr/bin/env bash

source ./testlib.sh
source ../../variables.sh

# We rely on checking return values and
# fail if we use -e. Reset in case it is
# already set.
set +e

if test "x$RRR_WITH_JS" != 'xno'; then
	PWD=`pwd`
	SCRIPT_SUCCESS=test_import_success.js
	SCRIPT_ONCE=test_import_once.mjs
	SCRIPT_SAME_MODULE=test_a.mjs
	SCRIPT_FAIL=test_import_fail.js
	JS="../rrr_js -d 1"
	TAIL=".then(() => {console.log('- OK')}).catch((msg) => {console.critical('- Loading failed: ' + msg)})";

	# Failing imports test
	echo "Test failing import"
	if ! $JS module < $SCRIPT_FAIL; then
		exit 1
	fi

	# Load module
	echo "Test successful import"
	if ! $JS module < $SCRIPT_SUCCESS; then
		exit 1
	fi

	# Load same module only once
	echo "Test successful import, same module only once"
	if ! $JS module < $SCRIPT_ONCE; then
		exit 1
	fi

	# Load module with import statement as script (should fail)
	echo "Test import statement in script"
	if $JS script < $SCRIPT_SUCCESS; then
		exit 1
	fi

	# Load with absolute path
	echo "Test absolute path"
	if ! echo "import('$PWD/$SCRIPT_SUCCESS')$TAIL;" | $JS module; then
		exit 1
	fi
	echo

	# Load with relative path
	echo "Test relative path"
	if ! echo "import('../tests/$SCRIPT_SUCCESS')$TAIL;" | $JS module; then
		exit 1
	fi
	echo

	# Load same module from parent and child
	echo "Test load same module from parent and child"
	if ! $JS module < $SCRIPT_SAME_MODULE; then
		exit 1
	fi

	./test_js_import_support.sh
	case $? in
		0)
			if ! $JS module < test_json_import.js; then
				# Dynamic json import test failed
				exit 1
			fi
			;;
		2)
			# OK, but assert import is not available
			;;
		*)
			# Error while checking await import availibility
			exit 1
			;;
	esac

	echo "Import tests succeeded"

	do_test_socket test_js.conf
	do_test_simple test_js_json.conf
else
	echo "Skipped test_js.conf and test_js_json.conf as JS support is missing"
fi
