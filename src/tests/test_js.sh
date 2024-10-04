#!/bin/bash

set -e

source ./testlib.sh
source ../../variables.sh

if test "x$RRR_WITH_JS" != 'xno'; then
	PWD=`pwd`
	SCRIPT_SUCCESS=test_import_success.js
	SCRIPT_FAIL=test_import_fail.js
	TAIL=".then(() => {console.log('- OK')}).catch((msg) => {console.critical('- Loading failed: ' + msg)})";

	# Failing imports test
	echo "Test failing import"
	if ! ../rrr_js module < $SCRIPT_FAIL; then
		# Import test failed
		exit 1
	fi

	# Load module
	echo "Test successful import"
	if ! ../rrr_js module < $SCRIPT_SUCCESS; then
		# Import test failed
		exit 1
	fi

	# Load module with import statement as script (should fail)
	echo "Test import statement in script"
	if ../rrr_js script < $SCRIPT_SUCCESS; then
		# Import test failed
		exit 1
	fi

	# Load with absolute path
	echo "Test absolute path"
	if ! echo "import('$PWD/$SCRIPT_SUCCESS')$TAIL;" | ../rrr_js module; then
		# Import test failed
		exit 1
	fi
	echo

	# Load with relative path
	echo "Test relative path"
	if ! echo "import('../tests/$SCRIPT_SUCCESS')$TAIL;" | ../rrr_js module; then
		# Import test failed
		exit 1
	fi
	echo

	./test_js_import_support.sh
	case $? in
		0)
			if ! ../rrr_js module < test_json_import.js; then
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
