#1/bin/sh

if echo "import('nonexistent').catch();" | ../rrr_js; then
	echo "Dynamic import works" 1>&2
else
	echo "Dynamic import does not work" 1>&2
	# Return one for dynamic import not available
	exit 1
fi

if echo "await import('nonexistent').catch();" | ../rrr_js; then
	echo "Dynamic import with await works" 1>&2
else
	echo "Dynamic import with await does not work" 1>&2
	# Return two for await not available
	exit 2
fi

# Return zero for all features available
exit 0
