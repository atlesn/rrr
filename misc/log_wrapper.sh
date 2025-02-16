#!/bin/sh

while IFS= read -r line; do
	echo "Wrapper: $line"
done
