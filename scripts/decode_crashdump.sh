#!/bin/bash
set -eu

if [[ $# -lt 1 || $# -gt 1 ]]; then
	echo "Usage: $0 path_to_binary"
	echo "  path_to_binary: Binary (with symbols) that generated the stacktrace"
	exit 1
fi

echo "Paste your stacktrace here, and press CTRL+D when done"

input=$(cat)

echo "$input" | while IFS= read -r line
do
	if [[ $line == *dragent* ]]
	then
		exe=$1
	else
		exe=$(echo "$line" | cut -d\( -f1)
	fi

	symbol=$(echo "$line" | cut -d\( -f2 | cut -d\) -f1)

	gdb -batch -ex "info line *$symbol" $exe
done
