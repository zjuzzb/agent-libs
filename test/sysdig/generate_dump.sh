#!/bin/bash

# This file can test tcpdump-like rotation features.

# Author: Samuele Pilleri

# PARAMS #
# -C : file size
# -G : time
# -W : rotation
# -w : file
# -e : events

# EXIT CODES #
#  -> 0 : all right
#  -> 10: failed Test 1
#  -> 11: failed Test 2
#  -> 12: failed Test 3
#  -> 13: failed Test 4
#  -> 14: failed Test 5
#  -> 15: failed Test 6
#  -> 16: failed Test 7
#  -> 17: failed Test 8
#  -> 50: received SIGINT or SIGTERM signal

function quit {
	printf "Clean up everything..."
	kill $(jobs -p) > /dev/null 2> /dev/null
	rm -rf dumps
	printf " [OK]\n"
	exit $1
}

printf "Setting up the environment..."
trap 'quit 50' SIGINT SIGTERM
mkdir dumps
printf " [OK]\n"

printf "Starting background deamons for generating events..."
(dd if=/dev/urandom of=/dev/null bs=1024) &
printf " [OK]\n"

### TEST 1 ###
printf "Simple file generation every n-megabytes..."
timeout 15 sysdig -C 1 -w dumps/dump.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -gt 100 ]]; then
	printf " [OK]\n"
else
	printf " [FAIL]\n"
	quit 10
fi
rm -f dumps/*

### TEST 2 ###
printf "Rotation on n-files every m-megabytes..."
timeout 15 sysdig -C 1 -W 5 -w dumps/dump.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -eq 6 ]]; then	# 6 because ls -l adds one line
	printf " [OK]\n"
else
	printf " [FAIL]\n"
	quit 11
fi
rm -f dumps/*

### TEST 3 ###
printf "Dump every n-seconds with specified name-format..."
timeout 15 sysdig -G 3 -w dumps/dump%T.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -eq 6 || "$FILECNT" -eq 7 ]]; then # 6 because ls -l adds one line, 7 because the SIGTERM interrupt could arrive one millisecond too late
        printf " [OK]\n"
else
        printf " [FAIL]\n"
        quit 12
fi
rm -f dumps/*

### TEST 4 ###
printf "Dump every n-seconds max file limit with specified name-format..."
timeout 15 sysdig -G 3 -W 5 -w dumps/dump%T.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -eq 6 || "$FILECNT" -eq 7 ]]; then # It should always be 6 (remember ls) but custom file name does NOT find any file to override
        printf " [OK]\n"
else
        printf " [FAIL]\n"
        quit 13
fi
rm -f dumps/*

### TEST 5 ###
printf "Dump every n-seconds with sequential name..."
timeout 20 sysdig -G 3 -w dumps/dump.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -gt 5 && "$FILECNT" -lt 10 ]]; then
        printf " [OK]\n"
else
        printf " [FAIL]\n"
        quit 14
fi
rm -f dumps/*

### TEST 6 ###
printf "Dump every n-seconds max file limit with sequential name..."
timeout 15 sysdig -G 3 -W 5 -w dumps/dump.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -eq 6 ]]; then # 6 because ls -l adds one line
        printf " [OK]\n"
else
        printf " [FAIL]\n"
        quit 15
fi
rm -f dumps/*

### TEST 7 ###
printf "Dump every n-events..."
timeout 10 sysdig -e 1000 -w dumps/dump.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -gt 100 ]]; then
        printf " [OK]\n"
else
        printf " [FAIL]\n"
        quit 16
fi
rm -f dumps/*

### TEST 8 ###
printf "Dump every n-events in a m-sized buffer ring..."
timeout 10 sysdig -e 1000 -W 5 -w dumps/dump.scap
FILECNT="$(ls -l dumps | wc -l)"
if [[ "$FILECNT" -eq 6 ]]; then # 6 because ls -l adds one line
        printf " [OK]\n"
else
        printf " [FAIL]\n"
        quit 17
fi
rm -f dumps/*

# All tests passed
printf "\nAll tests passed!\n\n"
quit 0


# KNOWN BUGS:
#  -> if -G (with format) and -r are specified then the first file name is first_dump.scap
