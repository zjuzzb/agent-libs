#!/bin/bash

SLEEP_TIME=$1
RC=$2

if [ -z $SLEEP_TIME ]; then
    SLEEP_TIME=1
fi

if [ -z $RC ]; then
    RC=0
fi

sleep $SLEEP_TIME

echo "This is to stdout"
echo "This is to stderr" >&2
exit $RC


