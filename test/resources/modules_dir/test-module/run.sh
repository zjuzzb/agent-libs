#!/bin/bash

SLEEP_TIME=$1

if [ -z $SLEEP_TIME ]; then
    SLEEP_TIME=1
fi

sleep $SLEEP_TIME


