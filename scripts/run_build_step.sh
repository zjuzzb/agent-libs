#!/bin/bash

SECTION=$1

shift

$@ > log-$SECTION.txt 2>&1

if [[ $? == 0 ]]; then
    echo "$SECTION completed without errors"
else
    cat log-$SECTION.txt
    exit 1
fi


