#!/bin/bash

while true
do

for((i = 0; i < 1000; ++i)); do
    echo "fire-hose-metric-${i}:1|c" > /dev/udp/127.0.0.1/8125
done

sleep 1

done
