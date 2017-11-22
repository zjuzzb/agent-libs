#!/bin/bash

CUSTOMERID=$1
if [ ! -z $2 ]; then
  FIRST_FOUND=$2
fi

mkdir -p $CUSTOMERID
for i in `seq 12`; do 
  echo "Connecting to collector-$i.."
  scp -r production-collector-$i:/tmp/$CUSTOMERID/ $CUSTOMERID/$i
done
