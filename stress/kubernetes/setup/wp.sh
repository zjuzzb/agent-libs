#!/bin/bash
set -eu

function stop() {
	./kubectl delete namespace loris
}

function start() {
	./init.sh
}

case "$1" in
	start)
		start
	;;
	restart)
		stop
		start
	;;
	stop)
		stop
	;;
esac
