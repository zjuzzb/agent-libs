#!/bin/bash
set -eu

function stop() {
	docker kill $(docker ps -a | grep srvc_ | awk '{print $1 }')
	docker rm $(docker ps -a | grep srvc_ | awk '{print $1 }')
}

function start() {
	docker run -d --name=srvc_node4 -e ROLE=node -e NAME=srvc_node4 -e NC=0 us
	docker run -d --name=srvc_node3 -e ROLE=node -e NAME=srvc_node3 -e NC=0 us
	docker run -d --name=srvc_node2 --link srvc_node4:srvc_next0 --link srvc_node3:srvc_next1 -e ROLE=node -e NAME=srvc_node2 -e NC=2 us
	docker run -d --name=srvc_node1 --link srvc_node2:srvc_next0 -e ROLE=root -e NAME=srvc_node1 -e NC=1 us
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
