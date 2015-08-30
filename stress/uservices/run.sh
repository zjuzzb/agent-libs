#!/bin/bash
set -eu

function stop() {
	docker kill $(docker ps -a | grep srvc_ | awk '{print $1 }')
	docker rm $(docker ps -a | grep srvc_ | awk '{print $1 }')
}

function start() {
	docker run -d --name=srvc_node6 -e ROLE=node -e NAME=srvc_node6 -e CPU_OPS=10000 -e NC=0 us
	docker run -d --name=srvc_node4 -e ROLE=node -e NAME=srvc_node4 -e CPU_OPS=15000 -e IO_OPS=1000 -e NC=0 us
	docker run -d --name=srvc_node3 -e ROLE=node -e NAME=srvc_node3 -e IO_OPS=1000 -e NC=0 us
	docker run -d --name=srvc_node2 --link srvc_node4:srvc_next0 --link srvc_node3:srvc_next1 --link srvc_node6:srvc_next2 -e ROLE=node -e NAME=srvc_node2 -e NC=3 us
	docker run -d --name=srvc_node5 --link srvc_node4:srvc_next0 --link srvc_node3:srvc_next1 -e ROLE=node -e NAME=srvc_node5 -e NC=2 us
	docker run -d --name=srvc_node1 --link srvc_node2:srvc_next0 --link srvc_node5:srvc_next1 -e ROLE=root -e NAME=srvc_node1 -e NC=2 -e CPU_OPS=20000 us
#	docker run -d --name=srvc_node7 --link srvc_node2:srvc_next0 --link srvc_node6:srvc_next1 -e ROLE=root -e NAME=srvc_node7 -e NC=2 -e CPU_OPS=100000 us

#	docker run -d --name=srvc_node6 -e ROLE=node -e NAME=srvc_node6 -e NC=0 us
#	docker run -d --name=srvc_node2 --link srvc_node6:srvc_next0 -e ROLE=node -e NAME=srvc_node2 -e NC=1 us
#	docker run -d --name=srvc_node1 --link srvc_node2:srvc_next0 -e ROLE=root -e NAME=srvc_node1 -e NC=1 us
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
	build)
		docker build -t us .
		stop
		start
	;;
esac
