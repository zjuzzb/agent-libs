#!/bin/bash
#set -eu

function stop() {
	docker rm -vf $(docker ps -qa)
	docker rm -vf $(docker ps -qa)
	docker rm -vf $(docker ps -qa)
	docker rm -vf $(docker ps -qa)
}

function start() {
#	docker run -d --name=srvc_node6 -e ROLE=node -e NAME=srvc_node6 -e CPU_OPS=10000 -e NC=0 us
#	docker run -d --name=srvc_node4 -e ROLE=node -e NAME=srvc_node4 -e CPU_OPS=1500000 -e IO_OPS=1000 -e NC=0 us
#	docker run -d --name=srvc_node3 -e ROLE=node -e NAME=srvc_node3 -e IO_OPS=1000 -e NC=0 us
#	docker run -d --name=srvc_node2 --link srvc_node4:srvc_next0 --link srvc_node3:srvc_next1 --link srvc_node6:srvc_next2 -e ROLE=node -e NAME=srvc_node2 -e NC=3 us
#	docker run -d --name=srvc_node5 --link srvc_node4:srvc_next0 --link srvc_node3:srvc_next1 -e ROLE=node -e NAME=srvc_node5 -e NC=2 us
#
#	docker run -d --name=s_movies --link srvc_node2:srvc_next0 --link srvc_node5:srvc_next1 -e ROLE=root -e NAME=s_movies -e NC=2 -e CPU_OPS=20000 us
#	docker run -d --name=s_users --link srvc_node2:srvc_next0 --link srvc_node6:srvc_next1 -e ROLE=root -e NAME=s_users -e NC=2 -e CPU_OPS=40000 us

	docker run -d --name=cnt_db -e ROLE=node -e NAME=s_db -e IO_OPS=100000 -e NC=0 us
	docker run -d --name=cnt_cache -e ROLE=node -e NAME=s_cache -e IO_OPS=20000 -e NC=0 us

	docker run -d --name=cnt_moviequeue -e CHILD_NAMES='[{"e":["dbquery"]}]' --link cnt_db:srvc_next0 -e ROLE=node -e NAME=s_moviequeue -e NC=1 us


	docker run -d --name=cnt_usermanager -e CHILD_NAMES='[{"e":["validate","getinfo","query"]}]' --link cnt_db:srvc_next0 -e ROLE=node -e NAME=s_usermanager -e NC=1 us
	docker run -d --name=cnt_moviemanager -e CHILD_NAMES='[{"e":["store","info","query"]}]' --link cnt_moviequeue:srvc_next0 -e ROLE=node -e NAME=s_moviemanager -e NC=1 us

	docker run -d --name=cnt_users --link cnt_usermanager:srvc_next0 --link cnt_cache:srvc_next1 -e CHILD_NAMES='[{"e":["login","stats","add","delete"]}, {"e":["user_cache"]}]' -e ROLE=root -e NAME=s_users -e NC=2 us

	docker run -d --name=cnt_movies --link cnt_moviemanager:srvc_next0 --link cnt_cache:srvc_next1 -e CHILD_NAMES='[{"e":["list","add","delete","rate"]}, {"e":["movie_cache"]}]' -e ROLE=root -e NAME=s_movies -e NC=2 us


#	docker run -d --name=srvc_node6 -e ROLE=node -e NAME=srvc_node6 -e NC=0 us
#	docker run -d --name=srvc_node2 --link srvc_node6:srvc_next0 -e ROLE=root -e NAME=srvc_node2 -e NC=1 us
#	docker run -d --name=srvc_node1 --link srvc_node6:srvc_next0 -e ROLE=root -e NAME=srvc_node1 -e NC=1 us

#	docker run -d --name=srvc_node5 -e ROLE=node -e NAME=srvc_node5 -e NC=0 us
#	docker run -d --name=srvc_node4 -e ROLE=node -e NAME=srvc_node4 -e NC=0 us
#	docker run -d --name=srvc_node3 -e ROLE=node -e NAME=srvc_node3 -e NC=0 us
#	docker run -d --name=srvc_node2 -e ROLE=node -e NAME=srvc_node2 -e NC=0 us
#	docker run -d --name=srvc_node1 --link srvc_node2:srvc_next0 --link srvc_node3:srvc_next1 --link srvc_node4:srvc_next2 --link srvc_node5:srvc_next3 -e ROLE=root -e NAME=srvc_node0 -e NC=4 -e SYNC=false us
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
