# usage: must have backend running locally. must have compiled fake agent. must have pbs in
# test_pbs directory, with each test case in a subfolder, with the input dams files in a
# subdirectory under that.
#
# first arg is path to fake agent binary
# second arg is entire cookie used when talking to front end. probably put this in quotes
#
# example:
# ./aggregated_pb_maker.sh ~/10s/fakeagent/dist/bin/ "wfx_unq=fia7GrGz6xZlIf2S; intercom-id-nbedguxv=e27af63c-c5f4-4aa2-897f-e0fb2a0f89aa; sysdig-token-sdc=dGVzdCU0MGRyYWlvcy5jb206MEJLOVZTdnNGd3BnTUxRQkR0V2JlZyUzRCUzRA; SESSION_SDC=ac95-d061-4e4b-aa30-2f8e08a13740482e; intercom-session-nbedguxv=SUN6TUpReHRrL293aVovb3lYN2NwWTA3Tm5nT0tCenpxNExTeU8rUlJHdHhoYnhJcjRjU1JVTU5tVEJQeXZ4NS0tMVRhYnNCZUVaelN0Z3Zkcyt5Sy9qZz09--6df27a60e35b8c1eefe07453cb026b2c4e15c33d; sysdig-jwt-sdc=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzeXNkaWciLCJzdWIiOiJ0ZXN0QGRyYWlvcy5jb20iLCJ1c2VyIjp7InVzZXJJZCI6MSwiY3VzdG9tZXJJZCI6MSwidGVhbUlkIjoxLCJwcm9kdWN0IjoiU0RDIn0sImlhdCI6MTU2NzYxODczOSwiZXhwIjoxNTY3NjIwNTM5fQ.jYzdx2nuLmReFMxS66YJgwCTpTX8XuB7uLiTW6kVxNI"
#
# pbs dumped to /tmp/1, and then overwrites the aggr_pbs directory
# don't kill while the fake agent is running, otherwise a PITA. it's a java process if you
# must find it in ps.

PATH_TO_FAKE_AGENT=$1
COOKIE=$2
rm -r /tmp/1
rm -r aggr_pbs
mkdir aggr_pbs
for i in ./test_pbs/*
do
    LAST_DIR=$(basename $i)
    $PATH_TO_FAKE_AGENT/fakeagent --customer-id 8c3a3eef-5f95-4937-bc72-f2bb9a48556a --port 6666 --override-machine-id --tick=1 -d $i &
    FAPID=$!
    sleep 10
    curl --header "X-Sysdig-Product: SDC" -H "Content-Type: application/json" -H "Cookie: $COOKIE" -v -G "localhost:9000/api/admin/agent/dump/customer/start/1?duration=10000&dumpAggregated=true"
    sleep 10
    curl --header "X-Sysdig-Product: SDC" -H "Content-Type: application/json" -H "Cookie: $COOKIE" -v -G "localhost:9000/api/admin/agent/dump/customer/stop/1?duration=10000&dumpAggregated=true"
    mv /tmp/1 aggr_pbs/$LAST_DIR
    kill $FAPID
    sleep 5
    COUNT=0
    for i in aggr_pbs/$LAST_DIR/raw/*.dam
    do
	mv $i aggr_pbs/$LAST_DIR/raw/input_$COUNT.dam
	COUNT=$((COUNT+1))
    done
    mv aggr_pbs/$LAST_DIR/raw/aggregated/*.dam aggr_pbs/$LAST_DIR/aggregated.dam
    rmdir aggr_pbs/$LAST_DIR/raw/aggregated
done

