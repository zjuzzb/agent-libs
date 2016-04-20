#!/bin/bash
#set -x
if [ -z $ENV_DATA_DIR ]; then
  ENV_DATA_DIR=$PWD/envs_data
fi
if [ -z $ENV_DIR ]; then
  ENV_DIR=$PWD/envs
fi
if [ -z $DOCKER_IMAGE ]; then
  DOCKER_IMAGE=agent
fi
if [ -z $AGENT_SAMPLES ]; then
  AGENT_SAMPLES=10
fi

env_start() {
  pushd $1
  if [ -e docker-compose.yaml ]; then
    docker-compose rm -fv
    docker-compose up -d
    sleep 10
  fi
  popd
}

env_stop() {
  pushd $1
  if [ -e docker-compose.yaml ]; then
    docker-compose kill
    docker-compose rm -fv
  fi
  popd
}

rm -fr $ENV_DATA_DIR
mkdir -p $ENV_DATA_DIR
for env_dir in $ENV_DIR/*; do
  env_name=`basename $env_dir`

  # setup env
  env_start $env_dir

  docker rm -f sysdig-agent
  docker run -d --name sysdig-agent --privileged --net host --pid host -e ACCESS_KEY=342b8432-12ee-4b75-915f-df5422e40de9 \
      -e COLLECTOR=collector-staging.sysdigcloud.com -v /var/run/docker.sock:/host/var/run/docker.sock \
      -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro \
      -v /usr:/host/usr:ro -e ADDITIONAL_CONF="metricsfile: { location: metrics }\n`cat $env_dir/additional_conf.yaml 2> /dev/null`" $DOCKER_IMAGE
  echo -n "* wait until the agent is up"
  agent_ok=0
  for i in `seq 60`; do
    if docker logs sysdig-agent 2>&1| grep -q "to collector"; then
      agent_ok=1
      break
    fi
    echo -n "."
    sleep 1
  done
  echo
  if [ $agent_ok == 1 ]; then
    echo "* agent ready, capture a couple of samples"
    sleep $AGENT_SAMPLES
  else
    echo "* error on loading agent"
    exit 1
  fi

  docker stop sysdig-agent

  # copy data
  mkdir -p $ENV_DATA_DIR/$env_name
  docker cp sysdig-agent:/opt/draios/metrics $ENV_DATA_DIR/$env_name/
  docker cp sysdig-agent:/opt/draios/logs $ENV_DATA_DIR/$env_name/

  # cleanup
  env_stop $env_dir
done