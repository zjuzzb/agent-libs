#!/bin/sh
#set -e

CONFIG_FILE=/opt/draios/etc/dragent.yaml
if [ -e $CONFIG_FILE ]
then
	PRECONFIGURED=1
	echo "* Found preconfigured dragent.yaml"
else
	PRECONFIGURED=0
fi
if [ ! -z "$ACCESS_KEY" ]; then
    echo "* Setting access key"

    if ! grep ^customerid $CONFIG_FILE > /dev/null 2>&1; then
        echo "customerid: $ACCESS_KEY" >> $CONFIG_FILE
    else
        sed -i "s/^customerid.*/customerid: $ACCESS_KEY/g" $CONFIG_FILE
    fi
fi

if [ ! -z "$COLLECTOR" ]; then
    echo "* Setting collector endpoint"

    if ! grep ^collector: $CONFIG_FILE > /dev/null 2>&1; then
        echo "collector: $COLLECTOR" >> $CONFIG_FILE
    else
        sed -i "s/^collector:.*/collector: $COLLECTOR/g" $CONFIG_FILE
    fi
fi

if [ ! -z "$COLLECTOR_PORT" ]; then
    echo "* Setting collector port"

    if ! grep ^collector_port $CONFIG_FILE > /dev/null 2>&1; then
        echo "collector_port: $COLLECTOR_PORT" >> $CONFIG_FILE
    else
        sed -i "s/^collector_port.*/collector_port: $COLLECTOR_PORT/g" $CONFIG_FILE
    fi
fi

if [ ! -z "$ADDITIONAL_CONF" ]
then
	if [ $PRECONFIGURED == 0 ]
	then
		echo "* Setting additional customer configuration:"
		echo -e "$ADDITIONAL_CONF"
		echo -e "$ADDITIONAL_CONF" >> $CONFIG_FILE
	else
		echo "* ADDITIONAL_CONF ignored"
	fi
fi

if [ -z "$HOSTNAME" ]
then
	HOSTNAME="unknown"
fi

if [ -z "$CONTAINER_NAME" ]
then
	echo "CONTAINER_NAME variable must be set"
	return 0
fi

if [ -z "$CONTAINER_ID" ]
then
	echo "CONTAINER_ID variable must be set"
	return 0
fi

if [ -z "$CONTAINER_IMAGE" ]
then
	echo "CONTAINER_IMAGE variable must be set"
	return 0
fi

if [ -z "$COLLECTOR_SSL" ]
then
	COLLECTOR_SSL=true
fi
if ! grep ^ssl $CONFIG_FILE > /dev/null 2>&1; then
	echo "ssl: $COLLECTOR_SSL" >> $CONFIG_FILE
fi

if [ $# -eq 0 ]
then
	echo "/opt/draios/bin/agentino --name $HOSTNAME --container-name $CONTAINER_NAME --container-id $CONTAINER_ID --image $CONTAINER_IMAGE $ADDITIONAL_ARGS"
	/opt/draios/bin/agentino --name $HOSTNAME --container-name $CONTAINER_NAME --container-id $CONTAINER_ID --image $CONTAINER_IMAGE $ADDITIONAL_ARGS
else
	exec "$@"
fi
