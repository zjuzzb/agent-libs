#!/bin/bash
#set -e

CONFIG_FILE=/opt/draios/etc/dragent.yaml
if [ -e $CONFIG_FILE ]
then
	PRECONFIGURED=1
	echo "* Found preconfigured dragent.yaml"
else
	PRECONFIGURED=0
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
	HOSTNAME="unknown hostname"
fi

if [ $# -eq 0 ]
then
	exec /opt/draios/bin/agentino
else
	exec "$@"
fi
