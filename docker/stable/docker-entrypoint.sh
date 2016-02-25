#!/bin/bash
#set -e

function am_i_a_k8s_delegated_node(){
	ip_addresses=$(hostname --all-ip-addresses)
	for ip in ${ip_addresses[@]}
	do
		if [ "${K8S_DELEGATED_NODE}" == "${ip}" ]; then
			return 0
		fi
	done
	return 1
}

echo "* Setting up /usr/src links from host"

for i in $(ls $SYSDIG_HOST_ROOT/usr/src)
do 
	ln -s $SYSDIG_HOST_ROOT/usr/src/$i /usr/src/$i
done

CONFIG_FILE=/opt/draios/etc/dragent.yaml

if ! mount | grep $CONFIG_FILE > /dev/null 2>&1; then
	rm -f $CONFIG_FILE

	if [ ! -z "$ACCESS_KEY" ]; then
		echo "* Setting access key"
		echo "customerid: $ACCESS_KEY" >> $CONFIG_FILE
	fi

	if [ ! -z "$TAGS" ]; then
		echo "* Setting tags"
		echo "tags: $TAGS" >> $CONFIG_FILE
	fi

	if [ ! -z "$COLLECTOR" ]; then
		echo "* Setting collector endpoint"
		echo "collector: $COLLECTOR" >> $CONFIG_FILE
	fi

	if [ ! -z "$COLLECTOR_PORT" ]; then
		echo "* Setting collector port"
		echo "collector_port: $COLLECTOR_PORT" >> $CONFIG_FILE
	fi

	if [ ! -z "$SECURE" ]; then
		echo "* Setting connection security"
		echo "ssl: $SECURE" >> $CONFIG_FILE
	fi

	if [ ! -z "$CHECK_CERTIFICATE" ]; then
		echo "* Setting SSL certificate check level"
		echo "ssl_verify_certificate: $CHECK_CERTIFICATE" >> $CONFIG_FILE
	fi

	if [ ! -z "$K8S_DELEGATED_NODE" ] && [ ! -z "$K8S_API_URI" ]; then
		if am_i_a_k8s_delegated_node; then
			echo "* Setting k8s api URI"
			echo "k8s_uri: $K8S_API_URI" >> $CONFIG_FILE
		fi
	fi

	if [ ! -z "$ADDITIONAL_CONF" ]; then
		echo "* Setting additional customer configuration:"
		echo -e "$ADDITIONAL_CONF"
		echo -e "$ADDITIONAL_CONF" >> $CONFIG_FILE
	fi
else
	echo "* Using bind-mounted dragent.yaml"
fi

echo "* Mounting memory cgroup fs"
mkdir -p $SYSDIG_HOST_ROOT/cgroup/memory
mount -t cgroup -o memory,ro none $SYSDIG_HOST_ROOT/cgroup/memory

if [ $# -eq 0 ]; then
	if ! /opt/draios/bin/sysdigcloud-probe-loader; then
		exit 1
	fi

	exec /opt/draios/bin/dragent
else
	exec "$@"
fi