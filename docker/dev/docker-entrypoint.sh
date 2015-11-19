#!/bin/bash
#set -e

#need to test this function on all the supported OS
function am_i_a_k8s_delegated_node(){
	my_ip=$(hostname -i)
	if [ "${K8S_DELEGATED_NODE}" == "${my_ip}" ]; then
		return 0
	else
		return 1
	fi
}

echo "* Setting up /usr/src links from host"

for i in $(ls $SYSDIG_HOST_ROOT/usr/src)
do 
	ln -s $SYSDIG_HOST_ROOT/usr/src/$i /usr/src/$i
done

CONFIG_FILE=/opt/draios/etc/dragent.yaml

if [ ! -z "$ACCESS_KEY" ]; then
	echo "* Setting access key"
	
	if ! grep ^customerid $CONFIG_FILE > /dev/null 2>&1; then
		echo "customerid: $ACCESS_KEY" >> $CONFIG_FILE
	else
		sed -i "s/^customerid.*/customerid: $ACCESS_KEY/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$TAGS" ]; then
	echo "* Setting tags"

	if ! grep ^tags $CONFIG_FILE > /dev/null 2>&1; then
		echo "tags: $TAGS" >> $CONFIG_FILE
	else
		sed -i "s/^tags.*/tags: $TAGS/g" $CONFIG_FILE
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

if [ ! -z "$SECURE" ]; then
	echo "* Setting connection security"

	if ! grep ^ssl: $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl: $SECURE" >> $CONFIG_FILE
	else
		sed -i "s/^ssl:.*/ssl: $SECURE/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$CHECK_CERTIFICATE" ]; then
	echo "* Setting SSL certificate check level"

	if ! grep ^ssl_verify_certificate $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl_verify_certificate: $CHECK_CERTIFICATE" >> $CONFIG_FILE
	else
		sed -i "s/^ssl_verify_certificate.*/ssl_verify_certificate: $CHECK_CERTIFICATE/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$K8S_DELEGATED_NODE" ]; then
	if ! am_i_a_k8s_delegated_node; then
		echo "* Disabling k8s_autodetect"
		if ! grep ^k8s_autodetect $CONFIG_FILE > /dev/null 2>&1; then
			echo "k8s_autodetect: false" >> $CONFIG_FILE
		else
			sed -i "s/^k8s_autodetect.*/k8s_autodetect: false/g" $CONFIG_FILE
		fi
	fi
fi

if [ ! -z "$ADDITIONAL_CONF" ]; then
	echo "* Setting additional customer configuration"
	echo -e $ADDITIONAL_CONF | while read line; do
		if [[ $line == *"k8s_"* ]] && [[ ! -z "$K8S_DELEGATED_NODE" ]]; then
			if am_i_a_k8s_delegated_node; then
				echo "* Configuring $line"
				if ! grep ^$line $CONFIG_FILE > /dev/null 2>&1; then
					echo "$line" >> $CONFIG_FILE
				else
					sed -i "s/^$line.*/$line/g" $CONFIG_FILE
				fi
			else
				echo "* Not delegate node skypping k8s configuration"
				continue
			fi
		else
			echo "* Configuring $line"
			if ! grep ^$line $CONFIG_FILE > /dev/null 2>&1; then
				echo "$line" >> $CONFIG_FILE
			else
				sed -i "s/^$line.*/$line/g" $CONFIG_FILE
			fi
		fi
	done
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