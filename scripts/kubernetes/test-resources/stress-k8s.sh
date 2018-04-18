for x in `seq 100`; do
        NAMESPACE="n$x"
        kubectl create namespace $NAMESPACE
	for j in `seq 100`; do
		kubectl -n $NAMESPACE run pause$j --image=luca3m/pause --replicas=0
	done
done
