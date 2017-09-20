for x in `seq 100`; do
        NAMESPACE="n$x"
        kubectl create namespace $NAMESPACE
        kubectl -n $NAMESPACE create -f redis-deployment.yaml 
done
