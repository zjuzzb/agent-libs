for x in `seq 100`; do
        kubectl delete namespace n$x
done
