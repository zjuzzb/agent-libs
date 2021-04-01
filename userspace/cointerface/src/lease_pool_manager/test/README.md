This test has been designed for being run manually on a real Kubernetes cluster.

# Create a test deployment

Run something like 

```
docker start -ia agent-install-release-internal && pushd /opt/draios/bin && cp lease_pool_manager cs_client_test /code/agent/userspace/cointerface/src/lease_pool_manager/test && popd && docker build -t fremmi/lease_pool_manager -f DockerfileServer . && docker build -t fremmi/cs_client_test -f DockerfileClient . && docker push fremmi/lease_pool_manager && docker push fremmi/cs_client_test && kubectl -n sysdig-agent delete deployment coldstart-deployment && kubectl -n sysdig-agent apply -f deployment.yaml
```

adjust the command and the containers image's name in deployment.yaml to fit your environment.


Each pod has 2 containers. One is the leader election container, named cs-server, and the other is the real application, named cs-client.

# Choose how many leader you can have at the same time

Apply a change in `deployment.yaml` as described here:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coldstart-deployment
  labels:
    app: coldstart-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: coldstart-deployment
  template:
    metadata:
      labels:
        app: coldstart-deployment
    spec:
      serviceAccount: sysdig-agent
      containers:
      - name: cs-client
        image: fremmi/cs_client_test
        args: ["-num-leases", "1"] <---CHANGE HERE
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
      - name: cs-server
        image: fremmi/lease_pool_manager
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
```


# What you will see?
Only pods with an acquired pod become ready. In the following example we have defined 4 leases in the same time and deployment has 5 replicas. We expect a single non ready pod.

```
fremmi@cervino:~$ kubectl -n sysdig-agent get pods
NAME                                   READY   STATUS    RESTARTS   AGE
coldstart-deployment-bdb9484f7-557dh   2/2     Running   1          19m
coldstart-deployment-bdb9484f7-5lrdp   2/2     Running   1          19m
coldstart-deployment-bdb9484f7-8n4wk   2/2     Running   1          19m
coldstart-deployment-bdb9484f7-d4hst   2/2     Running   1          19m
coldstart-deployment-bdb9484f7-nt5kj   0/2     Running   1          19m

```

# Enjoy the toy

If you want a pod to release its lease (and see what happens) you can use the following command

```
kubectl -n sysdig-agent exec -it  coldstart-deployment-bdb9484f7-557dh -c cs-client -- curl http://localhost:8080/release
```
