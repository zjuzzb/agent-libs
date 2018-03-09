This is a set of scripts that allows you to connect your local backend to a GKE cluster, it's composed of these components:

# local-backend service

Creates a kubernetes service exposed on port 30000 on each Node of the cluster that redirects to port 6666 of the kubernetes pods implementing it, you can create it with:

```
$ kubectl apply -f local-backend-service.yaml
```

# ssh-server service

It an ssh server exposed to the internet on port 22, GKE automatically will allocate a public IP for it, you can create it with:

```
$ kubectl apply -f ssh-server-service.yaml
```

and get the public IP with:

```
$ kubectl get service ssh-server
NAME         TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)        AGE
ssh-server   LoadBalancer   10.55.243.211   35.224.106.124   22:32510/TCP   6d
$
```

# ssh-server deployment

It uses `luca3m/ssh-server` which implements the ssh server exposed to the world and also the local-backend service. You can than create via the ssh client a remote tunnel and the connections to port 6666 of ssh-server pod will go to your local backend!

To configure it use these commands:

```
# add your key so you'll be able to authenticate
$ kubectl create secret generic authorized-keys --from-file=./authorized_keys
$ kubectl apply -f ssh-server-deployment.yaml
```

# Put everything together

Configure sysdig/agent daemonset to use `localhost:30000` as backend with ssl disabled. Run your local backend and then use this command to create the tunnel:

```
$ ssh -v -o StrictHostKeyChecking=no -i <path_to_pem> -N -R 0.0.0.0:6666:localhost:6666 root@<ssh-external-ip>
```

you are all set!
