#!/bin/bash

namespaces=("dev")
active_namespaces=("dev")

if [ ! -f $(pwd)/kubectl ]; then
  wget https://storage.googleapis.com/kubernetes-release/release/v1.0.6/bin/linux/amd64/kubectl
  chmod +x kubectl
fi


cat <<- 'EOF' > "mysql-rc.yaml"
kind: ReplicationController
apiVersion: v1
metadata:
  name: mysql
spec:
  replicas: 1
  # selector identifies the set of Pods that this
  # replication controller is responsible for managing
  selector:
    name: mysql
    role: mysqldb
    app: demo
  template:
    spec:
      containers:
        - name: mysql
          image: mysql
          ports:
            - containerPort: 3306
              name: mysql
          env:
          - name: MYSQL_ROOT_PASSWORD
            value: password
          - name: MYSQL_USER
            value: admin
          - name: MYSQL_PASSWORD
            value: password
          - name: MYSQL_DATABASE
            value: wordpress
    metadata:
      labels:
        # Important: these labels need to match the selector above
        # The api server enforces this constraint.
        name: mysql
        role: mysqldb
        app: demo
  labels:
    name: mysql-rc
    app: demo
EOF

cat <<- 'EOF' > "mysql-service.yaml"
apiVersion: v1
kind: Service
metadata: 
  labels: 
    name: mysql
  name: mysql
spec: 
  ports:
    - port: 3306
      targetPort: 3306
  selector:
    name: mysql 
    app: demo
    role: mysqldb
EOF


for namespace in ${namespaces[@]}
do
cat <<- EOF > "namespace.yaml"
  kind: "Namespace"
  apiVersion: "v1"
  metadata: 
    name: ${namespace}
    labels: 
      name: ${namespace}
EOF
./kubectl create -f namespace.yaml
done

#main
for namespace in ${active_namespaces[@]}
do
echo "Creating resource in ${namespace} namespace"
./kubectl create --namespace=${namespace} -f mysql-rc.yaml
./kubectl create --namespace=${namespace} -f mysql-service.yaml

MYSQL_SERVICE_IP=$(./kubectl get --namespace=${namespace} services mysql | tail -1 | tr -s " " | cut -d " " -f4)

cat <<- EOF > "wordpress-rc.yaml"
kind: ReplicationController
apiVersion: v1
metadata:
  name: wordpress
spec:
  replicas: 3
  # selector identifies the set of Pods that this
  # replication controller is responsible for managing
  selector:
    name: wordpress
    role: frontend
    app: demo
  template:
    spec:
      containers:
        - name: wordpress
          image: wordpress
          env:
          - name: WORDPRESS_DB_PASSWORD
            value: password
          - name: WORDPRESS_DB_USER
            value: admin
          - name: WORDPRESS_DB_HOST
            value: ${MYSQL_SERVICE_IP}:3306
          ports:
          - containerPort: 80
            name: wordpress
    metadata:
      labels:
        # Important: these labels need to match the selector above
        # The api server enforces this constraint.
        name: wordpress
        role: frontend
        app: demo
  labels:
    name: wordpress-rc
    app: demo
EOF

cat <<- EOF > "wordpress-service.yaml"
apiVersion: v1
kind: Service
metadata: 
  labels: 
    name: wordpress
  name: wordpress
spec: 
  ports:
    - port: 80
      targetPort: 80
  selector:
    name: wordpress 
    app: demo
    role: frontend
EOF
./kubectl create --namespace=${namespace} -f wordpress-service.yaml

WORDPRESS_SERVICE_IP=$(./kubectl get --namespace=${namespace} services wordpress | tail -1 | tr -s " " | cut -d " " -f4)

cat <<- EOF > "wp-client-rc.yaml"
kind: ReplicationController
apiVersion: v1
metadata:
  name: client
spec:
  replicas: 2
  # selector identifies the set of Pods that this
  # replication controller is responsible for managing
  selector:
    name: client
    role: clients
    app: demo
  template:
    spec:
      containers:
        - name: client
          image: ltagliamonte/recurling
          env:
          - name: URL
            value: http://${WORDPRESS_SERVICE_IP}/wp-admin/install.php
    metadata:
      labels:
        # Important: these labels need to match the selector above
        # The api server enforces this constraint.
        name: client
        role: clients
        app: demo
  labels:
    name: client-rc
    app: demo
EOF
./kubectl create --namespace=${namespace} -f wp-client-rc.yaml

sleep 60s

./kubectl create --namespace=${namespace} -f wordpress-rc.yaml

done

exit 0