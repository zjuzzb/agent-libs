# Usage

To deploy agent using kubernetes, use the template above in this way, first create a kubernetes secret with access-key:

```
kubectl create secret generic sysdig-agent --from-literal=access-key=<yourkey>
kubectl create configmap sysdig-agent --from-literal=collector=collector-staging.sysdigcloud.com
```


Then deploy the agent using:

```
kubectl apply -f sdm-daemonset.yaml
```
