# Usage

To deploy agent using kubernetes, use the template above in this way, first create a kubernetes secret with access-key:

```
kubectl create secret generic sysdig-agent --from-literal=access-key=<yourkey>
```

Then deploy the agent using:

```
kubectl apply -f sdm-daemonset.yaml
```
