package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
)

var deploymentInf cache.SharedInformer

func deploymentEvent(dep *v1beta1.Deployment, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDeploymentCongroup(dep, setLinks),
	}
}

func deploymentEquals(lhs *v1beta1.Deployment, rhs *v1beta1.Deployment) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	in = in && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
        EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	} else if !reflect.DeepEqual(lhs.Spec.Selector.MatchLabels, rhs.Spec.Selector.MatchLabels) {
		out = false
	}

	return in, out
}

func newDeploymentCongroup(deployment *v1beta1.Deployment, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_deployment"),
			Id:proto.String(string(deployment.GetUID()))},
	}

	ret.Tags = GetTags(deployment.ObjectMeta, "kubernetes.deployment.")
	ret.InternalTags = GetAnnotations(deployment.ObjectMeta, "kubernetes.deployment.")
	addDeploymentMetrics(&ret.Metrics, deployment)
	if setLinks {
		AddNSParents(&ret.Parents, deployment.GetNamespace())
		AddReplicaSetChildren(&ret.Children, deployment)
	}
	return ret
}

func addDeploymentMetrics(metrics *[]*draiosproto.AppMetric, deployment *v1beta1.Deployment) {
	prefix := "kubernetes.deployment."
	AppendMetricInt32(metrics, prefix+"status.replicas", deployment.Status.Replicas)
	// kube-state-metrics uses "kube_deployment_status_replicas_available" but
	// we use availableReplicas instead of replicasAvailable because it matches
	// the name in DeploymentStatus and other resources like ReplicationControllers
	AppendMetricInt32(metrics, prefix+"status.availableReplicas", deployment.Status.AvailableReplicas)
	AppendMetricInt32(metrics, prefix+"status.unavailableReplicas", deployment.Status.UnavailableReplicas)
	AppendMetricInt32(metrics, prefix+"status.updatedReplicas", deployment.Status.UpdatedReplicas)
	AppendMetricPtrInt32(metrics, prefix+"spec.replicas", deployment.Spec.Replicas)
	AppendMetricBool(metrics, prefix+"spec.paused", deployment.Spec.Paused)
	//if deployment.Spec.Strategy.RollingUpdate != nil {
	//	metrics[prefix + "spec.strategy.rollingupdate.max.unavailable"] = uint32(deployment.Spec.Strategy.RollingUpdate.MaxUnavailable)
	//}
}

func AddDeploymentParents(parents *[]*draiosproto.CongroupUid, replicaSet *v1beta1.ReplicaSet) {
	if CompatibilityMap["deployments"] {
		for _, obj := range deploymentInf.GetStore().List() {
			deployment := obj.(*v1beta1.Deployment)
			selector, _ := v1meta.LabelSelectorAsSelector(deployment.Spec.Selector)
			if replicaSet.GetNamespace() == deployment.GetNamespace() && selector.Matches(labels.Set(replicaSet.GetLabels())) {
				*parents = append(*parents, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_deployment"),
					Id:proto.String(string(deployment.GetUID()))})
			}
		}
	}
}

func AddDeploymentChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if CompatibilityMap["deployments"] {
		for _, obj := range deploymentInf.GetStore().List() {
			deployment := obj.(*v1beta1.Deployment)
			if deployment.GetNamespace() == namespaceName {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_deployment"),
					Id:proto.String(string(deployment.GetUID()))})
			}
		}
	}
}

func StartDeploymentsSInformer(ctx context.Context, kubeClient kubeclient.Interface) {
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Deployments", v1meta.NamespaceAll, fields.Everything())
	deploymentInf = cache.NewSharedInformer(lw, &v1beta1.Deployment{}, RsyncInterval)
	go deploymentInf.Run(ctx.Done())
}

func WatchDeployments(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchDeployments()")

	deploymentInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- deploymentEvent(obj.(*v1beta1.Deployment),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldDeployment := oldObj.(*v1beta1.Deployment)
				newDeployment := newObj.(*v1beta1.Deployment)
				if oldDeployment.GetResourceVersion() != newDeployment.GetResourceVersion() {
					sameEntity, sameLinks := deploymentEquals(oldDeployment, newDeployment)
					if !sameEntity || !sameLinks {
						evtc <- deploymentEvent(newDeployment,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldDeployment := obj.(*v1beta1.Deployment)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_deployment"),
							Id:proto.String(string(oldDeployment.GetUID()))},
					},
				}
			},
		},
	)

	return deploymentInf
}
