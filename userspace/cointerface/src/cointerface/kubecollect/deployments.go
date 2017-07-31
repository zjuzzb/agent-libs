package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
)

// make this a library function?
func deploymentEvent(ns *v1beta1.Deployment, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDeploymentCongroup(ns, setLinks),
	}
}

func deploymentEquals(lhs *v1beta1.Deployment, rhs *v1beta1.Deployment) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	if in && len(lhs.GetLabels()) != len(rhs.GetLabels()) {
		in = false
	} else {
		for k,v := range lhs.GetLabels() {
			if rhs.GetLabels()[k] != v {
				in = false
			}
		}
	}

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	} else if !reflect.DeepEqual(lhs.Spec.Selector.MatchLabels, rhs.Spec.Selector.MatchLabels) {
		out = false
	}

	return in, out
}

func newDeploymentCongroup(deployment *v1beta1.Deployment, setLinks bool) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range deployment.GetLabels() {
		tags["kubernetes.deployment.label." + k] = v
	}
	tags["kubernetes.deployment.name"] = deployment.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_deployment"),
			Id:proto.String(string(deployment.GetUID()))},
		Tags: tags,
	}
	if setLinks {
		AddNSParents(&ret.Parents, deployment.GetNamespace())
		AddReplicaSetChildren(&ret.Children, deployment)
	}
	return ret
}

var deploymentInf cache.SharedInformer

func AddDeploymentParents(parents *[]*draiosproto.CongroupUid, replicaSet *v1beta1.ReplicaSet) {
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

func AddDeploymentChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	for _, obj := range deploymentInf.GetStore().List() {
		deployment := obj.(*v1beta1.Deployment)
		if deployment.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_deployment"),
				Id:proto.String(string(deployment.GetUID()))})
		}
	}
}

func WatchDeployments(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchDeployments()")

	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Deployments", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	deploymentInf = cache.NewSharedInformer(lw, &v1beta1.Deployment{}, resyncPeriod)

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

	go deploymentInf.Run(ctx.Done())

	return deploymentInf
}
