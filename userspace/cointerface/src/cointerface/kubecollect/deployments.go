package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
)

// make this a library function?
func deploymentEvent(ns *v1beta1.Deployment, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDeploymentCongroup(ns),
	}
}

func newDeploymentCongroup(deployment *v1beta1.Deployment) (*draiosproto.ContainerGroup) {
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
	AddNSParents(&ret.Parents, deployment.GetNamespace())
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

func WatchDeployments(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchDeployments()")

	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Deployments", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	deploymentInf = cache.NewSharedInformer(lw, &v1beta1.Deployment{}, resyncPeriod)

	deploymentInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping Deployment: %v", obj.(*v1beta1.Deployment))
				evtc <- deploymentEvent(obj.(*v1beta1.Deployment),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldDeployment := oldObj.(*v1beta1.Deployment)
				newDeployment := newObj.(*v1beta1.Deployment)
				if oldDeployment.GetResourceVersion() != newDeployment.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping Deployment oldDeployment %v", oldDeployment)
					//log.Debugf("UpdateFunc dumping Deployment newDeployment %v", newDeployment)
					evtc <- deploymentEvent(newDeployment,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping Deployment: %v", obj.(*v1beta1.Deployment))
				evtc <- deploymentEvent(obj.(*v1beta1.Deployment),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go deploymentInf.Run(ctx.Done())

	return deploymentInf
}
