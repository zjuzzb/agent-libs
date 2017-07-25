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
	"k8s.io/api/core/v1"
)

// make this a library function?
func replicaSetEvent(ns *v1beta1.ReplicaSet, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(ns),
	}
}

func newReplicaSetCongroup(replicaSet *v1beta1.ReplicaSet) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range replicaSet.GetLabels() {
		tags["kubernetes.replicaset.label." + k] = v
	}
	tags["kubernetes.replicaset.name"] = replicaSet.GetName()

	desiredReplicas := uint32(0)
	if replicaSet.Spec.Replicas != nil {
		desiredReplicas = uint32(*replicaSet.Spec.Replicas)
	}
	metrics := map[string]uint32{"kubernetes.replicaSet.replicas.desired": desiredReplicas,
		"kubernetes.replicaSet.replicas.running": uint32(replicaSet.Status.Replicas),}

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicaset"),
			Id:proto.String(string(replicaSet.GetUID()))},
		Tags: tags,
		Metrics: metrics,
	}
	AddNSParents(&ret.Parents, replicaSet.GetNamespace())
	AddDeploymentParents(&ret.Parents, replicaSet)
	AddReplicaSetChildren(&ret.Children, replicaSet)
	return ret
}

var replicaSetInf cache.SharedInformer

func AddReplicaSetParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector, _ := v1meta.LabelSelectorAsSelector(replicaSet.Spec.Selector)
		if pod.GetNamespace() == replicaSet.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(replicaSet.GetUID()))})
		}
	}
}

func WatchReplicaSets(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchReplicaSets()")

	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicaSets", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	replicaSetInf = cache.NewSharedInformer(lw, &v1beta1.ReplicaSet{}, resyncPeriod)

	replicaSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping ReplicaSet: %v", obj.(*v1beta1.ReplicaSet))
				evtc <- replicaSetEvent(obj.(*v1beta1.ReplicaSet),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldReplicaSet := oldObj.(*v1beta1.ReplicaSet)
				newReplicaSet := newObj.(*v1beta1.ReplicaSet)
				if oldReplicaSet.GetResourceVersion() != newReplicaSet.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping ReplicaSet oldReplicaSet %v", oldReplicaSet)
					//log.Debugf("UpdateFunc dumping ReplicaSet newReplicaSet %v", newReplicaSet)
					evtc <- replicaSetEvent(newReplicaSet,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ReplicaSet: %v", obj.(*v1beta1.ReplicaSet))
				evtc <- replicaSetEvent(obj.(*v1beta1.ReplicaSet),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go replicaSetInf.Run(ctx.Done())

	return replicaSetInf
}
