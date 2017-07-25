package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"	
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/extensions/v1beta1"	
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
)

// make this a library function?
func daemonSetEvent(ns *v1beta1.DaemonSet, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDaemonSetCongroup(ns),
	}
}

func newDaemonSetCongroup(daemonSet *v1beta1.DaemonSet) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range daemonSet.GetLabels() {
		tags["kubernetes.daemonset.label." + k] = v
	}
	tags["kubernetes.daemonset.name"] = daemonSet.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_daemonset"),
			Id:proto.String(string(daemonSet.GetUID()))},
		Tags: tags,
	}
	AddNSParents(&ret.Parents, daemonSet.GetNamespace())
	return ret
}

var daemonSetInf cache.SharedInformer

func AddDaemonSetParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	for _, obj := range daemonSetInf.GetStore().List() {
		daemonSet := obj.(*v1beta1.DaemonSet)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector, _ := v1meta.LabelSelectorAsSelector(daemonSet.Spec.Selector)
		if pod.GetNamespace() == daemonSet.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_daemonset"),
				Id:proto.String(string(daemonSet.GetUID()))})
		}
	}
}

func WatchDaemonSets(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchDaemonSets()")

	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "DaemonSets", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	daemonSetInf = cache.NewSharedInformer(lw, &v1beta1.DaemonSet{}, resyncPeriod)

	daemonSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping DaemonSet: %v", obj.(*v1beta1.DaemonSet))
				evtc <- daemonSetEvent(obj.(*v1beta1.DaemonSet),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldDaemonSet := oldObj.(*v1beta1.DaemonSet)
				newDaemonSet := newObj.(*v1beta1.DaemonSet)
				if oldDaemonSet.GetResourceVersion() != newDaemonSet.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping DaemonSet oldDaemonSet %v", oldDaemonSet)
					//log.Debugf("UpdateFunc dumping DaemonSet newDaemonSet %v", newDaemonSet)
					evtc <- daemonSetEvent(newDaemonSet,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping DaemonSet: %v", obj.(*v1beta1.DaemonSet))
				evtc <- daemonSetEvent(obj.(*v1beta1.DaemonSet),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go daemonSetInf.Run(ctx.Done())

	return daemonSetInf
}
