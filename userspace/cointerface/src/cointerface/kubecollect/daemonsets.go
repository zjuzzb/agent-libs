package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"	
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/extensions/v1beta1"	
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
)

var daemonSetInf cache.SharedInformer

func daemonSetEvent(ns *v1beta1.DaemonSet, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDaemonSetCongroup(ns),
	}
}

func newDaemonSetCongroup(daemonSet *v1beta1.DaemonSet) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_daemonset"),
			Id:proto.String(string(daemonSet.GetUID()))},
	}

	ret.Tags = GetTags(daemonSet.ObjectMeta, "kubernetes.daemonSet.")
	addDaemonSetMetrics(&ret.Metrics, daemonSet)
	AddNSParents(&ret.Parents, daemonSet.GetNamespace())
	selector, _ := v1meta.LabelSelectorAsSelector(daemonSet.Spec.Selector)
	AddPodChildren(&ret.Children, selector, daemonSet.GetNamespace())
	return ret
}

func addDaemonSetMetrics(metrics *[]*draiosproto.AppMetric, daemonSet *v1beta1.DaemonSet) {
	prefix := "kubernetes.daemonSet."
	AppendMetricInt32(metrics, prefix+"status.currentNumberScheduled", daemonSet.Status.CurrentNumberScheduled)
	AppendMetricInt32(metrics, prefix+"status.numberMisscheduled", daemonSet.Status.NumberMisscheduled)
	AppendMetricInt32(metrics, prefix+"status.desiredNumberScheduled", daemonSet.Status.DesiredNumberScheduled)
	AppendMetricInt32(metrics, prefix+"status.numberReady", daemonSet.Status.NumberReady)
}

func AddDaemonSetParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if CompatibilityMap["daemonsets"] {
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
}

func AddDaemonSetChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if CompatibilityMap["daemonsets"] {
		for _, obj := range daemonSetInf.GetStore().List() {
			daemonSet := obj.(*v1beta1.DaemonSet)
			if daemonSet.GetNamespace() == namespaceName {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_daemonset"),
					Id:proto.String(string(daemonSet.GetUID()))})
			}
		}
	}
}

func StartDaemonSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface) {
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "DaemonSets", v1meta.NamespaceAll, fields.Everything())
	daemonSetInf = cache.NewSharedInformer(lw, &v1beta1.DaemonSet{}, RsyncInterval)
	go daemonSetInf.Run(ctx.Done())
}

func WatchDaemonSets(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchDaemonSets()")

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

	return daemonSetInf
}
