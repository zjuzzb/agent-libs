package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	"github.com/gogo/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

func daemonSetEvent(ds kubecollect.CoDaemonSet, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newDaemonSetCongroup(ds),
	}
}

func newDaemonSetCongroup(daemonSet kubecollect.CoDaemonSet) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_daemonset"),
			Id:   proto.String(string(daemonSet.GetUID()))},
		Namespace: proto.String(daemonSet.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(daemonSet, "kubernetes.daemonSet.")
	ret.InternalTags = kubecollect_common.GetAnnotations(daemonSet.ObjectMeta, "kubernetes.daemonSet.")
	kubecollect.AddDaemonSetMetrics(&ret.Metrics, daemonSet)
	ret.LabelSelector = kubecollect_common.GetLabelSelector(*daemonSet.Spec.Selector)
	return ret
}

func startDaemonSetsWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	kubecollect_common.StartWatcher(ctx, kubeClient.AppsV1().RESTClient(), "DaemonSets", wg, evtc, fields.Everything(), handleDaemonsetEvent)
}

func handleDaemonsetEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	daemonset, ok := event.Object.(*appsv1.DaemonSet)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("daemonsets")
		evtc <- daemonSetEvent(kubecollect.CoDaemonSet{daemonset}, draiosproto.CongroupEventType_ADDED.Enum())
		kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_UPDATE)
		evtc <- daemonSetEvent(kubecollect.CoDaemonSet{daemonset}, draiosproto.CongroupEventType_UPDATED.Enum())
		kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_UPDATE_AND_SEND)
	} else if event.Type == watch.Deleted {
		evtc <- daemonSetEvent(kubecollect.CoDaemonSet{daemonset}, draiosproto.CongroupEventType_REMOVED.Enum())
		kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_DELETE)
	}
}
