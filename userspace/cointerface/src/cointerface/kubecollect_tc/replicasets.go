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

func replicaSetEvent(rs kubecollect.CoReplicaSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(rs, setLinks),
	}
}

func newReplicaSetCongroup(replicaSet kubecollect.CoReplicaSet, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicaset"),
			Id:proto.String(string(replicaSet.GetUID()))},
		Namespace:proto.String(replicaSet.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	ret.InternalTags = kubecollect_common.GetAnnotations(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	kubecollect.AddReplicaSetMetrics(&ret.Metrics, replicaSet)
	if setLinks {
		kubecollect_common.OwnerReferencesToParents(replicaSet.GetOwnerReferences(), &ret.Parents, nil)
	}
	return ret
}

func startReplicaSetWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	kubecollect.FilterEmptyRs = filterEmpty

	kubecollect_common.StartWatcher(ctx, kubeClient.AppsV1().RESTClient(), "ReplicaSets", wg, evtc, fields.Everything(), handleReplicaSetEvent)
}

func handleReplicaSetEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	rs, ok := event.Object.(*appsv1.ReplicaSet)

	if !ok {
		return
	}

	replicaSet := kubecollect.CoReplicaSet{rs}

	if !replicaSet.Filtered() {
		if event.Type == watch.Added {
			kubecollect_common.EventReceived("replicasets")
			evtc <- replicaSetEvent(replicaSet, draiosproto.CongroupEventType_ADDED.Enum(), true)
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_ADD)
		} else if event.Type == watch.Modified {
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_UPDATE)
			evtc <- replicaSetEvent(replicaSet, draiosproto.CongroupEventType_UPDATED.Enum(), true)
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_UPDATE_AND_SEND)
		} else if event.Type == watch.Deleted {
			evtc <- replicaSetEvent(replicaSet, draiosproto.CongroupEventType_REMOVED.Enum(), true)
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_DELETE)
		}
	}
}
