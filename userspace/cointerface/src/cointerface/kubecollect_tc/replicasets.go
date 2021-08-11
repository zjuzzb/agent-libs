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

	ret.Tags = kubecollect_common.GetTags(replicaSet, "kubernetes.replicaSet.")
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

// We usually want to avoid replicasets with spec.Replicas = 0.
// There are some exceptions coming from deployment rollover.
func filterAndConvertEventType(rs *kubecollect.CoReplicaSet, t watch.EventType) (bool, watch.EventType) {
	// If we don't want to filter empty rs, let's go ahead
	if !kubecollect.FilterEmptyRs || *rs.Spec.Replicas > 0 {
		return false, t
	}

	// A common case when a deployment is rolled-over:
	// a new rs with spec.replicas=0 and generation=1 is created.
	// As time passes and the old rs is going to be downscaled, both spec.replicas
	// and generation increases
	if t == watch.Added && rs.GetGeneration() == 1 {
		return false, t
	}

	// the following happens when, during a deployment rollover, the old
	// rs is scaled down to 0 (while the new one is scaled up)
	// Kubernetes will leave the 0 replicas rs for ever. We are going to
	// treat the event as a deletion
	if t == watch.Modified && rs.GetGeneration() > 1 {
		return false, watch.Deleted
	}

	// Always send delete
	if t == watch.Deleted {
		return false, t
	}

	return true, t
}

func handleReplicaSetEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	rs, ok := event.Object.(*appsv1.ReplicaSet)

	if !ok {
		return
	}

	replicaSet := kubecollect.CoReplicaSet{rs}

	filter, newType := filterAndConvertEventType(&replicaSet, event.Type)

	if !filter {
		if newType == watch.Added {
			kubecollect_common.EventReceived("replicasets")
			evtc <- replicaSetEvent(replicaSet, draiosproto.CongroupEventType_ADDED.Enum(), true)
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_ADD)
		} else if newType == watch.Modified {
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_UPDATE)
			evtc <- replicaSetEvent(replicaSet, draiosproto.CongroupEventType_UPDATED.Enum(), true)
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_UPDATE_AND_SEND)
		} else if newType == watch.Deleted {
			evtc <- replicaSetEvent(replicaSet, draiosproto.CongroupEventType_REMOVED.Enum(), true)
			kubecollect_common.AddEvent("replicasets", kubecollect_common.EVENT_DELETE)
		}
	}
}
