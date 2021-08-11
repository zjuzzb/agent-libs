package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)


func replicationControllerEvent(rc kubecollect.CoReplicationController, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicationControllerCongroup(rc),
	}
}

func newReplicationControllerCongroup(replicationController kubecollect.CoReplicationController) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicationcontroller"),
			Id:proto.String(string(replicationController.GetUID()))},
		Namespace:proto.String(replicationController.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(replicationController, "kubernetes.replicationController.")
	ret.InternalTags = kubecollect_common.GetAnnotations(replicationController.ObjectMeta, "kubernetes.replicationController.")
	kubecollect.AddReplicationControllerMetrics(&ret.Metrics, replicationController)
	return ret
}

func startReplicationControllerWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	kubecollect.FilterEmptyRs = filterEmpty

	kubecollect_common.StartWatcher(ctx, kubeClient.CoreV1().RESTClient(), "ReplicationControllers", wg, evtc, fields.Everything(), handleReplicationControllerEvent)
}

func handleReplicationControllerEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	rc, ok := event.Object.(*v1.ReplicationController)

	if !ok {
		return
	}

	replicationController:= kubecollect.CoReplicationController{rc}

	if !replicationController.Filtered() {
		if event.Type == watch.Added {
			kubecollect_common.EventReceived("replicationcontrollers")
			evtc <- replicationControllerEvent(replicationController, draiosproto.CongroupEventType_ADDED.Enum(), true)
			kubecollect_common.AddEvent("replicationcontrollers", kubecollect_common.EVENT_ADD)
		} else if event.Type == watch.Modified {
			kubecollect_common.AddEvent("replicationcontrollers", kubecollect_common.EVENT_UPDATE)
			evtc <- replicationControllerEvent(replicationController, draiosproto.CongroupEventType_UPDATED.Enum(), true)
			kubecollect_common.AddEvent("replicationcontrollers", kubecollect_common.EVENT_UPDATE_AND_SEND)
		} else if event.Type == watch.Deleted {
			evtc <- replicationControllerEvent(replicationController, draiosproto.CongroupEventType_REMOVED.Enum(), true)
			kubecollect_common.AddEvent("replicationcontrollers", kubecollect_common.EVENT_DELETE)
		}
	}
}

