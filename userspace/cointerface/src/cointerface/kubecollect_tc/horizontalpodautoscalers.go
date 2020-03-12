package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	"github.com/gogo/protobuf/proto"
	v1as "k8s.io/api/autoscaling/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

func horizontalPodAutoscalerEvent(ss *v1as.HorizontalPodAutoscaler, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newHorizontalPodAutoscalerCongroup(ss),
	}
}

func newHorizontalPodAutoscalerCongroup(hpa *v1as.HorizontalPodAutoscaler) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_hpa"),
			Id:proto.String(string(hpa.GetUID()))},
		Namespace:proto.String(hpa.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(hpa.ObjectMeta, "kubernetes.hpa.")
	ret.InternalTags = kubecollect_common.GetAnnotations(hpa.ObjectMeta, "kubernetes.hpa.")
	kubecollect.AddHorizontalPodAutoscalerMetrics(&ret.Metrics, hpa)

	if ret.InternalTags == nil {
		ret.InternalTags = make(map[string]string)
	}
	ret.InternalTags["hpa.scale.target.ref.kind"] = hpa.Spec.ScaleTargetRef.Kind
	ret.InternalTags["hpa.scale.target.ref.name"] = hpa.Spec.ScaleTargetRef.Name

	return ret
}

func startHPAWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	kubecollect_common.StartWatcher(ctx, kubeClient.AutoscalingV1().RESTClient(), "HorizontalPodAutoscalers", wg, evtc, fields.Everything(), handleHPAEvent)
}

func handleHPAEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	hpa, ok := event.Object.(*v1as.HorizontalPodAutoscaler)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("horizontalpodautoscalers")
		evtc <- horizontalPodAutoscalerEvent(hpa, draiosproto.CongroupEventType_ADDED.Enum())
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_UPDATE)
		evtc <- horizontalPodAutoscalerEvent(hpa, draiosproto.CongroupEventType_UPDATED.Enum())
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_UPDATE_AND_SEND)
	} else if event.Type == watch.Deleted {
		evtc <- horizontalPodAutoscalerEvent(hpa, draiosproto.CongroupEventType_REMOVED.Enum())
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_DELETE)
	}
}

