package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1as "k8s.io/api/autoscaling/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var horizontalPodAutoscalerInf cache.SharedInformer

func horizontalPodAutoscalerEvent(ss *v1as.HorizontalPodAutoscaler, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newHorizontalPodAutoscalerCongroup(ss),
	}
}

func newHorizontalPodAutoscalerCongroup(hpa *v1as.HorizontalPodAutoscaler) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_hpa"),
			Id:   proto.String(string(hpa.GetUID()))},
		Namespace: proto.String(hpa.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(hpa, "kubernetes.hpa.")
	ret.InternalTags = kubecollect_common.GetAnnotations(hpa.ObjectMeta, "kubernetes.hpa.")
	AddHorizontalPodAutoscalerMetrics(&ret.Metrics, hpa)
	AddPodChildrenFromOwnerRef(&ret.Children, hpa.ObjectMeta)
	if hpa.Spec.ScaleTargetRef.Kind == "Deployment" {
		AddDeploymentChildrenByName(&ret.Children, hpa.GetNamespace(), hpa.Spec.ScaleTargetRef.Name)
	} else if hpa.Spec.ScaleTargetRef.Kind == "ReplicationController" {
		AddReplicationControllerChildrenByName(&ret.Children, hpa.GetNamespace(), hpa.Spec.ScaleTargetRef.Name)
	} else if hpa.Spec.ScaleTargetRef.Kind == "ReplicaSet" {
		AddReplicaSetChildrenByName(&ret.Children, hpa.GetNamespace(), hpa.Spec.ScaleTargetRef.Name)
	}

	return ret
}

func AddHorizontalPodAutoscalerMetrics(metrics *[]*draiosproto.AppMetric, horizontalPodAutoscaler *v1as.HorizontalPodAutoscaler) {
	prefix := "kubernetes.hpa."
	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"replicas.min", horizontalPodAutoscaler.Spec.MinReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"replicas.max", horizontalPodAutoscaler.Spec.MaxReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"replicas.current", horizontalPodAutoscaler.Status.CurrentReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"replicas.desired", horizontalPodAutoscaler.Status.DesiredReplicas)
}

func AddHorizontalPodAutoscalerParents(parents *[]*draiosproto.CongroupUid, namespace string, apiversion string, kind string, name string) {
	if !kubecollect_common.ResourceReady("horizontalpodautoscalers") {
		return
	}

	for _, obj := range horizontalPodAutoscalerInf.GetStore().List() {
		hpa := obj.(*v1as.HorizontalPodAutoscaler)
		if hpa.GetNamespace() == namespace &&
			hpa.Spec.ScaleTargetRef.APIVersion == apiversion &&
			hpa.Spec.ScaleTargetRef.Kind == kind &&
			hpa.Spec.ScaleTargetRef.Name == name {
			// log.Debugf("Found HPA parents: hpa:%s -> %s:%s",
			// 	hpa.GetName(), kind, name)
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind: proto.String("k8s_hpa"),
				Id:   proto.String(string(hpa.GetUID()))})
		}
	}
}

func startHorizontalPodAutoscalersSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.AutoscalingV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "HorizontalPodAutoscalers", v1meta.NamespaceAll, fields.Everything())
	horizontalPodAutoscalerInf = cache.NewSharedInformer(lw, &v1as.HorizontalPodAutoscaler{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchHorizontalPodAutoscalers(evtc)
		horizontalPodAutoscalerInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchHorizontalPodAutoscalers(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchHorizontalPodAutoscalers()")

	horizontalPodAutoscalerInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("horizontalpodautoscalers")
				//log.Debugf("AddFunc dumping HorizontalPodAutoscaler: %v", obj.(*v1as.HorizontalPodAutoscaler))
				evtc <- horizontalPodAutoscalerEvent(obj.(*v1as.HorizontalPodAutoscaler),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("HPA", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldHorizontalPodAutoscaler := oldObj.(*v1as.HorizontalPodAutoscaler)
				newHorizontalPodAutoscaler := newObj.(*v1as.HorizontalPodAutoscaler)
				if oldHorizontalPodAutoscaler.GetResourceVersion() != newHorizontalPodAutoscaler.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping HorizontalPodAutoscaler oldHorizontalPodAutoscaler %v", oldHorizontalPodAutoscaler)
					//log.Debugf("UpdateFunc dumping HorizontalPodAutoscaler newHorizontalPodAutoscaler %v", newHorizontalPodAutoscaler)
					evtc <- horizontalPodAutoscalerEvent(newHorizontalPodAutoscaler,
						draiosproto.CongroupEventType_UPDATED.Enum())
					kubecollect_common.AddEvent("HPA", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("HPA", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldHPA := (*v1as.HorizontalPodAutoscaler)(nil)
				switch obj := obj.(type) {
				case *v1as.HorizontalPodAutoscaler:
					oldHPA = obj
				case cache.DeletedFinalStateUnknown:
					d := obj
					o, ok := (d.Obj).(*v1as.HorizontalPodAutoscaler)
					if ok {
						oldHPA = o
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without hpa object")
					}
				default:
					_ = log.Warn("Unknown object type in hpa DeleteFunc")
				}
				if oldHPA == nil {
					return
				}

				evtc <- horizontalPodAutoscalerEvent(oldHPA,
					draiosproto.CongroupEventType_REMOVED.Enum())
				kubecollect_common.AddEvent("HPA", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
