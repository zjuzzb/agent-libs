package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	v1as "k8s.io/api/autoscaling/v1"
)

var horizontalPodAutoscalerInf cache.SharedInformer

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
	}

	ret.Tags = GetTags(hpa.ObjectMeta, "kubernetes.hpa.")
	ret.InternalTags = GetAnnotations(hpa.ObjectMeta, "kubernetes.hpa.")
	addHorizontalPodAutoscalerMetrics(&ret.Metrics, hpa)
	AddNSParents(&ret.Parents, hpa.GetNamespace())
	AddPodChildrenFromOwnerRef(&ret.Children, hpa.ObjectMeta)
	if (hpa.Spec.ScaleTargetRef.Kind == "Deployment") {
		AddDeploymentChildrenByName(&ret.Children, hpa.GetNamespace(), hpa.Spec.ScaleTargetRef.Name)
	} else if (hpa.Spec.ScaleTargetRef.Kind == "ReplicationController") {
		AddReplicationControllerChildrenByName(&ret.Children, hpa.GetNamespace(), hpa.Spec.ScaleTargetRef.Name)
	} else if (hpa.Spec.ScaleTargetRef.Kind == "ReplicaSet") {
		AddReplicaSetChildrenByName(&ret.Children, hpa.GetNamespace(), hpa.Spec.ScaleTargetRef.Name)
	}

	return ret
}

func addHorizontalPodAutoscalerMetrics(metrics *[]*draiosproto.AppMetric, horizontalPodAutoscaler *v1as.HorizontalPodAutoscaler) {
	prefix := "kubernetes.hpa."
	AppendMetricPtrInt32(metrics, prefix+"replicas.min", horizontalPodAutoscaler.Spec.MinReplicas)
	AppendMetricInt32(metrics, prefix+"replicas.max", horizontalPodAutoscaler.Spec.MaxReplicas)
	AppendMetricInt32(metrics, prefix+"replicas.current", horizontalPodAutoscaler.Status.CurrentReplicas)
	AppendMetricInt32(metrics, prefix+"replicas.desired", horizontalPodAutoscaler.Status.DesiredReplicas)
}

func AddHorizontalPodAutoscalerParents(parents *[]*draiosproto.CongroupUid, namespace string, apiversion string, kind string, name string) {
	if compatibilityMap["horizontalpodautoscalers"] {
		for _, obj := range horizontalPodAutoscalerInf.GetStore().List() {
			hpa := obj.(*v1as.HorizontalPodAutoscaler)
			if hpa.GetNamespace() == namespace &&
				hpa.Spec.ScaleTargetRef.APIVersion == apiversion &&
				hpa.Spec.ScaleTargetRef.Kind == kind &&
				hpa.Spec.ScaleTargetRef.Name == name {
					// log.Debugf("Found HPA parents: hpa:%s -> %s:%s",
					// 	hpa.GetName(), kind, name)
					*parents = append(*parents, &draiosproto.CongroupUid{
						Kind:proto.String("k8s_hpa"),
						Id:proto.String(string(hpa.GetUID()))})
			}
		}
	}
}

func AddHorizontalPodAutoscalerChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if compatibilityMap["horizontalpodautoscalers"] {
		for _, obj := range horizontalPodAutoscalerInf.GetStore().List() {
			horizontalPodAutoscaler := obj.(*v1as.HorizontalPodAutoscaler)
			if horizontalPodAutoscaler.GetNamespace() == namespaceName {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_hpa"),
					Id:proto.String(string(horizontalPodAutoscaler.GetUID()))})
			}
		}
	}
}

func startHorizontalPodAutoscalersSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup) {
	client := kubeClient.AutoscalingV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "HorizontalPodAutoscalers", v1meta.NamespaceAll, fields.Everything())
	horizontalPodAutoscalerInf = cache.NewSharedInformer(lw, &v1as.HorizontalPodAutoscaler{}, RsyncInterval)

	wg.Add(1)
	go func() {
		horizontalPodAutoscalerInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchHorizontalPodAutoscalers(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchHorizontalPodAutoscalers()")

	horizontalPodAutoscalerInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping HorizontalPodAutoscaler: %v", obj.(*v1as.HorizontalPodAutoscaler))
				evtc <- horizontalPodAutoscalerEvent(obj.(*v1as.HorizontalPodAutoscaler),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldHorizontalPodAutoscaler := oldObj.(*v1as.HorizontalPodAutoscaler)
				newHorizontalPodAutoscaler := newObj.(*v1as.HorizontalPodAutoscaler)
				if oldHorizontalPodAutoscaler.GetResourceVersion() != newHorizontalPodAutoscaler.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping HorizontalPodAutoscaler oldHorizontalPodAutoscaler %v", oldHorizontalPodAutoscaler)
					//log.Debugf("UpdateFunc dumping HorizontalPodAutoscaler newHorizontalPodAutoscaler %v", newHorizontalPodAutoscaler)
					evtc <- horizontalPodAutoscalerEvent(newHorizontalPodAutoscaler,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping HorizontalPodAutoscaler: %v", obj.(*v1as.HorizontalPodAutoscaler))
				evtc <- horizontalPodAutoscalerEvent(obj.(*v1as.HorizontalPodAutoscaler),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	return horizontalPodAutoscalerInf
}
