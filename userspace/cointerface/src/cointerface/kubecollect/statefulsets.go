package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var StatefulSetInf cache.SharedInformer

func statefulSetEvent(ss *appsv1.StatefulSet, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newStatefulSetCongroup(ss),
	}
}

func newStatefulSetCongroup(statefulSet *appsv1.StatefulSet) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_statefulset"),
			Id:   proto.String(string(statefulSet.GetUID()))},
		Namespace: proto.String(statefulSet.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(statefulSet, "kubernetes.statefulset.")
	ret.InternalTags = kubecollect_common.GetAnnotations(statefulSet.ObjectMeta, "kubernetes.statefulset.")
	AddStatefulSetMetrics(&ret.Metrics, statefulSet)
	AddPodChildrenFromOwnerRef(&ret.Children, statefulSet.ObjectMeta)
	AddServiceParentsFromServiceName(&ret.Parents, statefulSet.GetNamespace(), statefulSet.Spec.ServiceName)

	ret.LabelSelector = kubecollect_common.GetLabelSelector(*statefulSet.Spec.Selector)

	if statefulSet.Spec.Template.Labels != nil {
		if ret.PodTemplateLabels == nil {
			ret.PodTemplateLabels = make(map[string]string)
		}
		for key, val := range statefulSet.Spec.Template.Labels {
			ret.PodTemplateLabels[key] = val
		}
	}

	return ret
}

func AddStatefulSetMetrics(metrics *[]*draiosproto.AppMetric, statefulSet *appsv1.StatefulSet) {
	prefix := "kubernetes.statefulset."
	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"replicas", statefulSet.Spec.Replicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas", statefulSet.Status.Replicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas.current", statefulSet.Status.CurrentReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas.ready", statefulSet.Status.ReadyReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas.updated", statefulSet.Status.UpdatedReplicas)
}

func AddStatefulSetChildrenFromService(children *[]*draiosproto.CongroupUid, service CoService) {
	if !kubecollect_common.ResourceReady("statefulsets") {
		return
	}

	for _, obj := range StatefulSetInf.GetStore().List() {
		statefulSet := obj.(*appsv1.StatefulSet)
		if service.GetNamespace() == statefulSet.GetNamespace() && service.GetName() == statefulSet.Spec.ServiceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind: proto.String("k8s_statefulset"),
				Id:   proto.String(string(statefulSet.GetUID()))})
		}
	}
}

func startStatefulSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.AppsV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "StatefulSets", v1meta.NamespaceAll, fields.Everything())
	StatefulSetInf = cache.NewSharedInformer(lw, &appsv1.StatefulSet{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchStatefulSets(evtc)
		StatefulSetInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchStatefulSets(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchStatefulSets()")

	StatefulSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("statefulsets")
				//log.Debugf("AddFunc dumping StatefulSet: %v", obj.(*appsv1.StatefulSet))
				evtc <- statefulSetEvent(obj.(*appsv1.StatefulSet),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("StatefulSet", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldStatefulSet := oldObj.(*appsv1.StatefulSet)
				newStatefulSet := newObj.(*appsv1.StatefulSet)
				if oldStatefulSet.GetResourceVersion() != newStatefulSet.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping StatefulSet oldStatefulSet %v", oldStatefulSet)
					//log.Debugf("UpdateFunc dumping StatefulSet newStatefulSet %v", newStatefulSet)
					evtc <- statefulSetEvent(newStatefulSet,
						draiosproto.CongroupEventType_UPDATED.Enum())
					kubecollect_common.AddEvent("StatefulSet", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("StatefulSet", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldSet := (*appsv1.StatefulSet)(nil)
				switch obj := obj.(type) {
				case *appsv1.StatefulSet:
					oldSet = obj
				case cache.DeletedFinalStateUnknown:
					o, ok := (obj.Obj).(*appsv1.StatefulSet)
					if ok {
						oldSet = o
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without statefulset object")
					}
				default:
					_ = log.Warn("Unknown object type in statefulset DeleteFunc")
				}
				if oldSet == nil {
					return
				}

				evtc <- statefulSetEvent(oldSet,
					draiosproto.CongroupEventType_REMOVED.Enum())
				kubecollect_common.AddEvent("StatefulSet", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
