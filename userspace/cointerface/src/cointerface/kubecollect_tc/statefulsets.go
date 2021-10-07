package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

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
	kubecollect_common.MapInsert(&ret.InternalTags, "kubernetes.statefulset.service.name", statefulSet.Spec.ServiceName)
	kubecollect.AddStatefulSetMetrics(&ret.Metrics, statefulSet)

	ret.LabelSelector = kubecollect_common.GetLabelSelector(*statefulSet.Spec.Selector)
	return ret
}

func startStatefulSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.AppsV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "StatefulSets", v1meta.NamespaceAll, fields.Everything())
	kubecollect.StatefulSetInf = cache.NewSharedInformer(lw, &appsv1.StatefulSet{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchStatefulSets(evtc)
		kubecollect.StatefulSetInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchStatefulSets(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchStatefulSets() from package %s", kubecollect_common.GetPkg(KubecollectClientTc{}))

	kubecollect.StatefulSetInf.AddEventHandler(
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
				switch obj.(type) {
				case *appsv1.StatefulSet:
					oldSet = obj.(*appsv1.StatefulSet)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*appsv1.StatefulSet)
					if ok {
						oldSet = o
					} else {
						log.Warn("DeletedFinalStateUnknown without statefulset object")
					}
				default:
					log.Warn("Unknown object type in statefulset DeleteFunc")
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
