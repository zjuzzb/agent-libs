package kubecollect

import (
	"cointerface/kubecollect_common"
	draiosproto "protorepo/agent-be/proto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

// make this a library function?
func nsEvent(ns *v1.Namespace, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newNSCongroup(ns, eventType),
	}
}

func nsEquals(lhs *v1.Namespace, rhs *v1.Namespace) bool {
	if lhs.GetName() != rhs.GetName() {
		return false
	}

	if !kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) ||
        !kubecollect_common.EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta) {
		return false
	}

	return true
}

func newNSCongroup(ns *v1.Namespace, eventType *draiosproto.CongroupEventType) (*draiosproto.ContainerGroup) {
	tags:= kubecollect_common.GetTags(ns, "kubernetes.namespace.")
	inttags:= kubecollect_common.GetAnnotations(ns.ObjectMeta, "kubernetes.namespace.")

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_namespace"),
			Id:proto.String(string(ns.GetUID()))},
		Tags: tags,
		InternalTags: inttags,
		Namespace:proto.String(tags["kubernetes.namespace.name"]),
	}

	return ret
}

var namespaceInf cache.SharedInformer

func StartNamespacesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "namespaces", v1meta.NamespaceAll, fields.Everything())
	namespaceInf = cache.NewSharedInformer(lw, &v1.Namespace{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchNamespaces(evtc)
		namespaceInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchNamespaces(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchNamespaces()")

	namespaceInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("namespaces")
				//log.Debugf("AddFunc dumping namespace: %v", obj.(*v1.Namespace))
				evtc <- nsEvent(obj.(*v1.Namespace),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("Namespace", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNS := oldObj.(*v1.Namespace)
				newNS := newObj.(*v1.Namespace)
				if oldNS.GetResourceVersion() != newNS.GetResourceVersion() && !nsEquals(oldNS, newNS) {
					//log.Debugf("UpdateFunc dumping namespace oldNS %v", oldNS)
					//log.Debugf("UpdateFunc dumping namespace newNS %v", newNS)
					evtc <- nsEvent(newNS,
						draiosproto.CongroupEventType_UPDATED.Enum())
					kubecollect_common.AddEvent("Namespace", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("Namespace", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldNS := (*v1.Namespace)(nil)
				switch obj.(type) {
				case *v1.Namespace:
					oldNS = obj.(*v1.Namespace)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.Namespace)
					if ok {
						oldNS = o
					} else {
						log.Warn("DeletedFinalStateUnknown without namespace object")
					}
				default:
					log.Warn("Unknown object type in namespace DeleteFunc")
				}
				if oldNS == nil {
					return
				}

				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_namespace"),
							Id:proto.String(string(oldNS.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("Namespace", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
