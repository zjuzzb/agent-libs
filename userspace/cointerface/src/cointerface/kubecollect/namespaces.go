package kubecollect

import (
	"cointerface/draiosproto"
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

	if !EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) ||
        !EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta) {
		return false
	}

	return true
}

func newNSCongroup(ns *v1.Namespace, eventType *draiosproto.CongroupEventType) (*draiosproto.ContainerGroup) {
	tags:= GetTags(ns.ObjectMeta, "kubernetes.namespace.")
	inttags:= GetAnnotations(ns.ObjectMeta, "kubernetes.namespace.")

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_namespace"),
			Id:proto.String(string(ns.GetUID()))},
		Tags: tags,
		InternalTags: inttags,
	}
	if *eventType == draiosproto.CongroupEventType_ADDED {
		AddDeploymentChildrenFromNamespace(&ret.Children, ns.GetName())
		AddDaemonSetChildrenFromNamespace(&ret.Children, ns.GetName())
		AddServiceChildrenFromNamespace(&ret.Children, ns.GetName())
		AddCronJobChildrenFromNamespace(&ret.Children, ns.GetName())
		AddJobChildrenFromNamespace(&ret.Children, ns.GetName())
		AddPodChildrenFromNamespace(&ret.Children, ns.GetName())
		AddReplicaSetChildrenFromNamespace(&ret.Children, ns.GetName())
		AddReplicationControllerChildrenFromNamespace(&ret.Children, ns.GetName())
		AddResourceQuotaChildrenFromNamespace(&ret.Children, ns.GetName())
		AddStatefulSetChildrenFromNamespace(&ret.Children, ns.GetName())
		AddIngressChildrenFromNamespace(&ret.Children, ns.GetName())
		AddHorizontalPodAutoscalerChildrenFromNamespace(&ret.Children, ns.GetName())
		AddPersistentVolumeClaimChildrenFromNamespace(&ret.Children, ns.GetName())
	}

	return ret
}

var namespaceInf cache.SharedInformer

func AddNSParents(parents *[]*draiosproto.CongroupUid, ns string) {
	if !resourceReady("namespaces") {
		return
	}

	for _, obj := range namespaceInf.GetStore().List() {
		nsObj := obj.(*v1.Namespace)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		if ns == nsObj.GetName() {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_namespace"),
				Id:proto.String(string(nsObj.GetUID()))})
			return
		}
	}
}

func startNamespacesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "namespaces", v1meta.NamespaceAll, fields.Everything())
	namespaceInf = cache.NewSharedInformer(lw, &v1.Namespace{}, RsyncInterval)

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
				eventReceived("namespaces")
				//log.Debugf("AddFunc dumping namespace: %v", obj.(*v1.Namespace))
				evtc <- nsEvent(obj.(*v1.Namespace),
					draiosproto.CongroupEventType_ADDED.Enum())
				addEvent("Namespace", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNS := oldObj.(*v1.Namespace)
				newNS := newObj.(*v1.Namespace)
				if oldNS.GetResourceVersion() != newNS.GetResourceVersion() && !nsEquals(oldNS, newNS) {
					//log.Debugf("UpdateFunc dumping namespace oldNS %v", oldNS)
					//log.Debugf("UpdateFunc dumping namespace newNS %v", newNS)
					evtc <- nsEvent(newNS,
						draiosproto.CongroupEventType_UPDATED.Enum())
					addEvent("Namespace", EVENT_UPDATE_AND_SEND)
				}
				addEvent("Namespace", EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldNS := obj.(*v1.Namespace)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_namespace"),
							Id:proto.String(string(oldNS.GetUID()))},
					},
				}
				addEvent("Namespace", EVENT_DELETE)
			},
		},
	)
}
