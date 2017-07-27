package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
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

func newNSCongroup(ns *v1.Namespace, eventType *draiosproto.CongroupEventType) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range ns.GetLabels() {
		tags["kubernetes.namespace.label." + k] = v
	}
	tags["kubernetes.namespace.name"] = ns.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_namespace"),
			Id:proto.String(string(ns.GetUID()))},
		Tags: tags,
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
	}

	return ret
}

var inf cache.SharedInformer

func AddNSParents(parents *[]*draiosproto.CongroupUid, ns string) {
	// Check first if (inf.HasSynced() == true) ??
	for _, obj := range inf.GetStore().List() {
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

func WatchNamespaces(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchNamespaces()")

	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "namespaces", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	inf = cache.NewSharedInformer(lw, &v1.Namespace{}, resyncPeriod)

	inf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping namespace: %v", obj.(*v1.Namespace))
				evtc <- nsEvent(obj.(*v1.Namespace),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNS := oldObj.(*v1.Namespace)
				newNS := newObj.(*v1.Namespace)
				if oldNS.GetResourceVersion() != newNS.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping namespace oldNS %v", oldNS)
					//log.Debugf("UpdateFunc dumping namespace newNS %v", newNS)
					evtc <- nsEvent(newNS,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping namespace: %v", obj.(*v1.Namespace))
				evtc <- nsEvent(obj.(*v1.Namespace),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go inf.Run(ctx.Done())

	//store := inf.GetStore()
	//return &store
	return inf
}
