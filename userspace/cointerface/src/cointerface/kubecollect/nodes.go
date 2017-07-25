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
func nodeEvent(ns *v1.Node, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newNodeCongroup(ns),
	}
}

func newNodeCongroup(node *v1.Node) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range node.GetLabels() {
		tags["kubernetes.node.label." + k] = v
	}
	tags["kubernetes.node.name"] = node.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_node"),
			Id:proto.String(string(node.GetUID()))},
		Tags: tags,
	}
	return ret
}

var nodeInf cache.SharedInformer

func AddNodeParents(parents *[]*draiosproto.CongroupUid, nodeName string) {
	for _, obj := range nodeInf.GetStore().List() {
		node := obj.(*v1.Node)
		if node.GetName() == nodeName {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_node"),
				Id:proto.String(string(node.GetUID()))})
		}
	}
}

func WatchNodes(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchNodes()")

	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Nodes", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	nodeInf = cache.NewSharedInformer(lw, &v1.Node{}, resyncPeriod)

	nodeInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping Node: %v", obj.(*v1.Node))
				evtc <- nodeEvent(obj.(*v1.Node),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNode := oldObj.(*v1.Node)
				newNode := newObj.(*v1.Node)
				if oldNode.GetResourceVersion() != newNode.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping Node oldNode %v", oldNode)
					//log.Debugf("UpdateFunc dumping Node newNode %v", newNode)
					evtc <- nodeEvent(newNode,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping Node: %v", obj.(*v1.Node))
				evtc <- nodeEvent(obj.(*v1.Node),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go nodeInf.Run(ctx.Done())

	return nodeInf
}
