package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func nodeEvent(node *v1.Node, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newNodeCongroup(node),
	}
}

func newNodeCongroup(node *v1.Node) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_node"),
			Id:   proto.String(string(node.GetUID()))},
		Node: proto.String(node.Name),
	}

	for _, nodeAddress := range node.Status.Addresses {
		found := false
		for _, addr := range ret.IpAddresses {
			if nodeAddress.Address == addr {
				found = true
			}
		}
		if !found {
			ret.IpAddresses = append(ret.IpAddresses, nodeAddress.Address)
		}
	}

	ret.Tags = kubecollect_common.GetTags(node, "kubernetes.node.")
	ret.InternalTags = kubecollect_common.GetAnnotations(node.ObjectMeta, "kubernetes.node.")
	kubecollect.AddNodeMetrics(&ret.Metrics, node)
	return ret
}

func startNodesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Nodes", v1meta.NamespaceAll, fields.Everything())
	kubecollect.NodeInf = cache.NewSharedInformer(lw, &v1.Node{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchNodes(evtc)
		kubecollect.NodeInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchNodes(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchNodes() from package %s", kubecollect_common.GetPkg(KubecollectClientTc{}))

	kubecollect.NodeInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("nodes")
				evtc <- nodeEvent(obj.(*v1.Node),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("Node", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNode := oldObj.(*v1.Node)
				newNode := newObj.(*v1.Node)
				if oldNode.GetResourceVersion() != newNode.GetResourceVersion() && !kubecollect.NodeEquals(oldNode, newNode) {
					evtc <- nodeEvent(newNode,
						draiosproto.CongroupEventType_UPDATED.Enum())
					kubecollect_common.AddEvent("Node", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("Node", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldNode := (*v1.Node)(nil)
				switch obj.(type) {
				case *v1.Node:
					oldNode = obj.(*v1.Node)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.Node)
					if ok {
						oldNode = o
					} else {
						log.Warn("DeletedFinalStateUnknown without node object")
					}
				default:
					log.Warn("Unknown object type in node DeleteFunc")
				}
				if oldNode == nil {
					return
				}

				evtc <- draiosproto.CongroupUpdateEvent{
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind: proto.String("k8s_node"),
							Id:   proto.String(string(oldNode.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("Node", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
