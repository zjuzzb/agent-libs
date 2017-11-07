package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

var nodeInf cache.SharedInformer

func nodeEvent(node *v1.Node, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newNodeCongroup(node),
	}
}

func nodeEquals(oldNode *v1.Node, newNode *v1.Node) bool {

	if oldNode.GetName() != newNode.GetName() {
		return false
	}

	if !EqualLabels(oldNode.ObjectMeta, newNode.ObjectMeta) ||
        !EqualAnnotations(oldNode.ObjectMeta, newNode.ObjectMeta) {
		return false
	}

	return true
}

func newNodeCongroup(node *v1.Node) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_node"),
			Id:proto.String(string(node.GetUID()))},
	}

	for _, nodeAddress := range node.Status.Addresses {
		ret.IpAddresses = append(ret.IpAddresses, nodeAddress.Address)
	}

	ret.Tags = GetTags(node.ObjectMeta, "kubernetes.node.")
	ret.InternalTags = GetAnnotations(node.ObjectMeta, "kubernetes.node.")
	addNodeMetrics(&ret.Metrics, node)
	AddPodChildrenFromNodeName(&ret.Children, node.GetName())
	return ret
}

func addNodeMetrics(metrics *[]*draiosproto.AppMetric, node *v1.Node) {
	prefix := "kubernetes.node."
	AppendMetricBool(metrics, prefix+"spec.unschedulable", node.Spec.Unschedulable)
	appendMetricResource(metrics, prefix+"status.capacity.cpuCores", node.Status.Capacity, v1.ResourceCPU)
	appendMetricResource(metrics, prefix+"status.capacity.memoryBytes", node.Status.Capacity, v1.ResourceMemory)
	appendMetricResource(metrics, prefix+"status.capacity.pods", node.Status.Capacity, v1.ResourcePods)
	appendMetricResource(metrics, prefix+"status.allocatable.cpuCores", node.Status.Allocatable, v1.ResourceCPU)
	appendMetricResource(metrics, prefix+"status.allocatable.memoryBytes", node.Status.Allocatable, v1.ResourceMemory)
	appendMetricResource(metrics, prefix+"status.allocatable.pods", node.Status.Allocatable, v1.ResourcePods)
	appendMetricNodeCondition(metrics, prefix+"status.ready", node.Status.Conditions, v1.NodeReady)
	appendMetricNodeCondition(metrics, prefix+"status.outOfDisk", node.Status.Conditions, v1.NodeOutOfDisk)
	appendMetricNodeCondition(metrics, prefix+"status.memoryPressure", node.Status.Conditions, v1.NodeMemoryPressure)
	appendMetricNodeCondition(metrics, prefix+"status.diskPressure", node.Status.Conditions, v1.NodeDiskPressure)
	appendMetricNodeCondition(metrics, prefix+"status.networkUnavailable", node.Status.Conditions, v1.NodeNetworkUnavailable)
	appendMetricNodeCondition(metrics, prefix+"status.inodePressure", node.Status.Conditions, v1.NodeInodePressure)
}

func appendMetricNodeCondition(metrics *[]*draiosproto.AppMetric, name string, conditions []v1.NodeCondition, ctype v1.NodeConditionType) {
	val := float64(0)
	found := false
	for _, cond := range conditions {
		if cond.Type != ctype {
			continue
		}
		switch cond.Status {
		case v1.ConditionTrue:
			val, found = 1, true
		case v1.ConditionFalse:
			fallthrough
		case v1.ConditionUnknown:
			val, found = 0, true
		}
		break
	}

	if found {
		AppendMetric(metrics, name, val)
	}
}

func AddNodeParents(parents *[]*draiosproto.CongroupUid, nodeName string) {
	if CompatibilityMap["nodes"] {
		for _, obj := range nodeInf.GetStore().List() {
			node := obj.(*v1.Node)
			if node.GetName() == nodeName {
				*parents = append(*parents, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_node"),
					Id:proto.String(string(node.GetUID()))})
			}
		}
	}
}

func StartNodesSInformer(ctx context.Context, kubeClient kubeclient.Interface) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Nodes", v1meta.NamespaceAll, fields.Everything())
	nodeInf = cache.NewSharedInformer(lw, &v1.Node{}, RsyncInterval)
	go nodeInf.Run(ctx.Done())
}

func WatchNodes(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchNodes()")

	nodeInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- nodeEvent(obj.(*v1.Node),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNode := oldObj.(*v1.Node)
				newNode := newObj.(*v1.Node)
				if oldNode.GetResourceVersion() != newNode.GetResourceVersion() && !nodeEquals(oldNode, newNode) {
					evtc <- nodeEvent(newNode,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldNode := obj.(*v1.Node)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_node"),
							Id:proto.String(string(oldNode.GetUID()))},
					},
				}
			},
		},
	)

	return nodeInf
}
