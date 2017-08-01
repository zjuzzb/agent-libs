package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"strings"
	"k8s.io/apimachinery/pkg/labels"
)

// pods get their own special version because they send events for containers too
func sendPodEvents(evtc chan<- draiosproto.CongroupUpdateEvent, pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool)  {
	updates := newPodEvents(pod, eventType, oldPod, setLinks)
	for _, evt := range updates {
		evtc <- *evt
	}
}

func newContainerEvent(c *v1.ContainerStatus, eventType draiosproto.CongroupEventType, containerEvents *[]*draiosproto.CongroupUpdateEvent, podUID string, children *[]*draiosproto.CongroupUid) {
	par := []*draiosproto.CongroupUid{&draiosproto.CongroupUid{
		Kind:proto.String("k8s_pod"),
		Id:proto.String(podUID)},
	}

	// Kubernetes reports containers in this format:
	// docker://<fulldockercontainerid>
	// rkt://<rktpodid>:<rktappname>
	// We instead use
	// <dockershortcontainerid>
	// <rktpodid>:<rktappname>
	// so here we are doing this conversion
	containerId := c.ContainerID
	if strings.HasPrefix(containerId, "docker://") {
		containerId = containerId[9:21]
	} else if strings.HasPrefix(containerId, "rkt://") {
		containerId = containerId[6:]
	} else {
		// unknown container type or ContainerID not available yet
		return
	}

	imageId := c.ImageID[strings.LastIndex(c.ImageID, ":")+1:]
	imageId = imageId[:12]

	*containerEvents = append(*containerEvents, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup {
			Uid: &draiosproto.CongroupUid {
				Kind:proto.String("container"),
				Id:proto.String(containerId),
			},
			Tags: map[string]string{
				"container.name"    : c.Name,
				"container.image"   : c.Image,
				"container.image.id": imageId,
			},
			Parents: par,
		},
	})

	*children = append(*children, &draiosproto.CongroupUid {
		Kind:proto.String("container"),
		Id:proto.String(containerId)},
	)
}

func podEquals(lhs *v1.Pod, rhs *v1.Pod) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	if in && len(lhs.GetLabels()) != len(rhs.GetLabels()) {
		in = false
	} else {
		for k,v := range lhs.GetLabels() {
			if rhs.GetLabels()[k] != v {
				in = false
			}
		}
	}

	if in && lhs.Status.HostIP != rhs.Status.HostIP {
		in = false
	}
	if in && lhs.Status.PodIP != rhs.Status.PodIP {
		in = false
	}

	if in {
		lRestartCount := uint32(0)
		for _, c := range lhs.Status.ContainerStatuses {
			lRestartCount += uint32(c.RestartCount)
		}
		rRestartCount := uint32(0)
		for _, c := range rhs.Status.ContainerStatuses {
			rRestartCount += uint32(c.RestartCount)
		}
		if lRestartCount != rRestartCount {
			in = false
		}
	}

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	}

	if out && lhs.Spec.NodeName != rhs.Spec.NodeName {
		out = false
	}

	if out && len(lhs.GetOwnerReferences()) != len(rhs.GetOwnerReferences()) {
		out = false
	} else if out {
		count := 0
		for _, lOwner := range lhs.GetOwnerReferences() {
			for _, rOwner := range rhs.GetOwnerReferences() {
				if lOwner.UID == rOwner.UID {
					count++
					break
				}
			}
		}
		if count != len(lhs.GetOwnerReferences()) {
			out = false
		}
	}

	if out && len(lhs.Status.ContainerStatuses) != len(rhs.Status.ContainerStatuses) {
		out = false
	} else if out {
		count := 0
		for _, lC := range lhs.Status.ContainerStatuses {
			if lC.ContainerID == "" {
				continue
			}
			for _, rC := range rhs.Status.ContainerStatuses {
				if rC.ContainerID == "" {
					continue
				}
				if lC.ContainerID == rC.ContainerID {
					count++
					break
				}
			}
		}
		if count != len(lhs.Status.ContainerStatuses) {
			out = false
		}
	}

	return in, out
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool) ([]*draiosproto.CongroupUpdateEvent) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range pod.GetLabels() {
		tags["kubernetes.pod.label." + k] = v
	}
	tags["kubernetes.pod.name"] = pod.GetName()
	// Need a way to distinguish these too
	var ips []string
	if pod.Status.HostIP != "" {
		ips = append(ips, pod.Status.HostIP)
	}
	if pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}

	var metrics []*draiosproto.AppMetric
	addPodMetrics(&metrics, pod)

	var parents []*draiosproto.CongroupUid
	if setLinks {
		AddNSParents(&parents, pod.GetNamespace())
		AddReplicaSetParents(&parents, pod)
		AddReplicationControllerParents(&parents, pod)
		AddStatefulSetParentsFromPod(&parents, pod)
		AddServiceParents(&parents, pod)
		AddDaemonSetParents(&parents, pod)
		AddNodeParents(&parents, pod.Spec.NodeName)
		AddJobParents(&parents, pod)
	}

	var children []*draiosproto.CongroupUid
	var containerEvents []*draiosproto.CongroupUpdateEvent
	if setLinks {
		var oldContainers []v1.ContainerStatus
		if oldPod != nil {
			for _, oldC := range oldPod.Status.ContainerStatuses {
				if oldC.ContainerID != "" {
					oldContainers = append(oldContainers, oldC)
				}
			}
		}
		for _, c := range pod.Status.ContainerStatuses {

			if c.ContainerID == "" {
				continue
			}

			found := false
			for i := 0; i < len(oldContainers); i++ {
				if oldContainers[i].ContainerID == c.ContainerID {
					oldContainers[i] = oldContainers[len(oldContainers)-1]
					oldContainers = oldContainers[:len(oldContainers)-1]
					found = true
					break
				}
			}
			if found {
				// Never fire UPDATED events for containers
				continue
			}

			var cEvtType draiosproto.CongroupEventType
			if eventType == draiosproto.CongroupEventType_UPDATED {
				cEvtType = draiosproto.CongroupEventType_ADDED
			} else {
				cEvtType = eventType
			}
			newContainerEvent(&c, cEvtType, &containerEvents, string(pod.GetUID()), &children)
		}
		for _, removedC := range oldContainers {
			if removedC.ContainerID != "" {
				newContainerEvent(&removedC, draiosproto.CongroupEventType_REMOVED, &containerEvents, string(pod.GetUID()), &children)
			}
		}
	}

	var cg []*draiosproto.CongroupUpdateEvent
	cg = append(cg, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup{
			Uid: &draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(pod.GetUID()))},
			Tags: tags,
			IpAddresses: ips,
			Metrics: metrics,
			Parents: parents,
			Children: children,
		},
	})
	cg = append(cg, containerEvents...)

	return cg
}

var podInf cache.SharedInformer

func addPodMetrics(metrics *[]*draiosproto.AppMetric, pod *v1.Pod) {
	prefix := "kubernetes.pod."

	// Dummy stub, we need to make the container status
	// metrics part of the container events
	restartCount := int32(0)
	for _, c := range pod.Status.ContainerStatuses {
		restartCount += c.RestartCount
	}

	AppendMetricInt32(metrics, prefix+"container.status.restarts", restartCount)
	AppendMetricInt32(metrics, prefix+"restart.count", restartCount)
}

func AddPodChildren(children *[]*draiosproto.CongroupUid, selector labels.Selector, namespace string) {
	if CompatibilityMap["pods"] {
		for _, obj := range podInf.GetStore().List() {
			pod := obj.(*v1.Pod)
			if pod.GetNamespace() == namespace && selector.Matches(labels.Set(pod.GetLabels())) {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_pod"),
					Id:proto.String(string(pod.GetUID()))})
			}
		}
	}
}

func AddPodChildrenFromNodeName(children *[]*draiosproto.CongroupUid, nodeName string) {
	if CompatibilityMap["pods"] {
		for _, obj := range podInf.GetStore().List() {
			pod := obj.(*v1.Pod)
			if pod.Spec.NodeName == nodeName {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_pod"),
					Id:proto.String(string(pod.GetUID()))})
			}
		}
	}
}

func AddPodChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if CompatibilityMap["pods"] {
		for _, obj := range podInf.GetStore().List() {
			pod := obj.(*v1.Pod)
			if pod.GetNamespace() == namespaceName {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_pod"),
					Id:proto.String(string(pod.GetUID()))})
			}
		}
	}
}

func AddPodChildrenFromOwnerRef(children *[]*draiosproto.CongroupUid, parent v1meta.ObjectMeta) {
	if CompatibilityMap["pods"] {
		for _, obj := range podInf.GetStore().List() {
			pod := obj.(*v1.Pod)
			for _, owner := range pod.GetOwnerReferences() {
				if owner.UID == parent.GetUID() {
					*children = append(*children, &draiosproto.CongroupUid{
						Kind:proto.String("k8s_pod"),
						Id:proto.String(string(pod.GetUID()))})
				}
			}
		}
	}
}

func StartPodsSInformer(ctx context.Context, kubeClient kubeclient.Interface) {
	client := kubeClient.CoreV1().RESTClient()
	fSelector, _ := fields.ParseSelector("status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded") // they don't support or operator...
	lw := cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, fSelector)
	podInf = cache.NewSharedInformer(lw, &v1.Pod{}, RsyncInterval)
	go podInf.Run(ctx.Done())
}

func WatchPods(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchPods()")

	podInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				newPod := obj.(*v1.Pod)
				sendPodEvents(evtc, newPod, draiosproto.CongroupEventType_ADDED, nil, true)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod := oldObj.(*v1.Pod)
				newPod := newObj.(*v1.Pod)
				if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
					sameEntity, sameLinks := podEquals(oldPod, newPod)
					if !sameEntity || !sameLinks {
						sendPodEvents(evtc, newPod, draiosproto.CongroupEventType_UPDATED, oldPod, !sameLinks)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldPod := obj.(*v1.Pod)
				// we have to call the function in this case because it will remove the containers too
				sendPodEvents(evtc, oldPod, draiosproto.CongroupEventType_REMOVED, nil, true)
			},
		},
	)
}
