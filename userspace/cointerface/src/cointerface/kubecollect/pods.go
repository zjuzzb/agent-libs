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

var podInf cache.SharedInformer

// pods get their own special version because they send events for containers too
func sendPodEvents(evtc chan<- draiosproto.CongroupUpdateEvent, pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool)  {
	updates := newPodEvents(pod, eventType, oldPod, setLinks)
	for _, evt := range updates {
		evtc <- *evt
	}
}

// We pass the ContainerStatus along with the pod since the caller
// already has it, and it saves us a lookup. We use the status name
// to get the corresponding Container aka the spec
func newContainerEvent(pod *v1.Pod,
	cstat *v1.ContainerStatus,
	eventType draiosproto.CongroupEventType,
	containerEvents *[]*draiosproto.CongroupUpdateEvent,
	children *[]*draiosproto.CongroupUid) {

	par := []*draiosproto.CongroupUid{&draiosproto.CongroupUid{
		Kind:proto.String("k8s_pod"),
		Id:proto.String(string(pod.GetUID()))},
	}

	// Kubernetes reports containers in this format:
	// docker://<fulldockercontainerid>
	// rkt://<rktpodid>:<rktappname>
	// We instead use
	// <dockershortcontainerid>
	// <rktpodid>:<rktappname>
	// so here we are doing this conversion
	containerId := cstat.ContainerID
	if strings.HasPrefix(containerId, "docker://") {
		containerId = containerId[9:21]
	} else if strings.HasPrefix(containerId, "rkt://") {
		containerId = containerId[6:]
	} else {
		// unknown container type or ContainerID not available yet
		return
	}

	imageId := cstat.ImageID[strings.LastIndex(cstat.ImageID, ":")+1:]
	imageId = imageId[:12]

	var metrics []*draiosproto.AppMetric
	found := false
	// There should always be a spec with the same name
	// as the status, so complain if we don't find it
	for _, c := range pod.Spec.Containers {
		if c.Name == cstat.Name {
			addContainerMetrics(&metrics, &c)
			found = true
			break
		}
	}
	if !found {
		log.Errorf("Could not find container spec for %v on pod %v",
			cstat.Name, pod.GetName())
	}

	*containerEvents = append(*containerEvents, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup {
			Uid: &draiosproto.CongroupUid {
				Kind:proto.String("container"),
				Id:proto.String(containerId),
			},
			Tags: map[string]string{
				"container.name"    : cstat.Name,
				"container.image"   : cstat.Image,
				"container.image.id": imageId,
			},
			Parents: par,
			Metrics: metrics,
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

	if out {
		lContainerCount := 0
		rContainerCount := 0

		for _, c := range lhs.Status.ContainerStatuses {
			if c.ContainerID != "" {
				lContainerCount++
			}
		}
		for _, c := range rhs.Status.ContainerStatuses {
			if c.ContainerID != "" {
				rContainerCount++
			}
		}

		if lContainerCount != rContainerCount {
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
	}

	return in, out
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool) ([]*draiosproto.CongroupUpdateEvent) {
	tags := GetTags(pod.ObjectMeta, "kubernetes.pod.")

	var ips []string
	/*if pod.Status.HostIP != "" {
		ips = append(ips, pod.Status.HostIP)
	}*/
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

		// Generate ADDED events for containers
		// that are in the new pod but not oldPod,
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
				// This means we can't do per-container stat updates
				continue
			}

			var cEvtType draiosproto.CongroupEventType
			if eventType == draiosproto.CongroupEventType_UPDATED {
				cEvtType = draiosproto.CongroupEventType_ADDED
			} else {
				cEvtType = eventType
			}
			newContainerEvent(pod, &c, cEvtType,
				&containerEvents, &children)
		}

		// Any remaining containers must have been deleted
		for _, removedC := range oldContainers {
			if removedC.ContainerID != "" {
				newContainerEvent(pod, &removedC,
					draiosproto.CongroupEventType_REMOVED,
					&containerEvents, &children)
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

// Containers only send ADDED/REMOVED events, so we can only use the
// static Container object for stats and nothing from ContainerStatus
func addContainerMetrics(metrics *[]*draiosproto.AppMetric, con *v1.Container) {
	prefix := "kubernetes.pod.container."
	appendMetricResource(metrics, prefix+"resourceRequests.cpuCores",
		con.Resources.Requests, v1.ResourceCPU)
	appendMetricResource(metrics, prefix+"resourceRequests.memoryBytes",
		con.Resources.Requests, v1.ResourceMemory)
	appendMetricResource(metrics, prefix+"resourceLimits.cpuCores",
		con.Resources.Limits, v1.ResourceCPU)
	appendMetricResource(metrics, prefix+"resourceLimits.memoryBytes",
		con.Resources.Limits, v1.ResourceMemory)
}

func addPodMetrics(metrics *[]*draiosproto.AppMetric, pod *v1.Pod) {
	prefix := "kubernetes.pod."

	// Restart count is a legacy metric attributed to pods
	// instead of the individual containers, so report it here
	restartCount := int32(0)
	waitingCount := int32(0)
	for _, c := range pod.Status.ContainerStatuses {
		restartCount += c.RestartCount
		if c.State.Waiting != nil {
			waitingCount += 1
		}
	}
	AppendMetricInt32(metrics, prefix+"container.status.restarts", restartCount)
	AppendMetricInt32(metrics, prefix+"container.status.waiting", waitingCount)
}

func resolveTargetPort(name string, selector labels.Selector, namespace string) uint32 {
	if !CompatibilityMap["pods"] {
		return 0
	}

	for _, obj := range podInf.GetStore().List() {
		pod := obj.(*v1.Pod)
		if !(pod.GetNamespace() == namespace && selector.Matches(labels.Set(pod.GetLabels()))) {
			continue
		}

		for _, c := range pod.Spec.Containers {
			for _, p := range c.Ports {
				if p.Name == name {
					return uint32(p.ContainerPort)
				}
			}
		}
	}
	return 0
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
