package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	draiosproto "protorepo/agent-be/proto"
	"strings"
	"sync"
)

var podInf cache.SharedInformer
var podEvtcHandle chan<- draiosproto.CongroupUpdateEvent

// container IDs from k8s are of the form <scheme>://<container_id>
// runc-based runtimes (Docker, containerd, CRI-o) use 64 hex digits as the ID
// but we truncate them to 12 characters for readability reasons
// known schemes (corresponding to k8s runtimes):
// - docker
// - rkt
// - containerd
// - cri-o
// rkt uses a different container ID format: rkt://<pod_id>:<app_id>

// pods get their own special version because they send events for containers too
func sendPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool)  {
	updates := newPodEvents(pod, eventType, oldPod, setLinks)
	for _, evt := range updates {
		podEvtcHandle <- *evt
	}
}

// Append ADDED/REMOVED events both containerEvents
func newContainerEvent(containerEvents *[]*draiosproto.CongroupUpdateEvent,
	cstat *v1.ContainerStatus,
	podUID types.UID,
	eventType draiosproto.CongroupEventType,
) {
	containerID, err := kubecollect_common.ParseContainerID(cstat.ContainerID)
	if err != nil {
		log.Debugf("Unable to parse ContainerID %v: %v", containerID, err)
		return
	}

	imageId := cstat.ImageID[strings.LastIndex(cstat.ImageID, ":")+1:]
	imageId = imageId[:12]

	*containerEvents = append(*containerEvents, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup {
			Uid: &draiosproto.CongroupUid {
				Kind:proto.String("container"),
				Id:proto.String(containerID),
			},
			Tags: map[string]string{
				"container.name"    : cstat.Name,
				"container.image"   : cstat.Image,
				"container.image.id": imageId,
			},
			Parents: []*draiosproto.CongroupUid{&draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(podUID))},
			},
		},
	})
	if eventType == draiosproto.CongroupEventType_ADDED {
		kubecollect_common.AddEvent("Container", kubecollect_common.EVENT_ADD)
	} else if eventType == draiosproto.CongroupEventType_REMOVED {
		kubecollect_common.AddEvent("Container", kubecollect_common.EVENT_DELETE)
	} else {
		kubecollect_common.AddEvent("Container", kubecollect_common.EVENT_UPDATE)
	}
}

// Append ADDED/REMOVED container events to contEvents and add
// child links for all running containers to podChildren
func processContainers(contEvents *[]*draiosproto.CongroupUpdateEvent,
	podChildren *[]*draiosproto.CongroupUid,
	containers []v1.ContainerStatus,
	oldContainers []v1.ContainerStatus,
	podUID types.UID,
	evtType draiosproto.CongroupEventType,
) {
	type cState int
	const (
		waiting cState = iota
		running
		terminated
	)
	getState := func(cs v1.ContainerState) cState {
		if cs.Terminated != nil {
			return terminated
		} else if cs.Running != nil {
			return running
		}
		// Waiting is the default if all three are nil
		return waiting
	}

	for _, c := range containers {
		state := getState(c.State)
		if (state < running) {
			continue
		} else if (state == running) {
			containerID, err := kubecollect_common.ParseContainerID(c.ContainerID)
			if err != nil {
				log.Debugf("Unable to parse ContainerID %v: %v", containerID, err)
				continue
			}

			// All running containers need to be added to the child list
			// even if they don't have an ADDED or REMOVED event this time
			*podChildren = append(*podChildren, &draiosproto.CongroupUid {
				Kind:proto.String("container"),
				Id:proto.String(containerID)},
			)
		}

		var oldState cState = waiting
		for _, oldC := range oldContainers {
			if oldC.Name == c.Name {
				oldState = getState(oldC.State)
				break;
			}
		}

		newEvent := false
		var newType draiosproto.CongroupEventType
		switch state {
		case running:
			if oldState < running &&
				(evtType == draiosproto.CongroupEventType_ADDED ||
				evtType == draiosproto.CongroupEventType_UPDATED) {
				newEvent, newType = true, draiosproto.CongroupEventType_ADDED
			}
		case terminated:
			// Always send for REMOVED, and send on UPDATED if we
			// notice a state transition. This results in sending
			// two delete events if we catch the UPDATED transition,
			// but the infra state code can handle double deletes
			if evtType == draiosproto.CongroupEventType_REMOVED ||
				(evtType == draiosproto.CongroupEventType_UPDATED &&
				oldState == running) {
				newEvent, newType = true, draiosproto.CongroupEventType_REMOVED
			}
		default:
			log.Errorf("Unexpected state=%v while processing containers", state)
		}

		if newEvent {
			newContainerEvent(contEvents, &c, podUID, newType)
		}
	}
}

func podEquals(lhs *v1.Pod, rhs *v1.Pod) (bool, bool) {
	in := true
	out := true
	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	in = in && kubecollect_common.EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)
	in = in && kubecollect_common.EqualProbes(lhs, rhs)

	if in && lhs.Status.PodIP != rhs.Status.PodIP {
		in = false
	}

	if in {
		lRestarts, lWaiting := statusCounts(lhs.Status.ContainerStatuses)
		rRestarts, rWaiting := statusCounts(rhs.Status.ContainerStatuses)
		if (lRestarts != rRestarts) || (lWaiting != rWaiting) {
			in = false
		}
	}

	if in {
		lInitRestarts, lInitWaiting := statusCounts(lhs.Status.InitContainerStatuses)
		rInitRestarts, rInitWaiting := statusCounts(rhs.Status.InitContainerStatuses)
		if (lInitRestarts != rInitRestarts) || (lInitWaiting != rInitWaiting) {
			in = false
		}
	}

	if in {
		lVal, lFound := getPodConditionMetric(lhs.Status.Conditions, v1.PodReady)
		rVal, rFound := getPodConditionMetric(rhs.Status.Conditions, v1.PodReady)
		if lFound != rFound || lVal != rVal {
			in = false
		}
	}

	if in {
		lRequestsCpu, lLimitsCpu, lRequestsMem, lLimitsMem := getPodContainerResources(lhs)
		rRequestsCpu, rLimitsCpu, rRequestsMem, rLimitsMem := getPodContainerResources(rhs)
		if lRequestsCpu != rRequestsCpu || lLimitsCpu != rLimitsCpu ||
			lRequestsMem != rRequestsMem || lLimitsMem != rLimitsMem {
			in = false
		}
	}

	out = out && kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta)

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
		// rhs is the new pod, lhs is the old pod
		var children []*draiosproto.CongroupUid
		var containerEvents []*draiosproto.CongroupUpdateEvent
		processContainers(&containerEvents, &children,
			rhs.Status.ContainerStatuses,
			lhs.Status.ContainerStatuses,
			rhs.GetUID(), draiosproto.CongroupEventType_UPDATED)
		if len(containerEvents) > 0 {
			out = false
		}
	}
	if out {
		var children []*draiosproto.CongroupUid
		var containerEvents []*draiosproto.CongroupUpdateEvent
		processContainers(&containerEvents, &children,
			rhs.Status.InitContainerStatuses,
			lhs.Status.InitContainerStatuses,
			rhs.GetUID(), draiosproto.CongroupEventType_UPDATED)
		if len(containerEvents) > 0 {
			out = false
		}
	}

	return in, out
}

func statusCounts(containers []v1.ContainerStatus) (restarts, waiting int32) {
	for _, c := range containers {
		restarts += c.RestartCount
		if c.State.Waiting != nil {
			waiting += 1
		}
	}
	return
}

var ownerRefKindToCongroupKind = map[string]string {
	"ReplicaSet": "k8s_replicaset",
	"ReplicationController": "k8s_replicationcontroller",
	"StatefulSet": "k8s_statefulset",
	"DaemonSet": "k8s_daemonset",
	"Job": "k8s_job",
}

func AddParentsToPodViaOwnerRef(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	for _, ref := range pod.GetOwnerReferences() {
		congroupKind := ownerRefKindToCongroupKind[ref.Kind]
		if congroupKind != "" {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind: proto.String(congroupKind),
				Id: proto.String(string(ref.UID))})
		} else {
			log.Debugf("Unexpected k8s kind %v", ref.Kind)
		}
	}
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool) ([]*draiosproto.CongroupUpdateEvent) {
	tags := kubecollect_common.GetTags(pod.ObjectMeta, "kubernetes.pod.")
	// This gets specially added as a tag since we don't have a
	// better way to report values that can be one of many strings
	tags["kubernetes.pod.label.status.phase"] = string(pod.Status.Phase)
	annotations := kubecollect_common.GetAnnotations(pod.ObjectMeta, "kubernetes.pod.")
	probes := kubecollect_common.GetProbes(pod)
	inttags := kubecollect_common.MergeInternalTags(annotations, probes)

	var ips []string
	if pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}

	var metrics []*draiosproto.AppMetric
	addPodMetrics(&metrics, pod)

	var parents []*draiosproto.CongroupUid
	if setLinks {
		AddNodeParents(&parents, pod.Spec.NodeName)

		AddParentsToPodViaOwnerRef(&parents, pod);
		// services don't have owner references and always use selectors
		AddServiceParents(&parents, pod)
	}

	var children []*draiosproto.CongroupUid
	var containerEvents []*draiosproto.CongroupUpdateEvent
	if setLinks {
		var oldContainers []v1.ContainerStatus
		var oldInitContainers []v1.ContainerStatus
		if oldPod != nil {
			oldContainers = oldPod.Status.ContainerStatuses
			oldInitContainers = oldPod.Status.InitContainerStatuses
		}
		processContainers(&containerEvents, &children,
			pod.Status.ContainerStatuses,
			oldContainers, pod.GetUID(), eventType)
		processContainers(&containerEvents, &children,
			pod.Status.InitContainerStatuses,
			oldInitContainers, pod.GetUID(), eventType)
	}

	var cg []*draiosproto.CongroupUpdateEvent
	cg = append(cg, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup{
			Uid: &draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(pod.GetUID()))},
			Tags: tags,
			InternalTags: inttags,
			IpAddresses: ips,
			Metrics: metrics,
			Parents: parents,
			Children: children,
			Namespace:proto.String(pod.GetNamespace()),
		},
	})
	cg = append(cg, containerEvents...)

	return cg
}

func addPodMetrics(metrics *[]*draiosproto.AppMetric, pod *v1.Pod) {
	prefix := "kubernetes.pod."

	// Restart count is a legacy metric attributed to pods
	// instead of the individual containers, so report it here
	restartCount, waitingCount := statusCounts(pod.Status.ContainerStatuses)
	initRestarts, initWaiting := statusCounts(pod.Status.InitContainerStatuses)
	restartCount += initRestarts
	waitingCount += initWaiting

	kubecollect_common.AppendMetricInt32(metrics, prefix+"container.status.restarts", restartCount)
	kubecollect_common.AppendRateMetric(metrics, prefix+"container.status.restart_rate", float64(restartCount))
	kubecollect_common.AppendMetricInt32(metrics, prefix+"container.status.waiting", waitingCount)
	appendMetricPodCondition(metrics, prefix+"status.ready", pod.Status.Conditions, v1.PodReady)
	appendMetricContainerResources(metrics, prefix, pod)
}

func getPodConditionMetric(conditions []v1.PodCondition, ctype v1.PodConditionType) (float64, bool) {
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
	return val, found
}

func appendMetricPodCondition(metrics *[]*draiosproto.AppMetric, name string, conditions []v1.PodCondition, ctype v1.PodConditionType) {
	val, found := getPodConditionMetric(conditions, ctype)

	if found {
		kubecollect_common.AppendMetric(metrics, name, val)
	}
}

func getPodContainerResources(pod *v1.Pod) (requestsCpu float64, limitsCpu float64, requestsMem float64, limitsMem float64) {
	requestsCpu, limitsCpu, requestsMem, limitsMem = 0, 0, 0, 0

	// https://kubernetes.io/docs/concepts/workloads/pods/init-containers/#resources
	// Pod effective resources are the higher of the sum of all app containers
	// or the highest init container value for that resource
	for _, c := range pod.Spec.Containers {
		requestsCpu += resourceVal(c.Resources.Requests, v1.ResourceCPU)
		limitsCpu += resourceVal(c.Resources.Limits, v1.ResourceCPU)
		requestsMem += resourceVal(c.Resources.Requests, v1.ResourceMemory)
		limitsMem += resourceVal(c.Resources.Limits, v1.ResourceMemory)
	}

	for _, c := range pod.Spec.InitContainers {
		initRequestsCpu := resourceVal(c.Resources.Requests, v1.ResourceCPU)
		if initRequestsCpu > requestsCpu {
			requestsCpu = initRequestsCpu
		}
		initLimitsCpu := resourceVal(c.Resources.Limits, v1.ResourceCPU)
		if initLimitsCpu > limitsCpu {
			limitsCpu = initLimitsCpu
		}
		initRequestsMem := resourceVal(c.Resources.Requests, v1.ResourceMemory)
		if initRequestsMem > requestsMem {
			requestsMem = initRequestsMem
		}
		initLimitsMem := resourceVal(c.Resources.Limits, v1.ResourceMemory)
		if initLimitsMem > limitsMem {
			limitsMem = initLimitsMem
		}
	}

	return
}

func appendMetricContainerResources(metrics *[]*draiosproto.AppMetric, prefix string, pod *v1.Pod) {
	requestsCpu, limitsCpu, requestsMem, limitsMem := getPodContainerResources(pod)

	kubecollect_common.AppendMetric(metrics, prefix+"resourceRequests.cpuCores", requestsCpu)
	kubecollect_common.AppendMetric(metrics, prefix+"resourceLimits.cpuCores", limitsCpu)
	kubecollect_common.AppendMetric(metrics, prefix+"resourceRequests.memoryBytes", requestsMem)
	kubecollect_common.AppendMetric(metrics, prefix+"resourceLimits.memoryBytes", limitsMem)
}

func resourceVal(rList v1.ResourceList, rName v1.ResourceName) float64 {
	v := float64(0)
	qty, ok := rList[rName]
	if ok {
		// Take MilliValue() and divide because
		// we could lose precision with Value()
		v = float64(qty.MilliValue())/1000
	}
	return v
}

func resolveTargetPort(name string, selector labels.Selector, namespace string) uint32 {
	if !kubecollect_common.ResourceReady("pods") {
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

func AddPodChildrenFromSelectors(children *[]*draiosproto.CongroupUid, selector labels.Selector, namespace string) {
	if !kubecollect_common.ResourceReady("pods") {
		return
	}

	for _, obj := range podInf.GetStore().List() {
		pod := obj.(*v1.Pod)
		if pod.GetNamespace() == namespace && selector.Matches(labels.Set(pod.GetLabels())) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(pod.GetUID()))})
		}
	}
}

func AddPodChildrenFromNodeName(children *[]*draiosproto.CongroupUid, nodeName string) {
	if !kubecollect_common.ResourceReady("pods") {
		return
	}

	for _, obj := range podInf.GetStore().List() {
		pod := obj.(*v1.Pod)
		if pod.Spec.NodeName == nodeName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(pod.GetUID()))})
		}
	}
}

func AddPodChildrenFromOwnerRef(children *[]*draiosproto.CongroupUid, parent v1meta.ObjectMeta) {
	if !kubecollect_common.ResourceReady("pods") {
		return
	}

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

func startPodsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	fSelector, _ := fields.ParseSelector("status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded") // they don't support or operator...
	lw := cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, fSelector)
	podInf = cache.NewSharedInformer(lw, &v1.Pod{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		podEvtcHandle = evtc
		watchPods()
		podInf.Run(ctx.Done())
		wg.Done()
	}()
}

// XXX For pods, this is broken out as a separate function as an example of how
// we can do it generically and also UT it, but not copying to other resources
// until we refactor the generic bits
func podDeleteFunc(obj interface{}) {
	oldPod := (*v1.Pod)(nil)

	switch obj.(type) {
	case *v1.Pod:
		oldPod = obj.(*v1.Pod)
	case cache.DeletedFinalStateUnknown:
		d := obj.(cache.DeletedFinalStateUnknown)
		p, ok := (d.Obj).(*v1.Pod)
		if ok {
			oldPod = p
		} else {
			log.Warn("DeletedFinalStateUnknown without pod object")
		}
	default:
		log.Warn("Unknown object type in pod DeleteFunc")
	}

	if oldPod == nil {
		return
	}

	// we have to call the function in this case because it will remove the containers too
	sendPodEvents(oldPod, draiosproto.CongroupEventType_REMOVED, nil, true)
	kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_DELETE)
}

func watchPods() {
	log.Debugf("In WatchPods()")

	podInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("pods")
				newPod := obj.(*v1.Pod)
				sendPodEvents(newPod, draiosproto.CongroupEventType_ADDED, nil, true)
				kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod := oldObj.(*v1.Pod)
				newPod := newObj.(*v1.Pod)
				if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
					sameEntity, sameLinks := podEquals(oldPod, newPod)
					if !sameEntity || !sameLinks {
						sendPodEvents(newPod, draiosproto.CongroupEventType_UPDATED, oldPod, !sameLinks)
						kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_UPDATE_AND_SEND)
					}
				}
				kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: podDeleteFunc,
		},
	)
}
