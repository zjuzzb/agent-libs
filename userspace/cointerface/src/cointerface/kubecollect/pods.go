package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"errors"
	"strings"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"regexp"
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
var containerIDRegex = regexp.MustCompile("^([a-z0-9-]+)://([0-9a-fA-F]{12})[0-9a-fA-F]*$")

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
	containerID, err := parseContainerID(cstat.ContainerID)
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
		addEvent("Container", EVENT_ADD)
	} else if eventType == draiosproto.CongroupEventType_REMOVED {
		addEvent("Container", EVENT_DELETE)
	} else {
		addEvent("Container", EVENT_UPDATE)
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
			containerID, err := parseContainerID(c.ContainerID)
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

func parseContainerID(containerID string) (string, error) {
	var err error = nil

	// Kubernetes reports containers in this format:
	// docker://<fulldockercontainerid>
	// rkt://<rktpodid>:<rktappname>
	// We instead use
	// <dockershortcontainerid>
	// <rktpodid>:<rktappname>
	// so here we are doing this conversion
	matches := containerIDRegex.FindStringSubmatch(containerID);
	if matches != nil {
		// matches[0] is the whole ID,
		// matches[1] is the scheme (e.g. "docker")
		// matches[2] is the first 12 hex digits of the ID
		return matches[2], nil
	} else if strings.HasPrefix(containerID, "rkt://") {
		// XXX Will the parsed rkt id always
		// be 12 char like for docker?
		if len(containerID) >= 7 {
			containerID = containerID[6:]
		} else {
			err = errors.New("ID too short for rkt format")
		}
	} else {
		err = errors.New("Unknown containerID format")
	}

	return containerID, err
}

func podEquals(lhs *v1.Pod, rhs *v1.Pod) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	in = in && EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

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

	out = out && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta)

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

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool) ([]*draiosproto.CongroupUpdateEvent) {
	tags := GetTags(pod.ObjectMeta, "kubernetes.pod.")
	// This gets specially added as a tag since we don't have a
	// better way to report values that can be one of many strings
	tags["kubernetes.pod.label.status.phase"] = string(pod.Status.Phase)
	inttags := GetAnnotations(pod.ObjectMeta, "kubernetes.pod.")

	var ips []string
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
		AddResourceQuotaParentsFromPod(&parents, pod)
		AddServiceParents(&parents, pod)
		AddDaemonSetParents(&parents, pod)
		AddNodeParents(&parents, pod.Spec.NodeName)
		AddJobParents(&parents, pod)
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

	AppendMetricInt32(metrics, prefix+"container.status.restarts", restartCount)
	appendRateMetric(metrics, prefix+"container.status.restart_rate", float64(restartCount))
	AppendMetricInt32(metrics, prefix+"container.status.waiting", waitingCount)
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
		AppendMetric(metrics, name, val)
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
		initRequestsMem := resourceVal(c.Resources.Requests, v1.ResourceCPU)
		if initRequestsMem > requestsMem {
			requestsMem = initRequestsMem
		}
		initLimitsMem := resourceVal(c.Resources.Limits, v1.ResourceCPU)
		if initLimitsMem > limitsMem {
			limitsMem = initLimitsMem
		}
	}

	return
}

func appendMetricContainerResources(metrics *[]*draiosproto.AppMetric, prefix string, pod *v1.Pod) {
	requestsCpu, limitsCpu, requestsMem, limitsMem := getPodContainerResources(pod)

	AppendMetric(metrics, prefix+"resourceRequests.cpuCores", requestsCpu)
	AppendMetric(metrics, prefix+"resourceLimits.cpuCores", limitsCpu)
	AppendMetric(metrics, prefix+"resourceRequests.memoryBytes", requestsMem)
	AppendMetric(metrics, prefix+"resourceLimits.memoryBytes", limitsMem)
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
	if !resourceReady("pods") {
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
	if !resourceReady("pods") {
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
	if !resourceReady("pods") {
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

func AddPodChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("pods") {
		return
	}

	for _, obj := range podInf.GetStore().List() {
		pod := obj.(*v1.Pod)
		if pod.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(pod.GetUID()))})
		}
	}
}

func AddPodChildrenFromOwnerRef(children *[]*draiosproto.CongroupUid, parent v1meta.ObjectMeta) {
	if !resourceReady("pods") {
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
	podInf = cache.NewSharedInformer(lw, &v1.Pod{}, RsyncInterval)

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
	addEvent("Pod", EVENT_DELETE)
}

func watchPods() {
	log.Debugf("In WatchPods()")

	podInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("pods")
				newPod := obj.(*v1.Pod)
				sendPodEvents(newPod, draiosproto.CongroupEventType_ADDED, nil, true)
				addEvent("Pod", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod := oldObj.(*v1.Pod)
				newPod := newObj.(*v1.Pod)
				if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
					sameEntity, sameLinks := podEquals(oldPod, newPod)
					if !sameEntity || !sameLinks {
						sendPodEvents(newPod, draiosproto.CongroupEventType_UPDATED, oldPod, !sameLinks)
						addEvent("Pod", EVENT_UPDATE_AND_SEND)
					}
				}
				addEvent("Pod", EVENT_UPDATE)
			},
			DeleteFunc: podDeleteFunc,
		},
	)
}
