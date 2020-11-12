package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

var podInf cache.SharedInformer
var podEvtcHandle chan<- draiosproto.CongroupUpdateEvent

// pods get their own special version because they send events for containers too
func sendPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool)  {
	updates := newPodEvents(pod, eventType, oldPod, setLinks)

	kubecollect_common.SendClusterCidrEvent(pod, eventType, podEvtcHandle)

	for _, evt := range updates {
		podEvtcHandle <- *evt
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

	for _, c := range containers {
		state := kubecollect_common.GetContainerState(c.State)
		if (state < kubecollect_common.Running) {
			continue
		} else if (state == kubecollect_common.Running) {
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

		var oldState kubecollect_common.CState = kubecollect_common.Waiting
		for _, oldC := range oldContainers {
			if oldC.Name == c.Name {
				oldState = kubecollect_common.GetContainerState(oldC.State)
				break;
			}
		}

		newEvent := false
		var newType draiosproto.CongroupEventType
		switch state {
		case kubecollect_common.Running:
			if oldState < kubecollect_common.Running &&
				(evtType == draiosproto.CongroupEventType_ADDED ||
				evtType == draiosproto.CongroupEventType_UPDATED) {
				newEvent, newType = true, draiosproto.CongroupEventType_ADDED
			}
		case kubecollect_common.Terminated:
			// Always send for REMOVED, and send on UPDATED if we
			// notice a state transition. This results in sending
			// two delete events if we catch the UPDATED transition,
			// but the infra state code can handle double deletes
			if evtType == draiosproto.CongroupEventType_REMOVED ||
				(evtType == draiosproto.CongroupEventType_UPDATED &&
				oldState == kubecollect_common.Running) {
				newEvent, newType = true, draiosproto.CongroupEventType_REMOVED
			}
		default:
			log.Errorf("Unexpected state=%v while processing containers", state)
		}

		if newEvent {
			kubecollect_common.NewContainerEvent(contEvents, &c, podUID, newType)
		}
	}
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
		lRestarts, lWaiting := kubecollect_common.StatusCounts(lhs.Status.ContainerStatuses)
		rRestarts, rWaiting := kubecollect_common.StatusCounts(rhs.Status.ContainerStatuses)
		if (lRestarts != rRestarts) || (lWaiting != rWaiting) {
			in = false
		}
	}

	if in {
		lInitRestarts, lInitWaiting := kubecollect_common.StatusCounts(lhs.Status.InitContainerStatuses)
		rInitRestarts, rInitWaiting := kubecollect_common.StatusCounts(rhs.Status.InitContainerStatuses)
		if (lInitRestarts != rInitRestarts) || (lInitWaiting != rInitWaiting) {
			in = false
		}
	}

	if in {
		lVal, lFound := kubecollect_common.GetPodConditionMetric(lhs.Status.Conditions, v1.PodReady)
		rVal, rFound := kubecollect_common.GetPodConditionMetric(rhs.Status.Conditions, v1.PodReady)
		if lFound != rFound || lVal != rVal {
			in = false
		}
	}

	if in {
		lRequestsCpu, lLimitsCpu, lRequestsMem, lLimitsMem := kubecollect_common.GetPodContainerResources(lhs)
		rRequestsCpu, rLimitsCpu, rRequestsMem, rLimitsMem := kubecollect_common.GetPodContainerResources(rhs)
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

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod, setLinks bool) ([]*draiosproto.CongroupUpdateEvent) {
	tags := kubecollect_common.GetTags(pod.ObjectMeta, "kubernetes.pod.")
	// This gets specially added as a tag since we don't have a
	// better way to report values that can be one of many strings
	tags["kubernetes.pod.label.status.phase"] = string(pod.Status.Phase)
	tags["kubernetes.pod.label.status.reason"] = string(pod.Status.Reason)

	for _, c := range pod.Status.Conditions {
		if c.Type == v1.PodScheduled && c.Status == v1.ConditionFalse {
			tags["kubernetes.pod.label.status.unschedulable"] = string("true")
			break
		}
	}

	annotations := kubecollect_common.GetAnnotations(pod.ObjectMeta, "kubernetes.pod.")
	probes := kubecollect_common.GetProbes(pod)
	inttags := kubecollect_common.MergeInternalTags(annotations, probes)

	var ips []string
	if pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}

	var metrics []*draiosproto.AppMetric
	kubecollect_common.AddPodMetrics(&metrics, pod)

	var parents []*draiosproto.CongroupUid
	if setLinks {
		AddNodeParents(&parents, pod.Spec.NodeName)

		kubecollect_common.AddParentsToPodViaOwnerRef(&parents, pod);
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

func startPodsSInformer(ctx context.Context, opts *sdc_internal.OrchestratorEventsStreamCommand, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	var selector string
	if opts.GetTerminatedPodsEnabled()  {
		selector = ""
	} else {
		selector = "status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded"
	}
	fSelector, _ := fields.ParseSelector(selector) // they don't support or operator...
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
