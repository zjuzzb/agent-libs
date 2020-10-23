package kubecollect_tc

import (
	"cointerface/kubecollect_common"
	"context"
	"errors"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"regexp"
	"strings"
	"sync"
)

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
func sendPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, setLinks bool)  {
	updates := newPodEvents(pod, eventType, setLinks)

	kubecollect_common.SendClusterCidrEvent(pod, eventType, podEvtcHandle)

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
	podUID types.UID,
	eventType draiosproto.CongroupEventType,
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
		if state < running {
			continue
		} else if state == running {
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

		var newType draiosproto.CongroupEventType
		sendEvent := false
		if state == running {
			sendEvent, newType = true, eventType
		} else if state == terminated {
			sendEvent, newType = true, draiosproto.CongroupEventType_REMOVED
		}

		if sendEvent == true {
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
	matches := containerIDRegex.FindStringSubmatch(containerID)
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

func statusCounts(containers []v1.ContainerStatus) (restarts, waiting int32) {
	for _, c := range containers {
		restarts += c.RestartCount
		if c.State.Waiting != nil {
			waiting += 1
		}
	}
	return
}

func AddParentsToPodViaOwnerRef(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	for _, ref := range pod.GetOwnerReferences() {
		congroupKind := kubecollect_common.OwnerRefKindToCongroupKind[ref.Kind]
		if congroupKind != "" {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind: proto.String(congroupKind),
				Id: proto.String(string(ref.UID))})
		} else {
			log.Debugf("Unexpected k8s kind %v", ref.Kind)
		}
	}
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, setLinks bool) []*draiosproto.CongroupUpdateEvent {
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

	var ctrPorts []*draiosproto.CongroupNetPort
	for _, ctr := range pod.Spec.Containers {
		for _, port := range ctr.Ports {
			containerPort  := uint32(port.ContainerPort)
			hostPort := uint32(port.HostPort)
			ctrPorts = append(ctrPorts, &draiosproto.CongroupNetPort{
				Port:                 &containerPort,
				TargetPort:           &hostPort,
				Protocol:             (*string)(&port.Protocol),
				NodePort:             nil,
				PublishedPort:        nil,
				Name:                 &port.Name,
			})
		}
	}

	var metrics []*draiosproto.AppMetric
	addPodMetrics(&metrics, pod)

	var parents []*draiosproto.CongroupUid
	if setLinks {
		AddParentsToPodViaOwnerRef(&parents, pod)
	}

	var children []*draiosproto.CongroupUid
	var containerEvents []*draiosproto.CongroupUpdateEvent
	if setLinks {
		processContainers(&containerEvents, &children,
			pod.Status.ContainerStatuses,
			pod.GetUID(),
			eventType)
		processContainers(&containerEvents, &children,
			pod.Status.InitContainerStatuses,
			pod.GetUID(),
			eventType)
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
			IpAddresses:  ips,
			Metrics:      metrics,
			Parents:      parents,
			Children:     children,
			Ports:        ctrPorts,
			Namespace:    proto.String(pod.GetNamespace()),
			Node:         proto.String(pod.Spec.NodeName),
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

func startPodWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	podEvtcHandle = evtc
	fselector, _ := fields.ParseSelector("status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded")
	kubecollect_common.StartWatcher(ctx, kubeClient.CoreV1().RESTClient(), "pods", wg, evtc, fselector, handlePodEvent)
}

func handlePodEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	pod, ok := event.Object.(*v1.Pod)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("pods")
		sendPodEvents(pod, draiosproto.CongroupEventType_ADDED,  true)
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_UPDATE_AND_SEND)
		sendPodEvents(pod, draiosproto.CongroupEventType_UPDATED,  true)
	} else if event.Type == watch.Deleted {
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_DELETE)
		sendPodEvents(pod, draiosproto.CongroupEventType_REMOVED,  true)
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_DELETE)
	}
}
