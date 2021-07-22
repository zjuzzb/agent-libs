package kubecollect_common

import (
	"errors"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	draiosproto "protorepo/agent-be/proto"
	"regexp"
	"strings"
)

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

type CState int
const (
	Waiting CState = iota
	Running
	Terminated
)

func ParseContainerID(containerID string) (string, error) {
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

func GetContainerState(cs v1.ContainerState) CState {
	if cs.Terminated != nil {
		return Terminated
	} else if cs.Running != nil {
		return Running
	}
	// Waiting is the default if all three are nil
	return Waiting
}

func AppendMetricContainerStatus(metrics *[]*draiosproto.AppMetric, pod *v1.Pod) {
	for _, containerStatus := range pod.Status.ContainerStatuses {
		state := GetContainerState(containerStatus.State)
		if state == Waiting {
			var newMetric draiosproto.AppMetric
			newMetric.Name = proto.String("kubernetes.pod.container.waiting")
			newMetric.Value = proto.Float64(1)
			// Note that GetContainerState returns Waiting as default
			// if the status is not Terminated or Running. So being here
			// does not guarantee that containerStatus.State.Waiting is not nil
			// We need an extra check
			if containerStatus.State.Waiting != nil {
				newMetric.Tags = append(newMetric.Tags, &draiosproto.AppTag{
					Key:   proto.String("reason"),
					Value: &containerStatus.State.Waiting.Reason,
				})
			}
			*metrics = append(*metrics, &newMetric)
		} else if state == Terminated {
			containerId, _ := ParseContainerID(containerStatus.ContainerID)
			var newMetric draiosproto.AppMetric
			newMetric.Name = proto.String("kubernetes.pod.container.terminated")
			newMetric.Value = proto.Float64(1)

			newMetric.Tags = append(newMetric.Tags, &draiosproto.AppTag{
				Key:                  proto.String("reason"),
				Value:                &containerStatus.State.Terminated.Reason,
			})

			newMetric.Tags = append(newMetric.Tags, &draiosproto.AppTag{
				Key:                  proto.String("containerId"),
				Value:                proto.String(containerId),
			})

			*metrics = append(*metrics, &newMetric)
		}
	}
}

func AddPodMetrics(metrics *[]*draiosproto.AppMetric, pod *v1.Pod) {
	prefix := "kubernetes.pod."

	// Restart count is a legacy metric attributed to pods
	// instead of the individual containers, so report it here
	restartCount, waitingCount := StatusCounts(pod.Status.ContainerStatuses)
	initRestarts, initWaiting := StatusCounts(pod.Status.InitContainerStatuses)
	restartCount += initRestarts
	waitingCount += initWaiting

	AppendMetricInt32(metrics, prefix+"container.status.restarts", restartCount)
	AppendRateMetric(metrics, prefix+"container.status.restart_rate", float64(restartCount))
	AppendMetricInt32(metrics, prefix+"container.status.waiting", waitingCount)
	appendMetricPodCondition(metrics, prefix+"status.ready", pod.Status.Conditions, v1.PodReady)
	appendMetricContainerResources(metrics, prefix, pod)
	AppendMetricContainerStatus(metrics, pod)
}

func appendMetricPodCondition(metrics *[]*draiosproto.AppMetric, name string, conditions []v1.PodCondition, ctype v1.PodConditionType) {
	val, found := GetPodConditionMetric(conditions, ctype)

	if found {
		AppendMetric(metrics, name, val)
	}
}

func GetPodConditionMetric(conditions []v1.PodCondition, ctype v1.PodConditionType) (float64, bool) {
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

func GetPodContainerResources(pod *v1.Pod) (requestsCpu float64, limitsCpu float64, requestsMem float64, limitsMem float64) {
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
	requestsCpu, limitsCpu, requestsMem, limitsMem := GetPodContainerResources(pod)

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

func StatusCounts(containers []v1.ContainerStatus) (restarts, waiting int32) {
	for _, c := range containers {
		restarts += c.RestartCount
		if c.State.Waiting != nil {
			waiting += 1
		}
	}
	return
}

// Append ADDED/REMOVED events both containerEvents
func NewContainerEvent(containerEvents *[]*draiosproto.CongroupUpdateEvent,
	cstat *v1.ContainerStatus,
	podUID types.UID,
	eventType draiosproto.CongroupEventType,
) {
	containerID, err := ParseContainerID(cstat.ContainerID)
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
		AddEvent("Container", EVENT_ADD)
	} else if eventType == draiosproto.CongroupEventType_REMOVED {
		AddEvent("Container", EVENT_DELETE)
	} else {
		AddEvent("Container", EVENT_UPDATE)
	}
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

func GetVolumes(pod *v1.Pod) *draiosproto.K8SPod {
	if pod == nil {
		return nil
	}

	ret := &draiosproto.K8SPod{Common: CreateCommon("", "")}

	for _, volume := range pod.Spec.Volumes {
		newVolume := &draiosproto.K8SPodVolume{}
		newVolume.Name = &volume.Name
		if pvc := volume.PersistentVolumeClaim; pvc != nil {
			newVolume.Volumesource = &draiosproto.K8SPodVolumeSource{
				TypeList:             &draiosproto.K8SPodVolumeSource_Persistentvolumeclaim{Persistentvolumeclaim: &draiosproto.K8SPodVolumePersistentVolumeClaim{
					Name:     &pvc.ClaimName,
					Readonly: &pvc.ReadOnly,
				}},

			}
			ret.Volumes = append(ret.Volumes, newVolume)
		}
	}

	return ret
}