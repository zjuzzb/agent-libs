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
	"strings"
	"k8s.io/apimachinery/pkg/labels"
)

// pods get their own special version because they send events for containers too
func sendPodEvents(evtc chan<- draiosproto.CongroupUpdateEvent, pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod)  {
	updates := newPodEvents(pod, eventType, oldPod)
	for _, evt := range updates {
		evtc <- *evt
	}
}

func newContainerEvent(c *v1.ContainerStatus, eventType draiosproto.CongroupEventType, cg *[]*draiosproto.CongroupUpdateEvent, podUID string) {
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
		// unknown container type
		return
	}

	*cg = append(*cg, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup {
			Uid: &draiosproto.CongroupUid {
				Kind:proto.String("container"),
				Id:proto.String(containerId),
			},
			Tags: map[string]string{
				"container.name"    : c.Name,
				"container.image"   : c.Image,
			},
			Parents: par,
		},
	})
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, oldPod *v1.Pod) ([]*draiosproto.CongroupUpdateEvent) {
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

	// This duplicates the ContainerStatuses loop below, refactor?
	restartCount := uint32(0)
	for _, c := range pod.Status.ContainerStatuses {
		restartCount += uint32(c.RestartCount)
	}
	podMetrics := map[string]uint32{"kubernetes.pod.restart.count": restartCount}

	var parents []*draiosproto.CongroupUid
	AddNSParents(&parents, pod.GetNamespace())
	AddReplicaSetParents(&parents, pod)
	AddReplicationControllerParents(&parents, pod)
	AddStatefulSetParentsFromPod(&parents, pod)
	AddServiceParents(&parents, pod)
	AddDaemonSetParents(&parents, pod)
	AddNodeParents(&parents, pod.Spec.NodeName)
	AddJobParents(&parents, pod)
	log.Debugf("WatchPods(): parent size: %v", len(parents))

	var cg []*draiosproto.CongroupUpdateEvent
	cg = append(cg, &draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup{
			Uid: &draiosproto.CongroupUid{
				Kind:proto.String("k8s_pod"),
				Id:proto.String(string(pod.GetUID()))},
			Tags: tags,
			IpAddresses: ips,
			Parents: parents,
			Metrics: podMetrics,
		},
	})

	var oldContainers []v1.ContainerStatus
	if oldPod != nil {
		oldContainers = append(oldContainers, oldPod.Status.ContainerStatuses...)
	}
	for _, c := range pod.Status.ContainerStatuses {
		found := false
		i := 0
		if oldPod != nil {
			for _, oldC := range oldPod.Status.ContainerStatuses {
				if oldC.ContainerID == c.ContainerID {
					oldContainers[i] = oldContainers[len(oldContainers)-1]
					oldContainers = oldContainers[:len(oldContainers)-1]
					found = true
					break
				}
				i++
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
		newContainerEvent(&c, cEvtType, &cg, string(pod.GetUID()))
	}
	for _, removedC := range oldContainers {
		newContainerEvent(&removedC, draiosproto.CongroupEventType_REMOVED, &cg, string(pod.GetUID()))
	}

	return cg
}

var podInf cache.SharedInformer

func AddPodChildren(children *[]*draiosproto.CongroupUid, selector labels.Selector, namespace string) {
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

func WatchPods(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchPods()")

	client := kubeClient.CoreV1().RESTClient()
	fSelector, _ := fields.ParseSelector("status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded") // they don't support or operator...
	lw := cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, fSelector)
	resyncPeriod := time.Duration(10) * time.Second
	podInf = cache.NewSharedInformer(lw, &v1.Pod{}, resyncPeriod)

	podInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping pod: %v", obj.(*v1.Pod))
				newPod := obj.(*v1.Pod)
				sendPodEvents(evtc, newPod, draiosproto.CongroupEventType_ADDED, nil)
				//evtc <- podEvent(obj.(*v1.Pod), draiosproto.CongroupEventType_ADDED)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod := oldObj.(*v1.Pod)
				newPod := newObj.(*v1.Pod)
				if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping pod oldPod %v", oldPod)
					//log.Debugf("UpdateFunc dumping pod newPod %v", newPod)
					sendPodEvents(evtc, newPod, draiosproto.CongroupEventType_UPDATED, oldPod)
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping pod: %v", obj.(*v1.Pod))
				oldPod := obj.(*v1.Pod)
				sendPodEvents(evtc, oldPod, draiosproto.CongroupEventType_REMOVED, nil)
				//evtc <- podEvent(obj.(*v1.Pod), draiosproto.CongroupEventType_REMOVED)
			},
		},
	)

	go podInf.Run(ctx.Done())
}
