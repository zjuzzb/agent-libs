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
)

// pods get their own special version because they send events for containers too
func sendPodEvents(evtc chan<- draiosproto.CongroupUpdateEvent, pod *v1.Pod, eventType draiosproto.CongroupEventType)  {
	updates := newPodEvents(pod, eventType)
	for _, evt := range updates {
		evtc <- *evt
	}
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType) ([]*draiosproto.CongroupUpdateEvent) {
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

	var parents []*draiosproto.CongroupUid
	AddNSParents(&parents, pod.GetNamespace())
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
		},
	})

	// We assume the container<->pod relationship
	// is static for the lifetime of the pod
	if eventType == draiosproto.CongroupEventType_ADDED || eventType == draiosproto.CongroupEventType_REMOVED {
		par := []*draiosproto.CongroupUid{&draiosproto.CongroupUid{
			Kind:proto.String("k8s_pod"),
			Id:proto.String(string(pod.GetUID()))}}
		for _, c := range pod.Status.ContainerStatuses {
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
				continue
			}
			cg = append(cg, &draiosproto.CongroupUpdateEvent {
				Type: eventType.Enum(),
				Object: &draiosproto.ContainerGroup {
					Uid: &draiosproto.CongroupUid {
						Kind:proto.String("container"),
						Id:proto.String(containerId),
					},
					Parents: par,
				},
			})
		}
	}

	return cg
}

func WatchPods(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchPods()")

	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	inf := cache.NewSharedInformer(lw, &v1.Pod{}, resyncPeriod)

	inf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping pod: %v", obj.(*v1.Pod))
				sendPodEvents(evtc, obj.(*v1.Pod), draiosproto.CongroupEventType_ADDED)
				//evtc <- podEvent(obj.(*v1.Pod), draiosproto.CongroupEventType_ADDED)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod := oldObj.(*v1.Pod)
				newPod := newObj.(*v1.Pod)
				if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping pod oldPod %v", oldPod)
					//log.Debugf("UpdateFunc dumping pod newPod %v", newPod)
					sendPodEvents(evtc, newPod, draiosproto.CongroupEventType_UPDATED)
					//evtc <- podEvent(newPod, draiosproto.CongroupEventType_UPDATED)
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping pod: %v", obj.(*v1.Pod))
				sendPodEvents(evtc, obj.(*v1.Pod), draiosproto.CongroupEventType_REMOVED)
				//evtc <- podEvent(obj.(*v1.Pod), draiosproto.CongroupEventType_REMOVED)
			},
		},
	)

	go inf.Run(ctx.Done())
}
