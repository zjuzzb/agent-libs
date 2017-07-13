package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"sdc_internal"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// make this a library function?
func podEvent(pod *v1.Pod, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newPodCongroup(pod),
	}
}

func newPodCongroup(pod *v1.Pod) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := pod.GetAnnotations()
	for k, v := range pod.GetLabels() {
		tags[k] = v
	}

	var ips []string
	if pod.Status.HostIP != "" {
		ips = append(ips, pod.Status.HostIP)
	}
	if pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}

	return &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_pod"),
			Id:proto.String(string(pod.GetUID()))},
		Tags: tags,
		IpAddresses: ips,
		Parents: nil,
	}
}

func WatchPods(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, nil)
	resyncPeriod := time.Duration(10) * time.Second;
	inf := cache.NewSharedInformer(lw, &v1.Pod{}, resyncPeriod)

	inf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.Debugf("AddFunc dumping pod: %v", obj.(*v1.Pod))
				evtc <- podEvent(obj.(*v1.Pod),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPod := oldObj.(*v1.Pod)
				newPod := newObj.(*v1.Pod)
				if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
					log.Debugf("UpdateFunc dumping pod oldPod %v", oldPod)
					log.Debugf("UpdateFunc dumping pod newPod %v", newPod)
					evtc <- podEvent(newPod,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				log.Debugf("DeleteFunc dumping pod: %v", obj.(*v1.Pod))
				evtc <- podEvent(obj.(*v1.Pod),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go inf.Run(ctx.Done())
}

func HelloPods(ctx context.Context, cmd *sdc_internal.KubeHelloCommand) (*sdc_internal.KubeHelloResult, error) {
	res := &sdc_internal.KubeHelloResult{}
	res.Successful = proto.Bool(true)
	return res, nil
}
