package kubecollect

import (
	"context"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/draiosproto"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	tw "k8s.io/client-go/tools/watch"
	"sort"
	"strings"
	"sync"
)

type podMetaData struct {
	namespace string
	uid       string
	status    string
}

var clusterPods map[string]podMetaData
var statusMap map[string]map[string]uint64
var alreadySentCongroupUid map[string]bool

var podStatusAllowed []string

func initStructures() {
	clusterPods = make(map[string]podMetaData)
	statusMap = make(map[string]map[string]uint64)
	alreadySentCongroupUid = make(map[string]bool)
}

func reset() {
	clusterPods = nil
	statusMap = nil
	alreadySentCongroupUid = nil
}

func increaseStatusMap(namespace string, status string) {
	if statusMap[namespace] == nil {
		statusMap[namespace] = make(map[string]uint64)
	}

	if statusMap[namespace][status] < 0 {
		panic("Key [" + namespace + "," + status + "]:" + string(statusMap[namespace][status]))
	}
	statusMap[namespace][status]++
}

func decreaseStatusMap(namespace string, status string){
	if statusMap[namespace] == nil {
		panic("Invalid decrease operation on Namespace:" + namespace)
	}

	statusMap[namespace][status]--
	if statusMap[namespace][status] < 0 {
		panic("Key [" + namespace + "," + status + "]:" + string(statusMap[namespace][status]))
	}
}

func toLowerArray(ar []string) []string {
	var ret []string

	for _, elem := range ar {
		ret = append(ret, strings.ToLower(elem))
	}

	return ret
}

func startPodStatusWatcher(ctx context.Context, opts *sdc_internal.OrchestratorEventsStreamCommand, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debug("startPodStatusWatcher starts")

	reset()
	initStructures()

	podStatusAllowed = opts.GetPodStatusAllowlist()

	// Always consider the Running aggr State

	runningAlreadyPresent := false
	for _, status := range podStatusAllowed {
		if status == "Running" {
			runningAlreadyPresent = true
			break
		}
	}
	if !runningAlreadyPresent {
		podStatusAllowed = append(podStatusAllowed, "Running")
	}


	podStatusAllowed = toLowerArray(podStatusAllowed)

	// sort the array to do a binary search later
	sort.Strings(podStatusAllowed)

	lw := cache.NewListWatchFromClient(kubeClient.CoreV1().RESTClient(), "Pods", v1meta.NamespaceAll, fields.Everything())

	wg.Add(1)

	go func() {

		defer func() {
			log.Debug("startPodStatusWatcher ended")
			wg.Done()
		}()

		// ListWatchUntil is a wrapper around RetryWatcher
		_, err := tw.ListWatchUntil(ctx, lw,
			func(event watch.Event) (bool, error) {
				if event.Type == watch.Error {
					log.Debug("startPodStatusWatcher got event type Error")
					// Keep on anyway
				} else if handleEvent(event) {
					sendPodStatusMap(evtc)
				}
				// Don't stop the watcher yet
				return false, nil
			})

		if err != nil {
			log.Debugf("startPodStatusWatcher Could not start a RetryWatcher: %s", err.Error())
		}
	} ()
}

func handleEvent(event watch.Event) bool {
	ret := false

	pod, ok := event.Object.(*v1.Pod)
	if !ok {
		return ret
	}
	podUid := string(pod.UID)
	podStatus := getStatusFromPod(pod)
	podNamespace := pod.Namespace


	if (event.Type == watch.Added) {
		//Ensure uid is not present in clusterPods
		if  _, ok := clusterPods[podUid]; ok {
			log.Debugf("request to add pod with uid %s which is already present", string(podUid))
		} else {
			// 1) Insert in clusterPods
			// 2) Update statusMap

			clusterPods[podUid] = podMetaData{podNamespace, podUid, podStatus}
			increaseStatusMap(podNamespace, podStatus)
			ret = true
		}
	} else if(event.Type == watch.Deleted) {
		// Ensure uid exists in clusterPods
		if pod, ok := clusterPods[podUid]; !ok {
			log.Debugf("request to delete pod with uid %s which not present", podUid)
		} else {
			delete(clusterPods, podUid)
			// decrease the status belonging to the deleted pod
			decreaseStatusMap(pod.namespace, pod.status)
			ret = true
		}
	} else if(event.Type == watch.Modified) {
		if pod, ok := clusterPods[podUid]; !ok {
			log.Debugf("request to modify pod with uid %s which not present", podUid)
		} else {
			// insert in clusterPods and in statusMap the new status
			oldStatus := pod.status
			newStatus := podStatus

			if(oldStatus != newStatus) {
				decreaseStatusMap(pod.namespace, oldStatus)
				increaseStatusMap(pod.namespace, newStatus)
				clusterPods[podUid] = podMetaData{pod.namespace, pod.uid, newStatus}
				ret = true
			}
		}
	} else {
		log.Debugf("got an unhandled event type %s", event.Type)
	}

	return ret
}

func getStatusFromPod(pod *v1.Pod) string {
	// Copied from printer.go (where kubectl output come from)

	reason := string(pod.Status.Phase)
	if pod.Status.Reason != "" {
		reason = pod.Status.Reason
	}

	initializing := false
	for i := range pod.Status.InitContainerStatuses {
		container := pod.Status.InitContainerStatuses[i]
		// restarts += int(container.RestartCount)
		switch {
		case container.State.Terminated != nil && container.State.Terminated.ExitCode == 0:
			continue
		case container.State.Terminated != nil:
			// initialization is failed
			if len(container.State.Terminated.Reason) == 0 {
				if container.State.Terminated.Signal != 0 {
					reason = fmt.Sprintf("Init:Signaled")
				} else {
					reason = fmt.Sprintf("Init:ErrorExit")
				}
			} else {
				reason = "Init:Terminated"
			}
			initializing = true
		case container.State.Waiting != nil && len(container.State.Waiting.Reason) > 0 && container.State.Waiting.Reason != "PodInitializing":
			reason = "Init:Waiting"
			initializing = true
		default:
			reason = fmt.Sprintf("Initializing")
			initializing = true
		}
		break
	}
	if !initializing {
		hasRunning := false
		for i := len(pod.Status.ContainerStatuses) - 1; i >= 0; i-- {
			container := pod.Status.ContainerStatuses[i]

			if container.State.Waiting != nil && container.State.Waiting.Reason != "" {
				reason = container.State.Waiting.Reason
			} else if container.State.Terminated != nil && container.State.Terminated.Reason != "" {
				reason = container.State.Terminated.Reason
			} else if container.State.Terminated != nil && container.State.Terminated.Reason == "" {
				if container.State.Terminated.Signal != 0 {
					reason = fmt.Sprintf("Signaled")
				} else {
					reason = fmt.Sprintf("ErrorExit")
				}
			} else if container.Ready && container.State.Running != nil {
				hasRunning = true
			}
		}

		// change pod status back to "Running" if there is at least one container still reporting as "Running" status
		if reason == "Completed" && hasRunning {
			reason = "Running"
		}
	}

	if pod.DeletionTimestamp != nil && pod.Status.Reason == "NodeLost" {
		reason = "Unknown"
	} else if pod.DeletionTimestamp != nil {
		reason = "Terminating"
	}

	// Verify that aggr status is in the allow list or it is an error condition
	toLowerReason := strings.ToLower(reason)
	if pos := sort.SearchStrings(podStatusAllowed, toLowerReason); pos == len(podStatusAllowed) || podStatusAllowed[pos] != toLowerReason {
		// It is not. So set ret to generic Error
		log.Debugf("Pod aggregated status %s is not in the allow list {%v}. Send Others instead", toLowerReason, podStatusAllowed)
		toLowerReason = "othererrors"
	}

	return toLowerReason
}

func createCongroupUpdateEvent(ns string, status string, count int64) draiosproto.CongroupUpdateEvent {
	key := ns + "|" + status

	cg := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("podstatuscounter"),
			Id:   proto.String(key),
		},
		Namespace:proto.String(ns),
	}
	cg.Tags = make(map[string]string)
	cg.Tags["kubernetes.podstatuscounter.label.status"] = status

	AppendMetricInt64(&cg.Metrics, "kubernetes.podstatuscounter.count", int64(count))
	var eventType draiosproto.CongroupEventType

	if _, exists := alreadySentCongroupUid[key]; exists {
		eventType = draiosproto.CongroupEventType_UPDATED
	} else {
		eventType = draiosproto.CongroupEventType_ADDED
		alreadySentCongroupUid[key] = true
	}

	event := draiosproto.CongroupUpdateEvent{
		Type:   &eventType,
		Object: cg,
	}

	return event
}

func sendPodStatusMap(evtc chan<- draiosproto.CongroupUpdateEvent) {
	for ns, val := range statusMap {
		for aggregateStatus, count := range val {
			evtc <- createCongroupUpdateEvent(ns, aggregateStatus, int64(count))
		}
	}
}

