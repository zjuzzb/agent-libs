package kubecollect_tc

import (
	"cointerface/kubecollect_common"
	"context"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

var podEvtcHandle chan<- draiosproto.CongroupUpdateEvent

// pods get their own special version because they send events for containers too
func sendPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, setLinks bool) {
	updates := newPodEvents(pod, eventType, setLinks)

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
			containerID, err := kubecollect_common.ParseContainerID(c.ContainerID)
			if err != nil {
				log.Debugf("Unable to parse ContainerID %v: %v", containerID, err)
				continue
			}

			// All running containers need to be added to the child list
			// even if they don't have an ADDED or REMOVED event this time
			*podChildren = append(*podChildren, &draiosproto.CongroupUid{
				Kind: proto.String("container"),
				Id:   proto.String(containerID)},
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
			kubecollect_common.NewContainerEvent(contEvents, &c, podUID, newType)
		}
	}
}

func newPodEvents(pod *v1.Pod, eventType draiosproto.CongroupEventType, setLinks bool) []*draiosproto.CongroupUpdateEvent {
	tags := kubecollect_common.GetTags(pod, "kubernetes.pod.")
	// This gets specially added as a tag since we don't have a
	// better way to report values that can be one of many strings
	tags["kubernetes.pod.label.status.phase"] = string(pod.Status.Phase)

	annotations := kubecollect_common.GetAnnotations(pod.ObjectMeta, "kubernetes.pod.")
	probes := kubecollect_common.GetProbes(pod)
	inttags := kubecollect_common.MergeInternalTags(annotations, probes)
	inttags = kubecollect_common.MergeInternalTags(inttags, map[string]string{"status.reason": string(pod.Status.Reason)})

	for _, c := range pod.Status.Conditions {
		if c.Type == v1.PodScheduled && c.Status == v1.ConditionFalse {
			inttags["status.unschedulable"] = string("true")
			break
		}
	}

	var ips []string
	if pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}

	var ctrPorts []*draiosproto.CongroupNetPort
	for _, ctr := range pod.Spec.Containers {
		for _, port := range ctr.Ports {
			containerPort := uint32(port.ContainerPort)
			hostPort := uint32(port.HostPort)
			ctrPorts = append(ctrPorts, &draiosproto.CongroupNetPort{
				Port:          &containerPort,
				TargetPort:    &hostPort,
				Protocol:      (*string)(&port.Protocol),
				NodePort:      nil,
				PublishedPort: nil,
				Name:          &port.Name,
			})
		}
	}

	var metrics []*draiosproto.AppMetric
	kubecollect_common.AddPodMetrics(&metrics, pod)

	var parents []*draiosproto.CongroupUid
	if setLinks {
		kubecollect_common.AddParentsToPodViaOwnerRef(&parents, pod)
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

	optPod := kubecollect_common.GetVolumes(pod)
	kubecollect_common.AddContainerStatusesToPod(optPod, pod)

	var cg []*draiosproto.CongroupUpdateEvent
	cg = append(cg, &draiosproto.CongroupUpdateEvent{
		Type: eventType.Enum(),
		Object: &draiosproto.ContainerGroup{
			Uid: &draiosproto.CongroupUid{
				Kind: proto.String("k8s_pod"),
				Id:   proto.String(string(pod.GetUID()))},
			Tags:         tags,
			InternalTags: inttags,
			IpAddresses:  ips,
			Metrics:      metrics,
			Parents:      parents,
			Children:     children,
			Ports:        ctrPorts,
			Namespace:    proto.String(pod.GetNamespace()),
			Node:         proto.String(pod.Spec.NodeName),
			K8SObject:    &draiosproto.K8SType{TypeList: &draiosproto.K8SType_Pod{Pod: optPod}},
		},
	})
	cg = append(cg, containerEvents...)

	return cg
}

func startPodWatcher(ctx context.Context, opts *sdc_internal.OrchestratorEventsStreamCommand, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	var getTerm bool = false
	if opts.GetTerminatedPodsEnabled() {
		getTerm = true
	}

	wg.Add(1)
	go func() {
		podEvtcHandle = evtc
		podWatcherLoop(ctx, getTerm, kubeClient)
		wg.Done()
	}()
}

func podWatcherLoop(ctx context.Context, getTerm bool, kubeClient kubeclient.Interface) {
	deleg := kubecollect_common.IsDelegated()
	delegChan := kubecollect_common.GetDelegateChan()

	for {
		log.Debugf("Start new Pod Watcher, delegated:%v", deleg)

		watcherWg := &sync.WaitGroup{}
		watcherCtx, cancelWatcher := context.WithCancel(ctx)
		startPodWatcherReally(watcherCtx, getTerm, deleg, kubeClient, watcherWg)

		var restart bool = false
		for !restart {
			select {
			case <-ctx.Done():
				log.Debug("PodWatcherLoop: context cancelled, waiting for watcher wg")
				watcherWg.Wait()
				log.Debug("PodWatcherLoop: watcher done, closing")
				return
			case d, ok := <-delegChan:
				if !ok {
					log.Warn("PodWatcherLoop: delegation channel closed")
					return
				}
				log.Debugf("PodWatcherLoop: delegation channel sent deleg=%v", d)
				if d != deleg {
					log.Debug("PodWatcherLoop: cancelling watcher and waiting")
					deleg = d
					cancelWatcher()
					watcherWg.Wait()
					log.Debug("PodWatcherLoop: restarting watcher")
					restart = true
					break
				}
			}
		}
	}
}

func startPodWatcherReally(ctx context.Context, getTerm bool, deleg bool, kubeClient kubeclient.Interface, wg *sync.WaitGroup) {

	var selector string = ""
	if !getTerm {
		selector = "status.phase!=Failed,status.phase!=Unknown,status.phase!=Succeeded"
	}

	node := kubecollect_common.GetNode()
	if node != "" && !deleg {
		log.Info("Only getting pods for node " + node)
		selector = selector + ",spec.nodeName=" + node
	} else {
		log.Info("Getting pods for all nodes ")
	}

	fselector, _ := fields.ParseSelector(selector)
	kubecollect_common.StartWatcher(ctx, kubeClient.CoreV1().RESTClient(), "pods", wg, podEvtcHandle, fselector, handlePodEvent)
}

func handlePodEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	pod, ok := event.Object.(*v1.Pod)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("pods")
		sendPodEvents(pod, draiosproto.CongroupEventType_ADDED, true)
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_UPDATE_AND_SEND)
		sendPodEvents(pod, draiosproto.CongroupEventType_UPDATED, true)
	} else if event.Type == watch.Deleted {
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_DELETE)
		sendPodEvents(pod, draiosproto.CongroupEventType_REMOVED, true)
		kubecollect_common.AddEvent("Pod", kubecollect_common.EVENT_DELETE)
	}
}
