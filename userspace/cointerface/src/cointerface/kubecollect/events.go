package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"

	"github.com/draios/protorepo/sdc_internal"
)

// Maximum event age in seconds, older events are discarded
const maxEventAge = 10

// Atomic doesn't have booleans, we'll use an int32 instead
var eventExportEnabled int32 = 0
var eventExportChannel chan int32 = make(chan int32, 1)

func SetEventExport(enable bool) {
	i := int32(0)
	if enable {
		i = 1
	}
	atomic.StoreInt32(&eventExportEnabled, i)
	eventExportChannel <- i
}

func isEventExportEnabled() bool {
	return atomic.LoadInt32(&eventExportEnabled) != 0
}

func newUserEvent(event *v1.Event) sdc_internal.K8SUserEvent {
	log.Debugf("newUserEvent()")

	// For timestamp, first check EventTime. If it is -ve choose `lastTimestamp`.
	// Checking validity of a times is as simple as making sure the value
	// is positive to rule out bogus values (typically if the field is
	// null, that means it is populated with a time of 0001-01-01 00:00:00 +0000 UTC).
	// During unix conversion , it becomes a negative value. So checking for +ve
	// is sufficient. We could simply add "EventTime" as a field to this
	// but that would require changes to the protobuf and also in
	// "k8s_user_event_message_handler.cpp" . This change minimizes that by simply
	// populating lastTimestamp with a valid timestamp.
	ts := int64(event.EventTime.Time.UTC().Unix())
	if ts < int64(0) {
		// eventTime is -ve ; use lastTimestamp
		ts = int64(event.LastTimestamp.Time.UTC().Unix())
		if ts < int64(0) {
			// lastTimestamp is also -ve; use current time.
			t := v1meta.Time{Time: time.Now()}
			ts = int64(t.Time.UTC().Unix())
			log.Infof("K8s User Event: Both eventTime and lastTimestamp are null. Event is : %v", event)
		}
	}

	evt := sdc_internal.K8SUserEvent{
		Obj: newK8SObject(event),
		Source: &sdc_internal.K8SSource{
			Component: proto.String(event.Source.Component),
			Host:      proto.String(event.Source.Host),
		},
		Reason:         proto.String(event.Reason),
		Message:        proto.String(event.Message),
		FirstTimestamp: proto.Int64(event.FirstTimestamp.Time.UTC().Unix()),
		LastTimestamp:  proto.Int64(ts),
		Count:          proto.Int32(event.Count),
		Type:           proto.String(event.Type),
	}
	return evt
}

func newK8SObject(event *v1.Event) *sdc_internal.K8SObject {
	obj := event.InvolvedObject

	ret := &sdc_internal.K8SObject{
		Kind:            proto.String(obj.Kind),
		Namespace:       proto.String(obj.Namespace),
		Name:            proto.String(obj.Name),
		Uid:             proto.String(string(obj.UID)),
		ApiVersion:      proto.String(obj.APIVersion),
		ResourceVersion: proto.String(obj.ResourceVersion),
		FieldPath:       proto.String(obj.FieldPath),
	}
	return ret
}

func StartUserEventsStream(userEventContext context.Context,
	wg *sync.WaitGroup,
	userEventChannel chan<- sdc_internal.K8SUserEvent,
	debugEvents bool,
	includeTypes []string) bool {

	wg.Add(1)
	go func() {
		tryUserEventsWatch(userEventContext, userEventChannel, debugEvents, includeTypes)
		log.Debug("UserEvents: done watching. Closing channel")
		close(userEventChannel)
		wg.Done()
	}()
	return true
}

func tryUserEventsWatch(userEventContext context.Context,
	userEventChannel chan<- sdc_internal.K8SUserEvent,
	debugEvents bool,
	includeTypes []string) {

	abort := false
	for !abort {
		if isEventExportEnabled() {
			abort = !StartUserEventsWatch(userEventContext, userEventChannel, debugEvents, includeTypes)
			log.Debugf("UserEvents: StartUserEventsWatch done. abort=%v", abort)
			continue
		}
		log.Debug("UserEvents: waiting for delegation")
		// wait for delegation or cancellation
		startwatch := false
		for !abort && !startwatch {
			select {
			case e, ok := <-eventExportChannel:
				if !ok {
					// Shouldn't happen
					log.Error("UserEvents: event export channel died")
					abort = true
				}
				if e != 0 {
					log.Debug("UserEvents: event export enabled, starting")
					startwatch = true
				}
			case <-userEventContext.Done():
				log.Debug("UserEvents: event context cancelled")
				abort = true
			}
		}
	}
}

func StartUserEventsWatch(userEventContext context.Context,
	userEventChannel chan<- sdc_internal.K8SUserEvent,
	debugEvents bool,
	includeTypes []string) bool {

	log.Debug("UserEvents: In StartUserEventsWatch")
	kubeClient, kubeClientChan := kubecollect_common.GetKubeClient()
	if kubeClient == nil {
		log.Debugf("UserEvents: No kube client yet")
		return false
	}
	client := kubeClient.CoreV1().Events(v1meta.NamespaceAll)
	var fieldstr string

	if debugEvents {
		log.Debugf("UserEvents: watching all")
		fieldstr = ""
	} else {
		log.Debugf("UserEvents: watching filtered")
		// k8s api doesn't do "or", so have to explicitly reject all the un-wanted kinds.
		fieldstr = "involvedObject.kind!=Cronjob,involvedObject.kind!=Ingress,involvedObject.kind!=Job,involvedObject.kind!=Namespace,involvedObject.kind!=ResourceQuota"

		sort.Strings(includeTypes)
		// Add services and hpas based on includeTypes
		if !kubecollect_common.InSortedArray("services", includeTypes) {
			fieldstr = fieldstr + ",involvedObject.kind!=Services"
		}
		if !kubecollect_common.InSortedArray("horizontalpodautoscalars", includeTypes) {
			fieldstr = fieldstr + ",involvedObject.kind!=HorizontalPodAutoscaler"
		}
	}

	listOptions := v1meta.ListOptions{FieldSelector: fieldstr}
	watcher, err := client.Watch(listOptions)
	if err != nil {
		log.Errorf("UserEvents: Failed to start watcher: %s", err)
		return false
	}

	return watchUserEvents(watcher, kubeClientChan, userEventContext, userEventChannel)
}

func watchUserEvents(watcher watch.Interface,
	kubeClientChan chan struct{},
	userEventContext context.Context,
	userEventChannel chan<- sdc_internal.K8SUserEvent) bool {

	log.Debugf("In WatchUserEvents()")

	ch := watcher.ResultChan()

	for {
		select {
		case <-kubeClientChan:
			log.Debug("UserEvents: kubeClient closed, stopping stream")
			watcher.Stop()
			return false
		case e, ok := <-eventExportChannel:
			if !ok {
				// Shouldn't happen
				log.Error("UserEvents: event export channel died")
				watcher.Stop()
				return false
			}
			if e == 0 {
				log.Debug("UserEvents: event export disabled")
				watcher.Stop()
				return true
			}
		case <-userEventContext.Done():
			log.Debug("UserEvents: event context cancelled (in watch)")
			watcher.Stop()
			return false
		case event, ok := <-ch:
			if !ok {
				log.Warn("UserEvents: watcher channel failed. Shutting it down and retrying.")
				return false
			}
			switch event.Type {
			case watch.Modified:
				log.Debugf("Event: Creating event from modification: %+v", event.Object)
				fallthrough
			case watch.Added:
				evt, ok := event.Object.(*v1.Event)
				if !ok {
					log.Errorf("UserEvents: unexpected type: %v", event.Object)
				}
				// Filter out old events. There doesn't seem to be a way to
				// filter by timestamp in the fieldselector
				now := time.Now()
				var evttime time.Time
				if evt.EventTime.IsZero() {
					evttime = evt.LastTimestamp.Time
				} else {
					evttime = evt.EventTime.Time
				}
				if now.Sub(evttime).Seconds() > maxEventAge {
					log.Debugf("Event: discarding old event: %+v", evt)
				} else {
					log.Debugf("Event: Event add: %+v", evt)
					userEventChannel <- newUserEvent(evt)
				}
			case watch.Deleted:
				log.Debugf("Event: Ignoring event deletion: %+v", event.Object)
			case watch.Error:
				log.Infof("Event: got watch error, object: %+v", event.Object)
			}
		}
	}
}
