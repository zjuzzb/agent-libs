package kubecollect

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/core/v1"

	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"

	"github.com/draios/protorepo/sdc_internal"
)

// Atomic doesn't have booleans, we'll use an int32 instead
var eventExportEnabled int32 = 0

func SetEventExport(enable bool) {
	i := int32(0)
	if (enable) {
		i = 1
	}
	atomic.StoreInt32(&eventExportEnabled, i)
}

func isEventExportEnabled() (bool) {
	return atomic.LoadInt32(&eventExportEnabled) != 0
}

func newUserEvent(event *v1.Event) (sdc_internal.K8SUserEvent) {
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
			t := metav1.Time{Time: time.Now()}
			ts = int64(t.Time.UTC().Unix())
			log.Infof("K8s User Event: Both eventTime and lastTimestamp are null. Event is : %v", event)
		}
	}

	evt := sdc_internal.K8SUserEvent {
		Obj: newK8SObject(event),
		Source: &sdc_internal.K8SSource{
			Component: proto.String(event.Source.Component),
			Host: proto.String(event.Source.Host),
		},
		Reason: proto.String(event.Reason),
		Message: proto.String(event.Message),
		FirstTimestamp: proto.Int64(event.FirstTimestamp.Time.UTC().Unix()),
		LastTimestamp: proto.Int64(ts),
		Count: proto.Int32(event.Count),
		Type: proto.String(event.Type),
	}
	return evt
}

func newK8SObject(event *v1.Event) (*sdc_internal.K8SObject) {
	obj := event.InvolvedObject

	ret := &sdc_internal.K8SObject{
		Kind: proto.String(obj.Kind),
		Namespace: proto.String(obj.Namespace),
		Name: proto.String(obj.Name),
		Uid: proto.String(string(obj.UID)),
		ApiVersion: proto.String(obj.APIVersion),
		ResourceVersion: proto.String(obj.ResourceVersion),
		FieldPath: proto.String(obj.FieldPath),
	}
	return ret
}

var eventInf cache.SharedInformer

func startUserEventsSInformer(ctx context.Context,
			      kubeClient kubeclient.Interface,
			      wg *sync.WaitGroup,
			      userEventChannel chan<- sdc_internal.K8SUserEvent,
			      debugEvents bool) {
	var fSelector fields.Selector
	client := kubeClient.CoreV1().RESTClient()

	if debugEvents {
		log.Debugf("UserEvents: watching all")
		fSelector = fields.Everything()
	} else {
		var err error
		log.Debugf("UserEvents: watching filtered")
		// k8s api doesn't do "or", so have to explicitly reject all the un-wanted kinds.
		fSelector, err = fields.ParseSelector("involvedObject.kind!=Cronjob,involvedObject.kind!=HorizontalPodAutoscaler,involvedObject.kind!=Ingress,involvedObject.kind!=Job,involvedObject.kind!=Namespace,involvedObject.kind!=Service,involvedObject.kind!=ResourceQuota")
		if err != nil {
			log.Errorf("UserEvents: Failed to create field selector, falling back to watching all: %v", err)
			fSelector = fields.Everything()
		}
	}
	lw := cache.NewListWatchFromClient(client, "events", metav1.NamespaceAll, fSelector)
	eventInf = cache.NewSharedInformer(lw, &v1.Event{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchUserEvents(userEventChannel)
		eventInf.Run(ctx.Done())
		wg.Done()
	}()
}

// func watchEvents(userEventChannel chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
func watchUserEvents(userEventChannel chan<- sdc_internal.K8SUserEvent) cache.SharedInformer {
	log.Debugf("In WatchEvents()")

	// Only delegated agents should be sending k8s events to the collector
	// XXX: Currently cointerface will always start an informer and this watcher
	// for events. Dragent will send commands to start or stop sending events
	// when it has figured out that its delegation status has changed.
	// Ideally we should not have the informer and this watcher running needlessly.

	eventInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if (isEventExportEnabled()) {
					log.Debugf("Event: Event add: %+v", obj)
					userEventChannel <- newUserEvent(obj.(*v1.Event))
				} else {
					log.Debugf("Event: Skip add event export");
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if (isEventExportEnabled()) {
					log.Debugf("Event: Event update: old: %+v, new: %+v", oldObj, newObj)
					oldEvent := oldObj.(*v1.Event)
					newEvent := newObj.(*v1.Event)
					if oldEvent.GetResourceVersion() != newEvent.GetResourceVersion() {
						userEventChannel <- newUserEvent(newEvent)
					}
				} else {
					log.Debugf("Event: Skip update event export");
				}
			},
			DeleteFunc: func(obj interface{}) {
				// What does it mean for an event to be deleted?
				// The legacy code ignores event deletions, so we will do the same.
				// If we some day decide to pass these events along make sure to
				// handle the case where the obj is a cache.DeletedFinalStateUnknown
				// instead of a v1.Event
				log.Debugf("Event: Ignoring event deletion: %+v", obj)
			},
		},
	)

	return eventInf
}
