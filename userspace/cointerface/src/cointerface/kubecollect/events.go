package kubecollect

import (
	"context"
	"sync"

	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/core/v1"

	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"

	"cointerface/sdc_internal"
)

func newUserEvent(event *v1.Event) (sdc_internal.K8SUserEvent) {
	log.Debugf("newUserEvent()")
	evt := sdc_internal.K8SUserEvent {
		Obj: newK8SObject(event),
		Source: &sdc_internal.K8SSource{
			Component: proto.String(event.Source.Component),
			Host: proto.String(event.Source.Host),
		},
		Reason: proto.String(event.Reason),
		Message: proto.String(event.Message),
		FirstTimestamp: proto.Int64(event.FirstTimestamp.Time.UTC().Unix()),
		LastTimestamp: proto.Int64(event.LastTimestamp.Time.UTC().Unix()),
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
		fSelector, err = fields.ParseSelector("involvedObject.kind!=Cronjob,involvedObject.kind!=HorizontalPodAutoscaler,involvedObject.kind!=Ingress,involvedObject.kind!=Job,involvedObject.kind!=Namespace,involvedObject.kind!=Service,involvedObject.kind!=Service,involvedObject.kind!=StatefulSet,involvedObject.kind!=ResourceQuota")
		if err != nil {
			log.Errorf("UserEvents: Failed to create field selector, falling back to watching all: %v", err)
			fSelector = fields.Everything()
		}
	}
	lw := cache.NewListWatchFromClient(client, "events", v1meta.NamespaceAll, fSelector)
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

	eventInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.Debugf("Event: Event add: %+v", obj)
				userEventChannel <- newUserEvent(obj.(*v1.Event))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Debugf("Event: Event update: old: %+v, new: %+v", oldObj, newObj)
				oldEvent := oldObj.(*v1.Event)
				newEvent := newObj.(*v1.Event)
				if oldEvent.GetResourceVersion() != newEvent.GetResourceVersion() {
					log.Debugf("UpdateFunc dumping Event oldEvent %v", oldEvent)
					log.Debugf("UpdateFunc dumping Event newEvent %v", newEvent)
					userEventChannel <- newUserEvent(newEvent)
				}
			},
			DeleteFunc: func(obj interface{}) {
				log.Debugf("Event: Event delete: %+v", obj)
				userEventChannel <- newUserEvent(obj.(*v1.Event))
			},
		},
	)

	return eventInf
}
