package kubecollect

import (
	"cointerface/sdc_internal"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/core/v1"
)

func userEventEvent(event *v1.Event) (sdc_internal.K8SUserEvent) {
	log.Debugf("userEventEvent()")
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
			      evtc chan<- sdc_internal.K8SUserEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "events", v1meta.NamespaceAll, fields.Everything())
	eventInf = cache.NewSharedInformer(lw, &v1.Event{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchUserEvents(evtc)
		eventInf.Run(ctx.Done())
		wg.Done()
	}()
}

// func watchEvents(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
func watchUserEvents(evtc chan<- sdc_internal.K8SUserEvent) cache.SharedInformer {
	log.Debugf("In WatchEvents()")

	eventInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.Debugf("Event: Event add: %+v", obj)
				evtc <- userEventEvent(obj.(*v1.Event))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Debugf("Event: Event update: old: %+v, new: %+v", oldObj, newObj)
				oldEvent := oldObj.(*v1.Event)
				newEvent := newObj.(*v1.Event)
				if oldEvent.GetResourceVersion() != newEvent.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping Event oldEvent %v", oldEvent)
					//log.Debugf("UpdateFunc dumping Event newEvent %v", newEvent)
					evtc <- userEventEvent(newEvent)
				}
			},
			DeleteFunc: func(obj interface{}) {
				log.Debugf("Event: Event delete: %+v", obj)
				//log.Debugf("DeleteFunc dumping ReplicaSet: %v", obj.(*v1.Event))
				evtc <- userEventEvent(obj.(*v1.Event))
			},
		},
	)

	return eventInf
}
