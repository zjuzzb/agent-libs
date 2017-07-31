package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"	
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
)

// make this a library function?
func serviceEvent(ns *v1.Service, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newServiceCongroup(ns, setLinks),
	}
}

func serviceEquals(lhs *v1.Service, rhs *v1.Service) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	if in && len(lhs.GetLabels()) != len(rhs.GetLabels()) {
		in = false
	} else {
		for k,v := range lhs.GetLabels() {
			if rhs.GetLabels()[k] != v {
				in = false
			}
		}
	}

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	} else if !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		out = false
	}

	return in, out
}

func serviceSelector(service *v1.Service) (labels.Selector, error) {
	lselector := &v1meta.LabelSelector{}
	for k, v := range service.Spec.Selector {
		v1meta.AddLabelToSelector(lselector, k, v)
	}
	return v1meta.LabelSelectorAsSelector(lselector)
}

func lookupServiceByName(serviceName, namespace string) string {
	// Probably we should map them by name somehow
	for _, obj := range serviceInf.GetStore().List() {
		service := obj.(*v1.Service)
		if service.GetNamespace() == namespace && service.GetName() == serviceName {
			return string(service.GetUID())
		}
	}
	return ""
}

func newServiceCongroup(service *v1.Service, setLinks bool) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range service.GetLabels() {
		tags["kubernetes.service.label." + k] = v
	}
	tags["kubernetes.service.name"] = service.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_service"),
			Id:proto.String(string(service.GetUID()))},
		Tags: tags,
	}
	if setLinks {
		AddNSParents(&ret.Parents, service.GetNamespace())
		AddIngressParents(&ret.Parents, service)
		AddStatefulSetParentsFromService(&ret.Parents, service)
		// ref: https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors
		if len(service.Spec.Selector) > 0 {
			selector, _ := serviceSelector(service)
			AddPodChildren(&ret.Children, selector, service.GetNamespace())
		}
	}
	return ret
}

var serviceInf cache.SharedInformer

func AddServiceParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	for _, obj := range serviceInf.GetStore().List() {
		service := obj.(*v1.Service)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())

		if len(service.Spec.Selector) == 0 {
			continue
		}

		selector, _ := serviceSelector(service)
		if pod.GetNamespace() == service.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_service"),
				Id:proto.String(string(service.GetUID()))})
		}
	}
}

func AddServiceChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	AddServiceChildrenFromServiceName(children, namespaceName, "")
}

func AddServiceChildrenFromServiceName(children *[]*draiosproto.CongroupUid, namespaceName string, serviceName string) {
	for _, obj := range serviceInf.GetStore().List() {
		service := obj.(*v1.Service)
		if service.GetNamespace() != namespaceName {
			continue
		}

		if "" == serviceName || service.GetName() == serviceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_service"),
				Id:proto.String(string(service.GetUID()))})
		}
	}
}

func WatchServices(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchServices()")

	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Services", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	serviceInf = cache.NewSharedInformer(lw, &v1.Service{}, resyncPeriod)

	serviceInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- serviceEvent(obj.(*v1.Service),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldService := oldObj.(*v1.Service)
				newService := newObj.(*v1.Service)
				if oldService.GetResourceVersion() != newService.GetResourceVersion() {
					sameEntity, sameLinks := serviceEquals(oldService, newService)
					if !sameEntity || !sameLinks {
						evtc <- serviceEvent(newService,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldService := obj.(*v1.Service)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_service"),
							Id:proto.String(string(oldService.GetUID()))},
					},
				}
			},
		},
	)

	go serviceInf.Run(ctx.Done())

	return serviceInf
}
