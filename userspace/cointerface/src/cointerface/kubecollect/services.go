package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"	
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
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

	in = in && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
		EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

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
	tags := GetTags(service.ObjectMeta, "kubernetes.service.")
	inttags := GetAnnotations(service.ObjectMeta, "kubernetes.service.")

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_service"),
			Id:proto.String(string(service.GetUID()))},
		Tags: tags,
		InternalTags: inttags,
	}

	ret.IpAddresses = append(ret.IpAddresses, service.Spec.ClusterIP)

	if setLinks {
		addServicePorts(&ret.Ports, service)
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
var unresolvedPorts = map[types.UID]bool{}

func addServicePorts(ports *[]*draiosproto.CongroupNetPort, service *v1.Service) {
	for _, port := range service.Spec.Ports {
		sPort := draiosproto.CongroupNetPort{
			Port: proto.Uint32(uint32(port.Port)),
			Protocol: proto.String(string(port.Protocol)),
		}

		p := uint32(0)
		if port.TargetPort.Type == intstr.Int {
			p = uint32(port.TargetPort.IntValue())
		} else {
			if len(service.Spec.Selector) > 0 {
				selector, _ := serviceSelector(service)
				p = resolveTargetPort(port.TargetPort.String(),
					selector, service.GetNamespace())
				// Resolving may have failed if we race
				// with pods being added. Note this service
				// so we can later send an update event with
				// the populated TargetPort
				if p == 0 {
					log.Debugf("Marking k8s_service %v for port resolution",
						service.GetName())
					unresolvedPorts[service.GetUID()] = true
				}

			}
		}
		sPort.TargetPort = proto.Uint32(p)

		*ports = append(*ports, &sPort)
	}
}

func AddServiceParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if compatibilityMap["services"] {
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
}

func AddServiceChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	AddServiceChildrenFromServiceName(children, namespaceName, "")
}

func AddServiceChildrenFromServiceName(children *[]*draiosproto.CongroupUid, namespaceName string, serviceName string) {
	if compatibilityMap["services"] {
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
}

func startServicesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Services", v1meta.NamespaceAll, fields.Everything())
	serviceInf = cache.NewSharedInformer(lw, &v1.Service{}, RsyncInterval)

	wg.Add(1)
	go func() {
		serviceInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchServices(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchServices()")

	serviceInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- serviceEvent(obj.(*v1.Service),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldService := oldObj.(*v1.Service)
				newService := newObj.(*v1.Service)

				sameEntity, sameLinks := true, true
				if oldService.GetResourceVersion() != newService.GetResourceVersion() {
					sameEntity, sameLinks = serviceEquals(oldService, newService)
				} else if unresolvedPorts[newService.GetUID()] {
					sameEntity, sameLinks = false, false
					delete(unresolvedPorts, newService.GetUID())
				}

				if !sameEntity || !sameLinks {
					evtc <- serviceEvent(newService,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldService := obj.(*v1.Service)
				// We may not have an unresolved port, but delete is still safe
				delete(unresolvedPorts, oldService.GetUID())
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

	return serviceInf
}
