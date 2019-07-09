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

// Globals are reset in startServicesSInformer
var svcSelectorCache *selectorCache

type coService struct {
	*v1.Service
}

func (svc coService) Selector() labels.Selector {
	return labels.Set(svc.Spec.Selector).AsSelector()
}

func (svc coService) Filtered() bool {
	return false
}

// If the optional selector field is defined, it means we could have
// pod children but don't know, so always return >0 in that case
func (svc coService) ActiveChildren() int32 {
	if len(svc.Spec.Selector) == 0 {
		return 0
	}
	return 1
}

// make this a library function?
func serviceEvent(svc coService, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newServiceCongroup(svc, setLinks),
	}
}

func serviceEquals(lhs coService, rhs coService) (bool, bool) {
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

func newServiceCongroup(service coService, setLinks bool) (*draiosproto.ContainerGroup) {
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
		selector, ok := svcSelectorCache.Get(service)
		if ok {
			AddPodChildren(&ret.Children, selector, service.GetNamespace())
		}
	}
	return ret
}

var serviceInf cache.SharedInformer
var portmapMutex = &sync.Mutex{}
var unresolvedPorts = map[types.UID]bool{}

func addServicePorts(ports *[]*draiosproto.CongroupNetPort, service coService) {
	for _, port := range service.Spec.Ports {
		sPort := draiosproto.CongroupNetPort{
			Port: proto.Uint32(uint32(port.Port)),
			Protocol: proto.String(string(port.Protocol)),
		}

		p := uint32(0)
		if port.TargetPort.Type == intstr.Int {
			p = uint32(port.TargetPort.IntValue())
		} else {
			selector, ok := svcSelectorCache.Get(service)
			if ok {
				p = resolveTargetPort(port.TargetPort.String(),
					selector, service.GetNamespace())
				// Resolving may have failed if we race
				// with pods being added. Note this service
				// so we can later send an update event with
				// the populated TargetPort
				if p == 0 {
					log.Debugf("Marking k8s_service %v for port resolution",
						service.GetName())
					portmapMutex.Lock()
					unresolvedPorts[service.GetUID()] = true
					portmapMutex.Unlock()
				}

			}
		}
		sPort.TargetPort = proto.Uint32(p)

		*ports = append(*ports, &sPort)
	}
}

func AddServiceParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !resourceReady("services") {
		return
	}

	podLabels := labels.Set(pod.GetLabels())
	for _, obj := range serviceInf.GetStore().List() {
		service := coService{obj.(*v1.Service)}
		if pod.GetNamespace() != service.GetNamespace() {
			continue
		}

		selector, ok := svcSelectorCache.Get(service)
		if ok && selector.Matches(podLabels) {
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
	if !resourceReady("services") {
		return
	}

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

func startServicesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	svcSelectorCache = newSelectorCache()
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Services", v1meta.NamespaceAll, fields.Everything())
	serviceInf = cache.NewSharedInformer(lw, &v1.Service{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchServices(evtc)
		serviceInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchServices(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchServices()")

	serviceInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("services")
				evtc <- serviceEvent(coService{obj.(*v1.Service)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("Service", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldService := coService{oldObj.(*v1.Service)}
				newService := coService{newObj.(*v1.Service)}

				sameEntity, sameLinks := true, true
				if oldService.GetResourceVersion() != newService.GetResourceVersion() {
					sameEntity, sameLinks = serviceEquals(oldService, newService)
				} else {
					portmapMutex.Lock()
					if unresolvedPorts[newService.GetUID()] {
						sameEntity, sameLinks = false, false
						delete(unresolvedPorts, newService.GetUID())
					}
					portmapMutex.Unlock()
				}

				if !sameLinks {
					svcSelectorCache.Update(newService)
				}
				if !sameEntity || !sameLinks {
					evtc <- serviceEvent(newService,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("Service", EVENT_UPDATE_AND_SEND)
				}
				addEvent("Service", EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldService := coService{nil}
				switch obj.(type) {
				case *v1.Service:
					oldService = coService{obj.(*v1.Service)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.Service)
					if ok {
						oldService = coService{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without service object")
					}
				default:
					log.Warn("Unknown object type in service DeleteFunc")
				}
				if oldService.Service == nil {
					return
				}

				svcSelectorCache.Remove(oldService)
				// We may not have an unresolved port, but delete is still safe
				portmapMutex.Lock()
				delete(unresolvedPorts, oldService.GetUID())
				portmapMutex.Unlock()
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_service"),
							Id:proto.String(string(oldService.GetUID()))},
					},
				}
				addEvent("Service", EVENT_DELETE)
			},
		},
	)
}
