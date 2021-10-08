package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"reflect"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Globals are reset in startServicesSInformer
var SvcSelectorCache *SelectorCache

type CoService struct {
	*v1.Service
}

func (svc CoService) Selector() labels.Selector {
	return labels.Set(svc.Spec.Selector).AsSelector()
}

func (svc CoService) Filtered() bool {
	return false
}

// If the optional selector field is defined, it means we could have
// pod children but don't know, so always return >0 in that case
func (svc CoService) ActiveChildren() int32 {
	if len(svc.Spec.Selector) == 0 {
		return 0
	}
	return 1
}

// make this a library function?
func serviceEvent(svc CoService, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newServiceCongroup(svc, setLinks),
	}
}

func ServiceEquals(lhs CoService, rhs CoService) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	in = in && kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
		kubecollect_common.EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

	if in && lhs.Spec.ClusterIP != rhs.Spec.ClusterIP {
		in = false
	}

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	} else if !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		out = false
	}

	return in, out
}

func lookupServiceByName(serviceName, namespace string) string {
	// Probably we should map them by name somehow
	for _, obj := range ServiceInf.GetStore().List() {
		service := obj.(*v1.Service)
		if service.GetNamespace() == namespace && service.GetName() == serviceName {
			return string(service.GetUID())
		}
	}
	return ""
}

func newServiceCongroup(service CoService, setLinks bool) *draiosproto.ContainerGroup {
	tags := kubecollect_common.GetTags(service, "kubernetes.service.")
	inttags := kubecollect_common.GetAnnotations(service.ObjectMeta, "kubernetes.service.")

	if inttags == nil {
		inttags = make(map[string]string, 1)
	}
	inttags["kubernetes.service.type"] = string(service.Spec.Type)

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_service"),
			Id:   proto.String(string(service.GetUID()))},
		Tags:         tags,
		InternalTags: inttags,
		Namespace:    proto.String(service.GetNamespace()),
	}

	if service.Spec.ClusterIP != "None" {
		ret.IpAddresses = append(ret.IpAddresses, service.Spec.ClusterIP)
	}

	addServicePorts(&ret.Ports, service)

	if setLinks {
		AddIngressParents(&ret.Parents, service)
		AddStatefulSetChildrenFromService(&ret.Children, service)
		// ref: https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors
		selector, ok := SvcSelectorCache.Get(service)
		if ok {
			AddPodChildrenFromSelectors(&ret.Children, selector, service.GetNamespace())
		}
	}
	if service.ActiveChildren() > 0 {
		ret.LabelSelector = &draiosproto.K8SLabelSelector{
			MatchLabels: service.Spec.Selector,
		}
	}
	return ret
}

var ServiceInf cache.SharedInformer
var PortmapMutex = &sync.Mutex{}
var UnresolvedPorts = map[types.UID]bool{}

func addServicePorts(ports *[]*draiosproto.CongroupNetPort, service CoService) {
	for _, port := range service.Spec.Ports {
		sPort := draiosproto.CongroupNetPort{
			Port:     proto.Uint32(uint32(port.Port)),
			Protocol: proto.String(string(port.Protocol)),
		}

		p := uint32(0)
		if port.TargetPort.Type == intstr.Int {
			p = uint32(port.TargetPort.IntValue())
		} else {
			selector, ok := SvcSelectorCache.Get(service)
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
					PortmapMutex.Lock()
					UnresolvedPorts[service.GetUID()] = true
					PortmapMutex.Unlock()
				}

			}
		}
		sPort.TargetPort = proto.Uint32(p)

		*ports = append(*ports, &sPort)
	}
}

func AddServiceParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !kubecollect_common.ResourceReady("services") {
		return
	}

	podLabels := labels.Set(pod.GetLabels())
	for _, obj := range ServiceInf.GetStore().List() {
		service := CoService{obj.(*v1.Service)}
		if pod.GetNamespace() != service.GetNamespace() {
			continue
		}

		selector, ok := SvcSelectorCache.Get(service)
		if ok && selector.Matches(podLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind: proto.String("k8s_service"),
				Id:   proto.String(string(service.GetUID()))})
		}
	}
}

func AddServiceParentsFromServiceName(parents *[]*draiosproto.CongroupUid, namespaceName string, serviceName string) {
	if !kubecollect_common.ResourceReady("services") {
		return
	}

	for _, obj := range ServiceInf.GetStore().List() {
		service := obj.(*v1.Service)
		if service.GetNamespace() != namespaceName {
			continue
		}

		if service.GetName() == serviceName {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind: proto.String("k8s_service"),
				Id:   proto.String(string(service.GetUID()))})
		}
	}
}

func startServicesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	SvcSelectorCache = NewSelectorCache()
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Services", v1meta.NamespaceAll, fields.Everything())
	ServiceInf = cache.NewSharedInformer(lw, &v1.Service{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchServices(evtc)
		ServiceInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchServices(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchServices()")

	ServiceInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("services")
				evtc <- serviceEvent(CoService{obj.(*v1.Service)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldService := CoService{oldObj.(*v1.Service)}
				newService := CoService{newObj.(*v1.Service)}

				sameEntity, sameLinks := true, true
				if oldService.GetResourceVersion() != newService.GetResourceVersion() {
					sameEntity, sameLinks = ServiceEquals(oldService, newService)
				} else if UnresolvedPorts[newService.GetUID()] {
					sameEntity, sameLinks = false, true
					delete(UnresolvedPorts, newService.GetUID())
				} else {
					PortmapMutex.Lock()
					if UnresolvedPorts[newService.GetUID()] {
						sameEntity, sameLinks = false, false
						delete(UnresolvedPorts, newService.GetUID())
					}
					PortmapMutex.Unlock()
				}

				if !sameLinks {
					SvcSelectorCache.Update(newService)
				}
				if !sameEntity || !sameLinks {
					evtc <- serviceEvent(newService,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldService := CoService{nil}
				switch obj := obj.(type) {
				case *v1.Service:
					oldService = CoService{Service: obj}
				case cache.DeletedFinalStateUnknown:
					o, ok := (obj.Obj).(*v1.Service)
					if ok {
						oldService = CoService{o}
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without service object")
					}
				default:
					_ = log.Warn("Unknown object type in service DeleteFunc")
				}
				if oldService.Service == nil {
					return
				}

				SvcSelectorCache.Remove(oldService)
				// We may not have an unresolved port, but delete is still safe
				PortmapMutex.Lock()
				delete(UnresolvedPorts, oldService.GetUID())
				PortmapMutex.Unlock()
				evtc <- draiosproto.CongroupUpdateEvent{
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind: proto.String("k8s_service"),
							Id:   proto.String(string(oldService.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
