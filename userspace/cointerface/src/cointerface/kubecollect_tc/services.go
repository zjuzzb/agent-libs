package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

func serviceEvent(svc kubecollect.CoService, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newServiceCongroup(svc, setLinks),
	}
}

func newServiceCongroup(service kubecollect.CoService, setLinks bool) (*draiosproto.ContainerGroup) {
	tags := kubecollect_common.GetTags(service.ObjectMeta, "kubernetes.service.")
	inttags := kubecollect_common.GetAnnotations(service.ObjectMeta, "kubernetes.service.")

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_service"),
			Id:proto.String(string(service.GetUID()))},
		Tags: tags,
		Selectors: service.Spec.Selector,
		InternalTags: inttags,
		Namespace:proto.String(service.GetNamespace()),
	}

	if service.Spec.ClusterIP != "None" {
		ret.IpAddresses = append(ret.IpAddresses, service.Spec.ClusterIP)
	}

	addServicePorts(&ret.Ports, service)

	if setLinks {
		kubecollect.AddIngressParents(&ret.Parents, kubecollect.CoService(service))
		AddStatefulSetChildrenFromService(&ret.Children, service)
	}
	return ret
}

func addServicePorts(ports *[]*draiosproto.CongroupNetPort, service kubecollect.CoService) {
	for _, port := range service.Spec.Ports {
		sPort := draiosproto.CongroupNetPort{
			Port: proto.Uint32(uint32(port.Port)),
			Protocol: proto.String(string(port.Protocol)),
		}

		p := uint32(0)
		if port.TargetPort.Type == intstr.Int {
			p = uint32(port.TargetPort.IntValue())
			sPort.TargetPort = proto.Uint32(p)
		} else {
			sPort.Name = &port.TargetPort.StrVal
			sPort.TargetPort = proto.Uint32(0)
		}
		*ports = append(*ports, &sPort)
	}
}

func AddServiceParentsFromServiceName(parents *[]*draiosproto.CongroupUid, namespaceName string, serviceName string) {
	if !kubecollect_common.ResourceReady("services") {
		return
	}

	for _, obj := range kubecollect.ServiceInf.GetStore().List() {
		service := obj.(*v1.Service)
		if service.GetNamespace() != namespaceName {
			continue
		}

		if service.GetName() == serviceName {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_service"),
				Id:proto.String(string(service.GetUID()))})
		}
	}
}

func startServicesSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	kubecollect.SvcSelectorCache = kubecollect.NewSelectorCache()
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Services", v1meta.NamespaceAll, fields.Everything())
	kubecollect.ServiceInf = cache.NewSharedInformer(lw, &v1.Service{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchServices(evtc)
		kubecollect.ServiceInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchServices(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchServices() from package %s", kubecollect_common.GetPkg(KubecollectClientTc{}))

	kubecollect.ServiceInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("services")
				evtc <- serviceEvent(kubecollect.CoService{obj.(*v1.Service)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldService := kubecollect.CoService{oldObj.(*v1.Service)}
				newService := kubecollect.CoService{newObj.(*v1.Service)}

				sameEntity, sameLinks := true, true
				if oldService.GetResourceVersion() != newService.GetResourceVersion() {
					sameEntity, sameLinks = kubecollect.ServiceEquals(oldService, newService)
				} else if kubecollect.UnresolvedPorts[newService.GetUID()] {
					sameEntity, sameLinks = false, true
					delete(kubecollect.UnresolvedPorts, newService.GetUID())
				} else {
					kubecollect.PortmapMutex.Lock()
					if kubecollect.UnresolvedPorts[newService.GetUID()] {
						sameEntity, sameLinks = false, false
						delete(kubecollect.UnresolvedPorts, newService.GetUID())
					}
					kubecollect.PortmapMutex.Unlock()
				}

				if !sameLinks {
					kubecollect.SvcSelectorCache.Update(kubecollect.CoService(newService))
				}
				if !sameEntity || !sameLinks {
					evtc <- serviceEvent(newService,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldService := kubecollect.CoService{nil}
				switch obj.(type) {
				case *v1.Service:
					oldService = kubecollect.CoService{obj.(*v1.Service)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.Service)
					if ok {
						oldService = kubecollect.CoService{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without service object")
					}
				default:
					log.Warn("Unknown object type in service DeleteFunc")
				}
				if oldService.Service == nil {
					return
				}

				kubecollect.SvcSelectorCache.Remove(kubecollect.CoService(oldService))
				// We may not have an unresolved port, but delete is still safe
				kubecollect.PortmapMutex.Lock()
				delete(kubecollect.UnresolvedPorts, oldService.GetUID())
				kubecollect.PortmapMutex.Unlock()
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_service"),
							Id:proto.String(string(oldService.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("Service", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
