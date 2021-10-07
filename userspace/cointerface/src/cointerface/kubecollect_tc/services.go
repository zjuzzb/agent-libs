package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

func serviceEvent(svc kubecollect.CoService, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newServiceCongroup(svc, setLinks),
	}
}

func newServiceCongroup(service kubecollect.CoService, setLinks bool) *draiosproto.ContainerGroup {
	tags := kubecollect_common.GetTags(service, "kubernetes.service.")
	inttags := kubecollect_common.GetAnnotations(service.ObjectMeta, "kubernetes.service.")

	kubecollect_common.MapInsert(&inttags, "kubernetes.service.type", string(service.Spec.Type))

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_service"),
			Id:   proto.String(string(service.GetUID()))},
		Tags:         tags,
		Selectors:    service.Spec.Selector,
		InternalTags: inttags,
		Namespace:    proto.String(service.GetNamespace()),
	}

	if service.Spec.ClusterIP != "None" {
		ret.IpAddresses = append(ret.IpAddresses, service.Spec.ClusterIP)
	}

	addServicePorts(&ret.Ports, service)

	if setLinks {
		kubecollect.AddIngressParents(&ret.Parents, kubecollect.CoService(service))
	}
	return ret
}

func addServicePorts(ports *[]*draiosproto.CongroupNetPort, service kubecollect.CoService) {
	for _, port := range service.Spec.Ports {
		sPort := draiosproto.CongroupNetPort{
			Port:     proto.Uint32(uint32(port.Port)),
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

func startServicesWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	kubecollect_common.StartWatcher(ctx, kubeClient.CoreV1().RESTClient(), "Services", wg, evtc, fields.Everything(), handleServiceEvent)
}

func handleServiceEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	service, ok := event.Object.(*v1.Service)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("services")
		evtc <- serviceEvent(kubecollect.CoService{service}, draiosproto.CongroupEventType_ADDED.Enum(), true)
		kubecollect_common.AddEvent("service", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("service", kubecollect_common.EVENT_UPDATE)
		evtc <- serviceEvent(kubecollect.CoService{service}, draiosproto.CongroupEventType_UPDATED.Enum(), true)
		kubecollect_common.AddEvent("service", kubecollect_common.EVENT_UPDATE_AND_SEND)
	} else if event.Type == watch.Deleted {
		evtc <- serviceEvent(kubecollect.CoService{service}, draiosproto.CongroupEventType_REMOVED.Enum(), false)
		kubecollect_common.AddEvent("service", kubecollect_common.EVENT_DELETE)
	}
}
