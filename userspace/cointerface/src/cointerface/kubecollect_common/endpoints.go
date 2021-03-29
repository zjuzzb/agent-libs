package kubecollect_common

import (
	"context"
	"github.com/gogo/protobuf/proto"
	appsv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

type CoEndpoints struct {
	*appsv1.Endpoints
}

func endpointsEvent(dep CoEndpoints, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newEndpointsCongroup(dep, setLinks),
	}
}

func newEndpointsCongroup(endpoints CoEndpoints, setLinks bool) (*draiosproto.ContainerGroup) {
	var ports []*draiosproto.CongroupNetPort
	var ips []string

	tags := GetTags(endpoints.ObjectMeta, "kubernetes.endpoints.")
	inttags := GetAnnotations(endpoints.ObjectMeta, "kubernetes.endpoints.")

	for _, subset := range endpoints.Subsets {
		// Merging both Addresses and NotReadyAddresses
		for _, endpointsAddress := range append(subset.Addresses, subset.NotReadyAddresses...) {
			found := false
			for _, addr := range ips {
				if endpointsAddress.IP == addr {
					found = true
				}
			}
			if !found {
				ips = append(ips, endpointsAddress.IP)
			}
		}

		for _, endpointsPort := range subset.Ports {
			found := false
			for _, port := range ports {
				if endpointsPort.Port == int32(*port.Port) {
					found = true
				}
			}
			if !found {
				ports = append(ports, &draiosproto.CongroupNetPort{
					Port: proto.Uint32(uint32(endpointsPort.Port)),
					TargetPort: proto.Uint32(0),
				})
			}
		}
	}

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_endpoints"),
			Id:proto.String(string(endpoints.GetUID()))},
		Tags: tags,
		InternalTags: inttags,
		Namespace: proto.String(endpoints.GetNamespace()),
		IpAddresses: ips,
		Ports: ports,
	}

	return ret
}

func StartEndpointsWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	StartWatcher(ctx, kubeClient.CoreV1().RESTClient(), "Endpoints", wg, evtc, fields.Everything(), handleEndpointsEvent)
}

func handleEndpointsEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	endpoints, ok := event.Object.(*appsv1.Endpoints)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		EventReceived("endpoints")
		evtc <- endpointsEvent(CoEndpoints{endpoints}, draiosproto.CongroupEventType_ADDED.Enum(), true)
		AddEvent("Endpoints", EVENT_ADD)
	} else if event.Type == watch.Modified {
		AddEvent("Endpoints", EVENT_UPDATE)
		evtc <- endpointsEvent(CoEndpoints{endpoints}, draiosproto.CongroupEventType_UPDATED.Enum(), true)
		AddEvent("Endpoints", EVENT_UPDATE_AND_SEND)
	} else if event.Type == watch.Deleted {
		evtc <- endpointsEvent(CoEndpoints{endpoints}, draiosproto.CongroupEventType_REMOVED.Enum(), false)
		AddEvent("Endpoints", EVENT_DELETE)
	}
}
