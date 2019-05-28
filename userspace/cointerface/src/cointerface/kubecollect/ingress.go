package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/api/core/v1"
)

// make this a library function?
func ingressEvent(ingress *v1beta1.Ingress, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newIngressCongroup(ingress),
	}
}

func newIngressCongroup(ingress *v1beta1.Ingress) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range ingress.GetLabels() {
		tags["kubernetes.ingress.label." + k] = v
	}
	tags["kubernetes.ingress.name"] = ingress.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_ingress"),
			Id:proto.String(string(ingress.GetUID()))},
		Tags: tags,
	}
	AddNSParents(&ret.Parents, ingress.GetNamespace())
	if backend := ingress.Spec.Backend; backend != nil {
		if serviceUid := lookupServiceByName(backend.ServiceName, ingress.GetNamespace()); serviceUid != "" {
			ret.Children = append(ret.Children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_service"),
				Id:proto.String(serviceUid)})
		}
	} else {
		for _, rule := range ingress.Spec.Rules {
			if http := rule.HTTP ; http != nil {
				for _, path := range http.Paths {
					if serviceUid := lookupServiceByName(path.Backend.ServiceName, ingress.GetNamespace()); serviceUid != "" {
						ret.Children = append(ret.Children, &draiosproto.CongroupUid{
							Kind:proto.String("k8s_service"),
							Id:proto.String(serviceUid)})
					}
				}
			}
		}
	}
	return ret
}

var ingressInf cache.SharedInformer

func AddIngressParents(parents *[]*draiosproto.CongroupUid, service *v1.Service) {
	if !resourceReady("ingress") {
		return
	}

	for _, obj := range ingressInf.GetStore().List() {
		ingress := obj.(*v1beta1.Ingress)
		if ingress.GetNamespace() != service.GetNamespace() {
			continue
		}
		if backend := ingress.Spec.Backend; backend != nil && backend.ServiceName == service.GetName(){
			*parents = append(*parents, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_ingress"),
				Id:proto.String(string(ingress.GetUID()))})
		} else {
			for _, rule := range ingress.Spec.Rules {
				if http := rule.HTTP ; http != nil {
					for _, path := range http.Paths {
						if path.Backend.ServiceName == service.GetName() {
							*parents = append(*parents, &draiosproto.CongroupUid{
								Kind:proto.String("k8s_ingress"),
								Id:proto.String(string(ingress.GetUID()))})
						}
					}
				}
			}
		}
	}
}

func AddIngressChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("ingress") {
		return
	}

	for _, obj := range ingressInf.GetStore().List() {
		ingress := obj.(*v1beta1.Ingress)
		if ingress.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_ingress"),
				Id:proto.String(string(ingress.GetUID()))})
		}
	}
}

func startIngressSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ingresses", v1meta.NamespaceAll, fields.Everything())
	ingressInf = cache.NewSharedInformer(lw, &v1beta1.Ingress{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchIngress(evtc)
		ingressInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchIngress(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchIngress()")

	ingressInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("ingress")
				evtc <- ingressEvent(obj.(*v1beta1.Ingress),
					draiosproto.CongroupEventType_ADDED.Enum())
				addEvent("Ingress", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldIngress := oldObj.(*v1beta1.Ingress)
				newIngress := newObj.(*v1beta1.Ingress)
				if oldIngress.GetResourceVersion() != newIngress.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping Service oldIngress %v", oldIngress)
					//log.Debugf("UpdateFunc dumping Service newIngress %v", newIngress)
					evtc <- ingressEvent(newIngress,
						draiosproto.CongroupEventType_UPDATED.Enum())
					addEvent("Ingress", EVENT_UPDATE_AND_SEND)
				}
				addEvent("Ingress", EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldIngress := (*v1beta1.Ingress)(nil)
				switch obj.(type) {
				case *v1beta1.Ingress:
					oldIngress = obj.(*v1beta1.Ingress)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1beta1.Ingress)
					if ok {
						oldIngress = o
					} else {
						log.Warn("DeletedFinalStateUnknown without ingress object")
					}
				default:
					log.Warn("Unknown object type in ingress DeleteFunc")
				}
				if oldIngress == nil {
					return
				}

				evtc <- ingressEvent(oldIngress,
					draiosproto.CongroupEventType_REMOVED.Enum())
				addEvent("Ingress", EVENT_DELETE)
			},
		},
	)
}
