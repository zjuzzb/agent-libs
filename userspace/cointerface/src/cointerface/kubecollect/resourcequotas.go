package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var resourceQuotaInf cache.SharedInformer

// make this a library function?
func resourceQuotaEvent(rq *v1.ResourceQuota, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newResourceQuotaCongroup(rq),
	}
}

func setScope(tags map[string]string, resourcequota *v1.ResourceQuota) {
	scopes := resourcequota.Spec.Scopes
	var terminatingTag = "kubernetes.resourcequota.label.scope.terminating"
	var nonterminatingTag = "kubernetes.resourcequota.label.scope.notterminating"
	var besteffortTag = "kubernetes.resourcequota.label.scope.besteffort"
	var nonbesteffortTag = "kubernetes.resourcequota.label.scope.notbesteffort"

	tags[terminatingTag] = "false"
	tags[nonterminatingTag] = "false"
	tags[besteffortTag] = "false"
	tags[nonbesteffortTag] = "false"

	for i := 0; i < len(scopes); i++ {
		if scopes[i] == "Terminating" {
			tags[terminatingTag] = "true"
		} else if scopes[i] == "NotTerminating" {
			tags[nonterminatingTag] = "true"
		} else if scopes[i] == "BestEffort" {
			tags[besteffortTag] = "true"
		} else if scopes[i] == "NotBestEffort" {
			tags[nonbesteffortTag] = "true"
		}
	}
}

func resourceQuotaEquals(oldResourceQuota *v1.ResourceQuota, newResourceQuota *v1.ResourceQuota) bool {
	ret := true
	if oldResourceQuota.GetName() != newResourceQuota.GetName() ||
		!kubecollect_common.EqualLabels(oldResourceQuota.ObjectMeta, newResourceQuota.ObjectMeta) ||
		!kubecollect_common.EqualAnnotations(oldResourceQuota.ObjectMeta, newResourceQuota.ObjectMeta) ||
		!kubecollect_common.EqualResourceList(oldResourceQuota.Status.Used, newResourceQuota.Status.Used) {
		ret = false
	}
	return ret
}

func newResourceQuotaCongroup(resourceQuota *v1.ResourceQuota) *draiosproto.ContainerGroup {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range resourceQuota.GetLabels() {
		tags["kubernetes.resourcequota.label."+k] = v
	}

	setScope(tags, resourceQuota)
	tags["kubernetes.resourcequota.name"] = resourceQuota.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_resourcequota"),
			Id:   proto.String(string(resourceQuota.GetUID()))},
		Tags:      tags,
		Namespace: proto.String(resourceQuota.GetNamespace()),
	}

	AddResourceQuotaMetrics(&ret.Metrics, resourceQuota)
	return ret
}

func AddResourceQuotaMetrics(metrics *[]*draiosproto.AppMetric, resourceQuota *v1.ResourceQuota) {
	prefix := "kubernetes.resourcequota."

	for k, v := range resourceQuota.Status.Used {
		hard := resourceQuota.Status.Hard[k]

		// Take MilliValue() and divide because
		// we could lose precision with Value()
		kubecollect_common.AppendMetric(metrics, prefix+k.String()+".hard", float64(hard.MilliValue())/1000)
		kubecollect_common.AppendMetric(metrics, prefix+k.String()+".used", float64(v.MilliValue())/1000)
	}
}

func StartResourceQuotasSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ResourceQuotas", v1meta.NamespaceAll, fields.Everything())
	resourceQuotaInf = cache.NewSharedInformer(lw, &v1.ResourceQuota{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchResourceQuotas(evtc)
		resourceQuotaInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchResourceQuotas(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchResourceQuotas()")

	resourceQuotaInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("resourcequotas")
				evtc <- resourceQuotaEvent(obj.(*v1.ResourceQuota),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("ResourceQuota", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldResourceQuota := oldObj.(*v1.ResourceQuota)
				newResourceQuota := newObj.(*v1.ResourceQuota)
				if (oldResourceQuota.GetResourceVersion() != newResourceQuota.GetResourceVersion()) ||
					!resourceQuotaEquals(oldResourceQuota, newResourceQuota) {

					evtc <- resourceQuotaEvent(newResourceQuota,
						draiosproto.CongroupEventType_UPDATED.Enum())
					kubecollect_common.AddEvent("ResourceQuota", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("ResourceQuota", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldRQ := (*v1.ResourceQuota)(nil)
				switch obj := obj.(type) {
				case *v1.ResourceQuota:
					oldRQ = obj
				case cache.DeletedFinalStateUnknown:
					o, ok := (obj.Obj).(*v1.ResourceQuota)
					if ok {
						oldRQ = o
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without resourcequota object")
					}
				default:
					_ = log.Warn("Unknown object type in resourcequota DeleteFunc")
				}
				if oldRQ == nil {
					return
				}

				evtc <- resourceQuotaEvent(oldRQ,
					draiosproto.CongroupEventType_REMOVED.Enum())
				kubecollect_common.AddEvent("ResourceQuota", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
