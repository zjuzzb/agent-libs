package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/core/v1"
)

// make this a library function?
func resourceQuotaEvent(rq *v1.ResourceQuota, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newResourceQuotaCongroup(rq),
	}
}

func newResourceQuotaCongroup(resourceQuota *v1.ResourceQuota) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range resourceQuota.GetLabels() {
		tags["kubernetes.resourcequota.label." + k] = v
	}
	tags["kubernetes.resourcequota.name"] = resourceQuota.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_resourcequota"),
			Id:proto.String(string(resourceQuota.GetUID()))},
		Tags: tags,
	}
	AddNSParents(&ret.Parents, resourceQuota.GetNamespace())
	return ret
}

var resourceQuotaInf cache.SharedInformer

func AddResourceQuotaChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	for _, obj := range resourceQuotaInf.GetStore().List() {
		resourceQuota := obj.(*v1.ResourceQuota)
		if resourceQuota.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_resourcequota"),
				Id:proto.String(string(resourceQuota.GetUID()))})
		}
	}
}

func StartResourceQuotasSInformer(ctx context.Context, kubeClient kubeclient.Interface) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ResourceQuotas", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second
	resourceQuotaInf = cache.NewSharedInformer(lw, &v1.ResourceQuota{}, resyncPeriod)
	go resourceQuotaInf.Run(ctx.Done())
}

func WatchResourceQuotas(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchResourceQuotas()")

	resourceQuotaInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				//log.Debugf("AddFunc dumping ResourceQuota: %v", obj.(*v1.ResourceQuota))
				evtc <- resourceQuotaEvent(obj.(*v1.ResourceQuota),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldResourceQuota := oldObj.(*v1.ResourceQuota)
				newResourceQuota := newObj.(*v1.ResourceQuota)
				if oldResourceQuota.GetResourceVersion() != newResourceQuota.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping ResourceQuota oldResourceQuota %v", oldResourceQuota)
					//log.Debugf("UpdateFunc dumping ResourceQuota newResourceQuota %v", newResourceQuota)
					evtc <- resourceQuotaEvent(newResourceQuota,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ResourceQuota: %v", obj.(*v1.ResourceQuota))
				evtc <- resourceQuotaEvent(obj.(*v1.ResourceQuota),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	return resourceQuotaInf
}
