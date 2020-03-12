package kubecollect

import (
	"cointerface/kubecollect_common"
	draiosproto "protorepo/agent-be/proto"
	"context"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sync"
)

var persistentVolumeClaimsInf cache.SharedInformer
var pvcMetricPrefix = "kubernetes.persistentvolumeclaim."

func StartPersistentVolumeClaimsInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "PersistentVolumeClaims", v1meta.NamespaceAll, fields.Everything())
	persistentVolumeClaimsInf = cache.NewSharedInformer(lw, &v1.PersistentVolumeClaim{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchPersistentVolumeClaims(evtc)
		persistentVolumeClaimsInf.Run(ctx.Done())
		wg.Done()
	}()
}


func persistentVolumeClaimEvent(pv *v1.PersistentVolumeClaim, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newPersistentVolumeClaimCongroup(pv),
	}
}

func newPersistentVolumeClaimCongroup(pvc *v1.PersistentVolumeClaim) (*draiosproto.ContainerGroup) {
	label_tag_name := pvcMetricPrefix + "label."
	internal_tag_name := pvcMetricPrefix + "label."

	tags := make(map[string]string)
	for k, v := range pvc.GetLabels() {
		tags[label_tag_name+ k] = v
	}

	var accessMode string
	for _, v := range pvc.Spec.AccessModes {
		accessMode += string(v)
	}

	tags[internal_tag_name + "accessmode"] = string(accessMode)

	tags[internal_tag_name + "volumename"] = pvc.Spec.VolumeName

	if pvc.Spec.StorageClassName != nil {
		tags[internal_tag_name + "storageclassname"] = *pvc.Spec.StorageClassName
	}

	tags[internal_tag_name + "status.phase"] = string(pvc.Status.Phase)
	storage := pvc.Status.Capacity["storage"]
	tags[internal_tag_name + "storage"] = storage.String()
	tags[pvcMetricPrefix + "name"] = pvc.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_persistentvolumeclaim"),
			Id:proto.String(string(pvc.GetUID()))},
		Tags: tags,
		Namespace:proto.String(pvc.GetNamespace()),
	}

	addPersistentVolumeClaimMetrics(&ret.Metrics, pvc)

	return ret
}

func addPersistentVolumeClaimMetrics(metrics *[]*draiosproto.AppMetric, pvc *v1.PersistentVolumeClaim) {
	storage, _ := pvc.Status.Capacity["storage"]

	if requestStorage, ok := pvc.Spec.Resources.Requests[v1.ResourceStorage]; ok {
		kubecollect_common.AppendMetricInt64(metrics, pvcMetricPrefix + "requests.storage", requestStorage.Value())
	}

	kubecollect_common.AppendMetricInt64(metrics, pvcMetricPrefix + "storage", storage.Value())
}

func watchPersistentVolumeClaims(evtc chan <- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In Watchpersistentvolumeclaims()")

	persistentVolumeClaimsInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("persistentvolumeclaims")
				log.Debugf("PVC: %v", obj.(*v1.PersistentVolumeClaim))
				evtc <- persistentVolumeClaimEvent(obj.(*v1.PersistentVolumeClaim),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("PersistentVolumeClaim", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPersistentVolumeClaim := oldObj.(*v1.PersistentVolumeClaim)
				newPersistentVolumeClaim := newObj.(*v1.PersistentVolumeClaim)
				if oldPersistentVolumeClaim.GetResourceVersion() != newPersistentVolumeClaim.GetResourceVersion() {
					evtc <- persistentVolumeClaimEvent(newPersistentVolumeClaim,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
				kubecollect_common.AddEvent("PersistentVolumeClaim", kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldPVC := (*v1.PersistentVolumeClaim)(nil)
				switch obj.(type) {
				case *v1.PersistentVolumeClaim:
					oldPVC = obj.(*v1.PersistentVolumeClaim)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.PersistentVolumeClaim)
					if ok {
						oldPVC = o
					} else {
						log.Warn("DeletedFinalStateUnknown without pvc object")
					}
				default:
					log.Warn("Unknown object type in pvc DeleteFunc")
				}
				if oldPVC == nil {
					return
				}

				evtc <- persistentVolumeClaimEvent(oldPVC,
					draiosproto.CongroupEventType_REMOVED.Enum())
				kubecollect_common.AddEvent("PersistentVolumeClaim", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}

