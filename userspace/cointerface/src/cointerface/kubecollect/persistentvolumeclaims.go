package kubecollect

import (
	"cointerface/draiosproto"
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

func startPersistentVolumeClaimsInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "PersistentVolumeClaims", v1meta.NamespaceAll, fields.Everything())
	persistentVolumeClaimsInf = cache.NewSharedInformer(lw, &v1.PersistentVolumeClaim{}, RsyncInterval)

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

func newPersistentVolumeClaimCongroup(pv *v1.PersistentVolumeClaim) (*draiosproto.ContainerGroup) {
	label_tag_name := pvcMetricPrefix + "label."
	internal_tag_name := pvcMetricPrefix + "label."

	tags := make(map[string]string)
	for k, v := range pv.GetLabels() {
		tags[label_tag_name+ k] = v
	}

	var accessMode string
	for _, v := range pv.Spec.AccessModes {
		accessMode += string(v)
	}

	tags[internal_tag_name + "accessmode"] = string(accessMode)

	tags[internal_tag_name + "volumename"] = pv.Spec.VolumeName
	tags[internal_tag_name + "storageclassname"] = *pv.Spec.StorageClassName
	tags[internal_tag_name + "status.phase"] = string(pv.Status.Phase)
	storage := pv.Status.Capacity["storage"]
	tags[internal_tag_name + "storage"] = storage.String()
	tags[pvcMetricPrefix + "name"] = pv.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_persistentvolumeclaim"),
			Id:proto.String(string(pv.GetUID()))},
		Tags: tags,
	}

	addPersistentVolumeClaimMetrics(&ret.Metrics, pv)

	AddNSParents(&ret.Parents, pv.GetNamespace())
	return ret
}

func addPersistentVolumeClaimMetrics(metrics *[]*draiosproto.AppMetric, pv *v1.PersistentVolumeClaim) {
	storage, _ := pv.Status.Capacity["storage"]
	AppendMetricInt64(metrics, pvcMetricPrefix + "storage", storage.Value())
}

func watchPersistentVolumeClaims(evtc chan <- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In Watchpersistentvolumeclaims()")

	persistentVolumeClaimsInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("persistentvolumeclaims")
				log.Debugf("PVC: %v", obj.(*v1.PersistentVolumeClaim))
				evtc <- persistentVolumeClaimEvent(obj.(*v1.PersistentVolumeClaim),
					draiosproto.CongroupEventType_ADDED.Enum())
				addEvent("PersistentVolumeClaim", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPersistentVolumeClaim := oldObj.(*v1.PersistentVolumeClaim)
				newPersistentVolumeClaim := newObj.(*v1.PersistentVolumeClaim)
				if oldPersistentVolumeClaim.GetResourceVersion() != newPersistentVolumeClaim.GetResourceVersion() {
					evtc <- persistentVolumeClaimEvent(newPersistentVolumeClaim,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
				addEvent("PersistentVolumeClaim", EVENT_UPDATE)
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
				addEvent("PersistentVolumeClaim", EVENT_DELETE)
			},
		},
	)
}

func AddPersistentVolumeClaimChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("persistentvolumeclaims") {
		return
	}

	for _, obj := range persistentVolumeClaimsInf.GetStore().List() {
		persistentVolumeClaim := obj.(*v1.PersistentVolumeClaim)
		if (persistentVolumeClaim.GetNamespace() == namespaceName) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_persistentvolumeclaim"),
				Id:proto.String(string(persistentVolumeClaim.GetUID()))})
		}
	}
}

