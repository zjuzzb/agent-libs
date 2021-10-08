package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var storageClassInf cache.SharedInformer

func StartStorageClassInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.StorageV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "storageclasses", v1meta.NamespaceAll, fields.Everything())
	storageClassInf = cache.NewSharedInformer(lw, &storagev1.StorageClass{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchStorageClasses(evtc)
		storageClassInf.Run(ctx.Done())
		wg.Done()
	}()
}

func getReclaimPolicy(sc *storagev1.StorageClass) *draiosproto.K8SStorageClassReclaimPolicy {
	var ret draiosproto.K8SStorageClassReclaimPolicy
	switch *sc.ReclaimPolicy {
	case v1.PersistentVolumeReclaimRecycle:
		ret = draiosproto.K8SStorageClassReclaimPolicy_STORAGE_CLASS_RECLAIM_POLICY_RECYCLE
	case v1.PersistentVolumeReclaimDelete:
		ret = draiosproto.K8SStorageClassReclaimPolicy_STORAGE_CLASS_RECLAIM_POLICY_DELETE
	case v1.PersistentVolumeReclaimRetain:
		ret = draiosproto.K8SStorageClassReclaimPolicy_STORAGE_CLASS_RECLAIM_POLICY_RETAIN
	}

	return &ret
}

func getVolumeBindingMode(sc *storagev1.StorageClass) *draiosproto.K8SVolumeBindingMode {
	var ret draiosproto.K8SVolumeBindingMode

	switch *sc.VolumeBindingMode {
	case storagev1.VolumeBindingImmediate:
		ret = draiosproto.K8SVolumeBindingMode_VOLUME_BINDING_MODE_IMMEDIATE
	case storagev1.VolumeBindingWaitForFirstConsumer:
		ret = draiosproto.K8SVolumeBindingMode_VOLUME_BINDING_MODE_WAIT_FOR_FIRST_CONSUMER
	}

	return &ret
}

func newStorageClassConGroup(sc *storagev1.StorageClass) (*draiosproto.ContainerGroup, error) {
	cg, err := kubecollect_common.K8SObjectToCongroup(sc, DRAIOS_KIND, METRIC_PREFIX)

	if err != nil {
		return nil, err
	}

	cg.K8SObject = &draiosproto.K8SType{
		TypeList: &draiosproto.K8SType_Sc{
			Sc: &draiosproto.K8SStorageClass{
				Common:            kubecollect_common.K8sToDraiosCommon(sc),
				Created:           proto.Uint32(uint32(sc.CreationTimestamp.Unix())),
				Provisioner:       proto.String(sc.Provisioner),
				ReclaimPolicy:     getReclaimPolicy(sc),
				VolumeBindingMode: getVolumeBindingMode(sc),
			},
		},
	}
	return cg, nil
}

const (
	RESOURCE      = "storageclasses"
	RESTYPE       = "StorageClass"
	DRAIOS_KIND   = "k8s_storageclass"
	METRIC_PREFIX = "kubernetes.storageclass."
)

func storageClassEvent(sc *storagev1.StorageClass, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	newSc, err := newStorageClassConGroup(sc)

	if err != nil {
		log.Errorf(err.Error())
		return draiosproto.CongroupUpdateEvent{}
	}

	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newSc,
	}
}

func watchStorageClasses(evtc chan<- draiosproto.CongroupUpdateEvent) {
	storageClassInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived(RESOURCE)
				evtc <- storageClassEvent(obj.(*storagev1.StorageClass), draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent(RESTYPE, kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldStorageClass := oldObj.(*storagev1.StorageClass)
				newStorageClass := newObj.(*storagev1.StorageClass)
				if oldStorageClass.GetResourceVersion() != newStorageClass.GetResourceVersion() {
					evtc <- storageClassEvent(newStorageClass, draiosproto.CongroupEventType_UPDATED.Enum())
				}
				kubecollect_common.AddEvent(RESTYPE, kubecollect_common.EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldSC := (*storagev1.StorageClass)(nil)
				switch obj.(type) {
				case *storagev1.StorageClass:
					oldSC = obj.(*storagev1.StorageClass)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*storagev1.StorageClass)
					if ok {
						oldSC = o
					} else {
						log.Warn("DeletedFinalStateUnknown without storage class object")
					}
				default:
					log.Warn("Unknown object type in storage class DeleteFunc")
				}
				if oldSC == nil {
					return
				}

				evtc <- storageClassEvent(oldSC, draiosproto.CongroupEventType_REMOVED.Enum())
				kubecollect_common.AddEvent(RESTYPE, kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
