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

var persistentVolumesInf cache.SharedInformer

var metricPrefix = "kubernetes.persistentvolume."

func startPersistentVolumesInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "PersistentVolumes", v1meta.NamespaceAll, fields.Everything())
	persistentVolumesInf = cache.NewSharedInformer(lw, &v1.PersistentVolume{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchPersistentVolumes(evtc)
		persistentVolumesInf.Run(ctx.Done())
		wg.Done()
	}()
}


func persistentVolumeEvent(pv *v1.PersistentVolume, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newPersistentVolumeCongroup(pv),
	}
}

func getPersistentVolumeType(pv *v1.PersistentVolume) string {
	var ret string
	source := pv.Spec.PersistentVolumeSource

	if source.GCEPersistentDisk != nil {
		ret = "GCEPersistentDisk"
	} else if source.AWSElasticBlockStore != nil {
		ret = "AWSElasticBlockStore"
	} else if source.HostPath != nil {
		ret = "HostPath"
	} else if source.Glusterfs != nil {
		ret = "Glusterfs"
	} else if source.NFS != nil {
		ret = "NFS"
	} else if source.RBD != nil {
		ret = "RBD"
	} else if source.ISCSI != nil {
		ret = "ISCSI"
	} else if source.Cinder != nil {
		ret = "Cinder"
	} else if source.CephFS != nil {
		ret = "CephFS"
	} else if source.FC != nil {
		ret = "FC"
	} else if source.Flocker != nil {
		ret = "Flocker"
	} else if source.FlexVolume != nil {
		ret = "FlexVolume"
	} else if source.AzureFile != nil {
		ret = "AzureFile"
	} else if source.VsphereVolume != nil {
		ret = "VsphereVolume"
	} else if source.Quobyte != nil {
		ret = "Quobyte"
	} else if source.AzureDisk != nil {
		ret = "AzureDisk"
	} else if source.PhotonPersistentDisk != nil {
		ret = "PhotonPersistentDisk"
	} else if source.PortworxVolume != nil {
		ret = "PortworxVolume"
	} else if source.ScaleIO != nil {
		ret = "ScaleIO"
	} else if source.Local != nil {
		ret = "Local"
	} else if source.StorageOS != nil {
		ret = "StorageOS"
	}

	return ret
}

func newPersistentVolumeCongroup(pv *v1.PersistentVolume) (*draiosproto.ContainerGroup) {
	label_tag_name := metricPrefix + "label."
	internal_tag_name := metricPrefix + "label."

	tags := make(map[string]string)
	for k, v := range pv.GetLabels() {
		tags[label_tag_name+ k] = v
	}

	inttags := GetAnnotations(pv.ObjectMeta, internal_tag_name)
	tags[internal_tag_name+ "storageclass"] = pv.Spec.StorageClassName
	tags[internal_tag_name+ "status.phase"] = string(pv.Status.Phase)
	tags[internal_tag_name+ "claim"] = pv.Spec.ClaimRef.Name
	tags[internal_tag_name+ "reclaimpolicy"] = string(pv.Spec.PersistentVolumeReclaimPolicy)

	var accessMode string
	for _, v := range pv.Spec.AccessModes {
		accessMode += string(v)
	}

	tags[internal_tag_name+ "accessmode"] = string(accessMode)

	tags[internal_tag_name+"source.type"] = getPersistentVolumeType(pv)

	tags[metricPrefix + "name"] = pv.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_persistentvolume"),
			Id:proto.String(string(pv.GetUID()))},
		Tags: tags,
		InternalTags: inttags,
	}

	addPersistentVolumeMetrics(&ret.Metrics, pv)
	return ret
}

func addPersistentVolumeMetrics(metrics *[]*draiosproto.AppMetric, pv *v1.PersistentVolume) {
	size, _ := pv.Spec.Capacity["storage"]
	AppendMetricInt64(metrics, metricPrefix+"storage", size.Value())

	// A cluster-wide count of PVs. the usual namespace-wide count does not apply
	// for PV as it is not bound to any namespace
	AppendMetricInt32(metrics, metricPrefix+"count", 1)
}

func watchPersistentVolumes(evtc chan <- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In Watchpersistentvolumes()")

	persistentVolumesInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("persistentvolumes")
				log.Debugf("DEBUG PV: %v", obj.(*v1.PersistentVolume))
				evtc <- persistentVolumeEvent(obj.(*v1.PersistentVolume),
					draiosproto.CongroupEventType_ADDED.Enum())
				addEvent("PersistentVolume", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldPersistentVolume := oldObj.(*v1.PersistentVolume)
				newPersistentVolume := newObj.(*v1.PersistentVolume)
				if oldPersistentVolume.GetResourceVersion() != newPersistentVolume.GetResourceVersion() {
					evtc <- persistentVolumeEvent(newPersistentVolume,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
				addEvent("PersistentVolume", EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				evtc <- persistentVolumeEvent(obj.(*v1.PersistentVolume),
					draiosproto.CongroupEventType_REMOVED.Enum())
				addEvent("PersistentVolume", EVENT_DELETE)
			},
		},
	)
}
