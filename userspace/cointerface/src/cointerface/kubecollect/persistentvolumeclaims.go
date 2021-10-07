package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	draiosproto "protorepo/agent-be/proto"
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

func persistentVolumeClaimEvent(pv *v1.PersistentVolumeClaim, eventType *draiosproto.CongroupEventType) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newPersistentVolumeClaimCongroup(pv),
	}
}

func phaseToDraiosEnum(phase *v1.PersistentVolumeClaimPhase) (error, draiosproto.K8SPersistentvolumeclaimPhase) {
	switch *phase {
	case v1.ClaimPending:
		return nil, draiosproto.K8SPersistentvolumeclaimPhase_PERSISTENT_VOLUME_CLAIM_PHASE_PENDING
	case v1.ClaimBound:
		return nil, draiosproto.K8SPersistentvolumeclaimPhase_PERSISTENT_VOLUME_CLAIM_PHASE_BOUND
	case v1.ClaimLost:
		return nil, draiosproto.K8SPersistentvolumeclaimPhase_PERSISTENT_VOLUME_CLAIM_PHASE_LOST
	}

	return fmt.Errorf("invalid pvc phase: %s", *phase), draiosproto.K8SPersistentvolumeclaimPhase_PERSISTENT_VOLUME_CLAIM_PHASE_LOST
}

func conditionStatusToDraiosEnum(status *v1.ConditionStatus) (error, draiosproto.K8SPersistentvolumeclaimConditionStatus) {
	switch *status {
	case v1.ConditionTrue:
		return nil, draiosproto.K8SPersistentvolumeclaimConditionStatus_PERSISTENT_VOLUME_CLAIM_CONDITION_STATUS_TRUE
	case v1.ConditionFalse:
		return nil, draiosproto.K8SPersistentvolumeclaimConditionStatus_PERSISTENT_VOLUME_CLAIM_CONDITION_STATUS_FALSE
	case v1.ConditionUnknown:
		return nil, draiosproto.K8SPersistentvolumeclaimConditionStatus_PERSISTENT_VOLUME_CLAIM_CONDITION_STATUS_UNKNOWN
	}

	return fmt.Errorf("invalid pvc condition status: %s", *status), draiosproto.K8SPersistentvolumeclaimConditionStatus_PERSISTENT_VOLUME_CLAIM_CONDITION_STATUS_UNKNOWN
}

func accessModeToDraiosEnum(mode *v1.PersistentVolumeAccessMode) (error, draiosproto.K8SVolumeAccessMode) {
	switch *mode {
	case v1.ReadWriteOnce:
		return nil, draiosproto.K8SVolumeAccessMode_VOLUME_ACCESS_MODE_READ_WRITE_ONCE
	case v1.ReadWriteMany:
		return nil, draiosproto.K8SVolumeAccessMode_VOLUME_ACCESS_MODE_READ_WRITE_MANY
	case v1.ReadOnlyMany:
		return nil, draiosproto.K8SVolumeAccessMode_VOLUME_ACCESS_MODE_READ_ONLY_MANY
	}
	return fmt.Errorf("invalid pvc access mode: %s", *mode), draiosproto.K8SVolumeAccessMode_VOLUME_ACCESS_MODE_READ_ONLY_MANY
}

func getMetaData(pvc *v1.PersistentVolumeClaim) *draiosproto.K8SPersistentvolumeclaim {
	ret := &draiosproto.K8SPersistentvolumeclaim{Common: kubecollect_common.CreateCommon("", "")}
	err, phase := phaseToDraiosEnum(&pvc.Status.Phase)
	if err != nil {
		log.Warnf(err.Error())
	} else {
		ret.Status = &draiosproto.K8SPersistentvolumeclaimStatusDetails{
			Phase: &phase,
		}
	}

	for _, condition := range pvc.Status.Conditions {
		err, status := conditionStatusToDraiosEnum(&condition.Status)
		if err != nil {
			log.Warnf(err.Error())
		} else {
			newCondition := &draiosproto.K8SPersistentvolumeclaimCondition{
				Status: &status,
				Type:   proto.String(string(condition.Type)),
			}
			ret.Status.Conditions = append(ret.Status.Conditions, newCondition)
		}
	}

	for _, accessMode := range pvc.Status.AccessModes {
		err, mode := accessModeToDraiosEnum(&accessMode)
		if err != nil {
			log.Warnf(err.Error())
		} else {
			ret.AccessModes = append(ret.AccessModes, mode)
		}

	}
	return ret
}

func newPersistentVolumeClaimCongroup(pvc *v1.PersistentVolumeClaim) *draiosproto.ContainerGroup {
	label_tag_name := pvcMetricPrefix + "label."
	internal_tag_name := pvcMetricPrefix + "label."

	tags := make(map[string]string)
	for k, v := range pvc.GetLabels() {
		tags[label_tag_name+k] = v
	}

	var accessMode string
	for _, v := range pvc.Spec.AccessModes {
		accessMode += string(v)
	}

	tags[internal_tag_name+"accessmode"] = string(accessMode)

	tags[internal_tag_name+"volumename"] = pvc.Spec.VolumeName

	if pvc.Spec.StorageClassName != nil {
		tags[internal_tag_name+"storageclassname"] = *pvc.Spec.StorageClassName
	}

	tags[internal_tag_name+"status.phase"] = string(pvc.Status.Phase)
	storage := pvc.Status.Capacity["storage"]
	tags[internal_tag_name+"storage"] = storage.String()
	tags[pvcMetricPrefix+"name"] = pvc.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_persistentvolumeclaim"),
			Id:   proto.String(string(pvc.GetUID()))},
		Tags: tags,
		K8SObject: &draiosproto.K8SType{
			TypeList: &draiosproto.K8SType_Pvc{Pvc: getMetaData(pvc)},
		},
		Namespace: proto.String(pvc.GetNamespace()),
	}

	addPersistentVolumeClaimMetrics(&ret.Metrics, pvc)

	return ret
}

func addPersistentVolumeClaimMetrics(metrics *[]*draiosproto.AppMetric, pvc *v1.PersistentVolumeClaim) {
	storage, _ := pvc.Status.Capacity["storage"]

	if requestStorage, ok := pvc.Spec.Resources.Requests[v1.ResourceStorage]; ok {
		kubecollect_common.AppendMetricInt64(metrics, pvcMetricPrefix+"requests.storage", requestStorage.Value())
	}

	kubecollect_common.AppendMetricInt64(metrics, pvcMetricPrefix+"storage", storage.Value())
}

func watchPersistentVolumeClaims(evtc chan<- draiosproto.CongroupUpdateEvent) {
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
