package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"reflect"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Globals are reset in startReplicationControllersSInformer
var replicationControllerInf cache.SharedInformer
var filterEmptyRc bool

type CoReplicationController struct {
	*v1.ReplicationController
}

func (rc CoReplicationController) Selector() labels.Selector {
	return labels.Set(rc.Spec.Selector).AsSelector()
}

// Some common k8s practices leave a lot of old rc's that have been
// scaled down to 0 pods in the spec. Those objects are rarely useful and
// can grow to a majority of the objects in the cluster, so we filter them
// out to keep load down in infra_state and the protobuf/backend.
func (rc CoReplicationController) Filtered() bool {
	if filterEmptyRc && rc.specReplicas() == 0 {
		return true
	}
	return false
}

func (rc CoReplicationController) ActiveChildren() int32 {
	return rc.Status.Replicas
}

func (rc CoReplicationController) specReplicas() int32 {
	if rc.Spec.Replicas == nil {
		return 1
	}
	return *rc.Spec.Replicas
}

// make this a library function?
func replicationControllerEvent(rc CoReplicationController, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newReplicationControllerCongroup(rc, setLinks),
	}
}

func rcEquals(lhs CoReplicationController, rhs CoReplicationController) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
		kubecollect_common.EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

	if lhs.Status.Replicas != rhs.Status.Replicas {
		sameEntity = false
		if (lhs.Status.Replicas == 0) || (rhs.Status.Replicas == 0) {
			sameLinks = false
		}
	}

	if sameEntity {
		if (lhs.Status.FullyLabeledReplicas != rhs.Status.FullyLabeledReplicas) ||
			(lhs.Status.ReadyReplicas != rhs.Status.ReadyReplicas) {
			sameEntity = false
		}
	}

	if sameEntity && ((lhs.Spec.Replicas == nil && rhs.Spec.Replicas != nil) ||
		(lhs.Spec.Replicas != nil && rhs.Spec.Replicas == nil)) {
		sameEntity = false
	}

	if sameEntity && (lhs.Spec.Replicas != nil && uint32(*lhs.Spec.Replicas) != uint32(*rhs.Spec.Replicas)) {
		sameEntity = false
	}

	if sameLinks && lhs.GetNamespace() != rhs.GetNamespace() {
		sameLinks = false
	}

	if sameLinks && !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		sameLinks = false
	}

	return sameEntity, sameLinks
}

func newReplicationControllerCongroup(replicationController CoReplicationController, setLinks bool) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_replicationcontroller"),
			Id:   proto.String(string(replicationController.GetUID()))},
		Namespace: proto.String(replicationController.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(replicationController, "kubernetes.replicationController.")
	ret.InternalTags = kubecollect_common.GetAnnotations(replicationController.ObjectMeta, "kubernetes.replicationController.")
	AddReplicationControllerMetrics(&ret.Metrics, replicationController)
	if setLinks {
		AddPodChildrenFromOwnerRef(&ret.Children, replicationController.ObjectMeta)
		AddHorizontalPodAutoscalerParents(&ret.Parents, replicationController.GetNamespace(), replicationController.APIVersion, replicationController.Kind, replicationController.GetName())
	}
	return ret
}

func AddReplicationControllerMetrics(metrics *[]*draiosproto.AppMetric, replicationController CoReplicationController) {
	prefix := "kubernetes.replicationController."
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas", replicationController.Status.Replicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.fullyLabeledReplicas", replicationController.Status.FullyLabeledReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.readyReplicas", replicationController.Status.ReadyReplicas)
	// Need to have unique key for replicas_running since we only set one protobuf field per metric in
	// legacy_k8s_protobuf.c, and we want two protobuf fields with the ReadyReplicas value
	// (replicas_running and replicas_ready).
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.runningReplicas", replicationController.Status.ReadyReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.availableReplicas", replicationController.Status.AvailableReplicas)
	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"spec.replicas", replicationController.Spec.Replicas)
}

func AddReplicationControllerChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !kubecollect_common.ResourceReady("replicationcontrollers") {
		return
	}

	for _, obj := range replicationControllerInf.GetStore().List() {
		rc := obj.(*v1.ReplicationController)
		if (rc.GetNamespace() == namespace) &&
			(rc.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind: proto.String("k8s_replicationcontroller"),
				Id:   proto.String(string(rc.GetUID()))})
		}
	}
}

func startReplicationControllersSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	filterEmptyRc = filterEmpty
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicationControllers", v1meta.NamespaceAll, fields.Everything())
	replicationControllerInf = cache.NewSharedInformer(lw, &v1.ReplicationController{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchReplicationControllers(evtc)
		replicationControllerInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchReplicationControllers(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchReplicationControllers()")

	replicationControllerInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("replicationcontrollers")

				rc := CoReplicationController{obj.(*v1.ReplicationController)}
				if rc.Filtered() {
					return
				}

				evtc <- replicationControllerEvent(rc,
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("ReplicationController", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kubecollect_common.AddEvent("ReplicationController", kubecollect_common.EVENT_UPDATE)
				oldRC := CoReplicationController{oldObj.(*v1.ReplicationController)}
				newRC := CoReplicationController{newObj.(*v1.ReplicationController)}
				if oldRC.GetResourceVersion() == newRC.GetResourceVersion() {
					return
				}

				newReplicas := newRC.specReplicas()
				oldReplicas := oldRC.specReplicas()
				if filterEmptyRc && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if filterEmptyRc && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicationControllerEvent(newRC,
						draiosproto.CongroupEventType_ADDED.Enum(), true)
					kubecollect_common.AddEvent("ReplicationController", kubecollect_common.EVENT_UPDATE_AND_SEND)
					return
				} else if filterEmptyRc && oldReplicas > 0 && newReplicas == 0 {
					evtc <- draiosproto.CongroupUpdateEvent{
						Type: draiosproto.CongroupEventType_REMOVED.Enum(),
						Object: &draiosproto.ContainerGroup{
							Uid: &draiosproto.CongroupUid{
								Kind: proto.String("k8s_replicationcontroller"),
								Id:   proto.String(string(newRC.GetUID()))},
						},
					}
					kubecollect_common.AddEvent("ReplicationController", kubecollect_common.EVENT_UPDATE_AND_SEND)
					return
				} else {
					sameEntity, sameLinks := rcEquals(oldRC, newRC)
					if !sameEntity || !sameLinks {
						evtc <- replicationControllerEvent(newRC,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
						kubecollect_common.AddEvent("ReplicationController", kubecollect_common.EVENT_UPDATE_AND_SEND)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				rc := CoReplicationController{nil}
				switch obj.(type) {
				case *v1.ReplicationController:
					rc = CoReplicationController{obj.(*v1.ReplicationController)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.ReplicationController)
					if ok {
						rc = CoReplicationController{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without replicationcontroller object")
					}
				default:
					log.Warn("Unknown object type in replicationcontroller DeleteFunc")
				}
				if rc.ReplicationController == nil {
					return
				}

				if rc.Filtered() {
					return
				}

				evtc <- draiosproto.CongroupUpdateEvent{
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind: proto.String("k8s_replicationcontroller"),
							Id:   proto.String(string(rc.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("ReplicationController", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
