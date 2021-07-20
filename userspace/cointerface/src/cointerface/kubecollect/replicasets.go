package kubecollect

import (
	"cointerface/kubecollect_common"
	"k8s.io/apimachinery/pkg/types"
	draiosproto "protorepo/agent-be/proto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Globals are reset in startReplicaSetsSInformer
var replicaSetInf cache.SharedInformer
var FilterEmptyRs bool

type CoReplicaSet struct {
	*appsv1.ReplicaSet
}

func (rs CoReplicaSet) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(rs.Spec.Selector)
	return s
}

// Some common k8s practices leave a lot of old replicasets that have been
// scaled down to 0 pods in the spec. Those objects are rarely useful and
// can grow to a majority of the objects in the cluster, so we filter them
// out to keep load down in infra_state and the protobuf/backend.
func (rs CoReplicaSet) Filtered() bool {
	if FilterEmptyRs && rs.specReplicas() == 0 {
		return true
	}
	return false
}

func (rs CoReplicaSet) ActiveChildren() int32 {
	return rs.Status.Replicas
}

func (rs CoReplicaSet) specReplicas() int32 {
	if rs.Spec.Replicas == nil {
		return 1
	}
	return *rs.Spec.Replicas
}

func replicaSetEvent(rs CoReplicaSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(rs, setLinks),
	}
}

func replicaSetEquals(lhs CoReplicaSet, rhs CoReplicaSet) (bool, bool) {
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
			sameLinks = false;
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

func newReplicaSetCongroup(replicaSet CoReplicaSet, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicaset"),
			Id:proto.String(string(replicaSet.GetUID()))},
		Namespace:proto.String(replicaSet.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	ret.InternalTags = kubecollect_common.GetAnnotations(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	AddReplicaSetMetrics(&ret.Metrics, replicaSet)
	if setLinks {
		AddDeploymentParents(&ret.Parents, replicaSet)
		AddPodChildrenFromOwnerRef(&ret.Children, replicaSet.ObjectMeta)
		AddHorizontalPodAutoscalerParents(&ret.Parents, replicaSet.GetNamespace(), replicaSet.APIVersion, replicaSet.Kind, replicaSet.GetName() )
	}
	return ret
}

func AddReplicaSetMetrics(metrics *[]*draiosproto.AppMetric, replicaSet CoReplicaSet) {
	prefix := "kubernetes.replicaset."
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas", replicaSet.Status.Replicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.fullyLabeledReplicas", replicaSet.Status.FullyLabeledReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.readyReplicas", replicaSet.Status.ReadyReplicas)
	// Need to have unique key for replicas_running since we only set one protobuf field per metric in 
	// legacy_k8s_protobuf.c, and we want two protobuf fields with the ReadyReplicas value 
	// (replicas_running and replicas_ready).
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.runningReplicas", replicaSet.Status.ReadyReplicas)
	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"spec.replicas", replicaSet.Spec.Replicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.availableReplicas", replicaSet.Status.AvailableReplicas)
}

func AddReplicaSetChildren(children *[]*draiosproto.CongroupUid, selector labels.Selector, ns string, parentDeployment v1meta.ObjectMeta) {
	if !kubecollect_common.ResourceReady("replicasets") {
		return
	}

	childUid := types.UID("")
	for _, obj := range replicaSetInf.GetStore().List() {
		rs := obj.(*appsv1.ReplicaSet)
		for _, rsOwner := range rs.GetOwnerReferences() {
			if rsOwner.UID == parentDeployment.UID {
				childUid = rs.GetUID()
				break
			}
		}
		if childUid != "" {
			break
		}
	}

	if childUid == "" && selector != nil {
		for _, obj := range replicaSetInf.GetStore().List() {
			replicaSet := obj.(*appsv1.ReplicaSet)
			if replicaSet.GetNamespace() != ns {
				continue
			}

			if selector.Matches(labels.Set(replicaSet.GetLabels())) {
				childUid = replicaSet.GetUID()
			}
		}
	}

	if childUid != "" {
		*children = append(*children, &draiosproto.CongroupUid{
			Kind: proto.String("k8s_replicaset"),
			Id:   proto.String(string(childUid))})
	}
}

func AddReplicaSetChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !kubecollect_common.ResourceReady("replicasets") {
		return
	}

	for _, obj := range replicaSetInf.GetStore().List() {
		rs := obj.(*appsv1.ReplicaSet)
		if (rs.GetNamespace() == namespace) &&
			(rs.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(rs.GetUID()))})
		}
	}
}

func startReplicaSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	FilterEmptyRs = filterEmpty
	client := kubeClient.AppsV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicaSets", v1meta.NamespaceAll, fields.Everything())
	replicaSetInf = cache.NewSharedInformer(lw, &appsv1.ReplicaSet{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchReplicaSets(evtc)
		replicaSetInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchReplicaSets(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchReplicaSets()")

	replicaSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("replicasets")

				rs := CoReplicaSet{obj.(*appsv1.ReplicaSet)}
				if rs.Filtered() {
					return
				}

				evtc <- replicaSetEvent(rs,
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("ReplicaSet", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kubecollect_common.AddEvent("ReplicaSet", kubecollect_common.EVENT_UPDATE)
				oldRS := CoReplicaSet{oldObj.(*appsv1.ReplicaSet)}
				newRS := CoReplicaSet{newObj.(*appsv1.ReplicaSet)}
				if oldRS.GetResourceVersion() == newRS.GetResourceVersion() {
					return
				}

				newReplicas := newRS.specReplicas()
				oldReplicas := oldRS.specReplicas()
				if FilterEmptyRs && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if FilterEmptyRs && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicaSetEvent(newRS,
						draiosproto.CongroupEventType_ADDED.Enum(), true)
					kubecollect_common.AddEvent("ReplicaSet", kubecollect_common.EVENT_UPDATE_AND_SEND)
					return
				} else if FilterEmptyRs && oldReplicas > 0 && newReplicas == 0 {
					evtc <- draiosproto.CongroupUpdateEvent {
						Type: draiosproto.CongroupEventType_REMOVED.Enum(),
						Object: &draiosproto.ContainerGroup{
							Uid: &draiosproto.CongroupUid{
								Kind:proto.String("k8s_replicaset"),
								Id:proto.String(string(newRS.GetUID()))},
						},
					}
					kubecollect_common.AddEvent("ReplicaSet", kubecollect_common.EVENT_UPDATE_AND_SEND)
					return
				} else {
					sameEntity, sameLinks := replicaSetEquals(oldRS, newRS)
					if !sameEntity || !sameLinks {
						evtc <- replicaSetEvent(newRS,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
						kubecollect_common.AddEvent("ReplicaSet", kubecollect_common.EVENT_UPDATE_AND_SEND)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				rs := CoReplicaSet{nil}
				switch obj.(type) {
				case *appsv1.ReplicaSet:
					rs = CoReplicaSet{obj.(*appsv1.ReplicaSet)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*appsv1.ReplicaSet)
					if ok {
						rs = CoReplicaSet{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without replicaset object")
					}
				default:
					log.Warn("Unknown object type in replicaset DeleteFunc")
				}
				if rs.ReplicaSet == nil {
					return
				}

				if rs.Filtered() {
					return
				}

				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_replicaset"),
							Id:proto.String(string(rs.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("ReplicaSet", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
