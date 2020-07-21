package kubecollect

import (
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
var filterEmptyRs bool

type coReplicaSet struct {
	*appsv1.ReplicaSet
}

func (rs coReplicaSet) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(rs.Spec.Selector)
	return s
}

// Some common k8s practices leave a lot of old replicasets that have been
// scaled down to 0 pods in the spec. Those objects are rarely useful and
// can grow to a majority of the objects in the cluster, so we filter them
// out to keep load down in infra_state and the protobuf/backend.
func (rs coReplicaSet) Filtered() bool {
	if filterEmptyRs && rs.specReplicas() == 0 {
		return true
	}
	return false
}

func (rs coReplicaSet) ActiveChildren() int32 {
	return rs.Status.Replicas
}

func (rs coReplicaSet) specReplicas() int32 {
	if rs.Spec.Replicas == nil {
		return 1
	}
	return *rs.Spec.Replicas
}

func replicaSetEvent(rs coReplicaSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(rs, setLinks),
	}
}

func replicaSetEquals(lhs coReplicaSet, rhs coReplicaSet) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
        EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

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

func newReplicaSetCongroup(replicaSet coReplicaSet, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicaset"),
			Id:proto.String(string(replicaSet.GetUID()))},
		Namespace:proto.String(replicaSet.GetNamespace()),
	}

	ret.Tags = GetTags(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	ret.InternalTags = GetAnnotations(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	addReplicaSetMetrics(&ret.Metrics, replicaSet)
	if setLinks {
		AddDeploymentParents(&ret.Parents, replicaSet)
		AddPodChildrenFromOwnerRef(&ret.Children, replicaSet.ObjectMeta)
		AddHorizontalPodAutoscalerParents(&ret.Parents, replicaSet.GetNamespace(), replicaSet.APIVersion, replicaSet.Kind, replicaSet.GetName() )
	}
	return ret
}

func addReplicaSetMetrics(metrics *[]*draiosproto.AppMetric, replicaSet coReplicaSet) {
	prefix := "kubernetes.replicaset."
	AppendMetricInt32(metrics, prefix+"status.replicas", replicaSet.Status.ReadyReplicas)
	AppendMetricInt32(metrics, prefix+"status.fullyLabeledReplicas", replicaSet.Status.FullyLabeledReplicas)
	AppendMetricInt32(metrics, prefix+"status.readyReplicas", replicaSet.Status.ReadyReplicas)
	AppendMetricPtrInt32(metrics, prefix+"spec.replicas", replicaSet.Spec.Replicas)
}

func AddReplicaSetChildren(children *[]*draiosproto.CongroupUid, selector labels.Selector, ns string) {
	if !resourceReady("replicasets") {
		return
	}

	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*appsv1.ReplicaSet)
		if replicaSet.GetNamespace() != ns {
			continue
		}

		if selector.Matches(labels.Set(replicaSet.GetLabels())) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(replicaSet.GetUID()))})
		}
	}
}

func AddReplicaSetChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !resourceReady("replicasets") {
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
	filterEmptyRs = filterEmpty
	client := kubeClient.AppsV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicaSets", v1meta.NamespaceAll, fields.Everything())
	replicaSetInf = cache.NewSharedInformer(lw, &appsv1.ReplicaSet{}, RsyncInterval)

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
				eventReceived("replicasets")

				rs := coReplicaSet{obj.(*appsv1.ReplicaSet)}
				if rs.Filtered() {
					return
				}

				evtc <- replicaSetEvent(rs,
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("ReplicaSet", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("ReplicaSet", EVENT_UPDATE)
				oldRS := coReplicaSet{oldObj.(*appsv1.ReplicaSet)}
				newRS := coReplicaSet{newObj.(*appsv1.ReplicaSet)}
				if oldRS.GetResourceVersion() == newRS.GetResourceVersion() {
					return
				}

				newReplicas := newRS.specReplicas()
				oldReplicas := oldRS.specReplicas()
				if filterEmptyRs && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if filterEmptyRs && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicaSetEvent(newRS,
						draiosproto.CongroupEventType_ADDED.Enum(), true)
					addEvent("ReplicaSet", EVENT_UPDATE_AND_SEND)
					return
				} else if filterEmptyRs && oldReplicas > 0 && newReplicas == 0 {
					evtc <- draiosproto.CongroupUpdateEvent {
						Type: draiosproto.CongroupEventType_REMOVED.Enum(),
						Object: &draiosproto.ContainerGroup{
							Uid: &draiosproto.CongroupUid{
								Kind:proto.String("k8s_replicaset"),
								Id:proto.String(string(newRS.GetUID()))},
						},
					}
					addEvent("ReplicaSet", EVENT_UPDATE_AND_SEND)
					return
				} else {
					sameEntity, sameLinks := replicaSetEquals(oldRS, newRS)
					if !sameEntity || !sameLinks {
						evtc <- replicaSetEvent(newRS,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
						addEvent("ReplicaSet", EVENT_UPDATE_AND_SEND)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				rs := coReplicaSet{nil}
				switch obj.(type) {
				case *appsv1.ReplicaSet:
					rs = coReplicaSet{obj.(*appsv1.ReplicaSet)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*appsv1.ReplicaSet)
					if ok {
						rs = coReplicaSet{o}
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
				addEvent("ReplicaSet", EVENT_DELETE)
			},
		},
	)
}
