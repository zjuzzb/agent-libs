package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/api/core/v1"
)

// Globals are reset in startReplicaSetsSInformer
var replicaSetInf cache.SharedInformer
var rsSelectors map[string]labels.Selector
var rsCacheMutex sync.RWMutex
var filterEmptyRs bool

func replicaSetEvent(rs *v1beta1.ReplicaSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(rs, setLinks),
	}
}

func replicaSetEquals(lhs *v1beta1.ReplicaSet, rhs *v1beta1.ReplicaSet) (bool, bool) {
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

func newReplicaSetCongroup(replicaSet *v1beta1.ReplicaSet, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicaset"),
			Id:proto.String(string(replicaSet.GetUID()))},
	}

	ret.Tags = GetTags(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	ret.InternalTags = GetAnnotations(replicaSet.ObjectMeta, "kubernetes.replicaSet.")
	addReplicaSetMetrics(&ret.Metrics, replicaSet)
	if setLinks {
		AddNSParents(&ret.Parents, replicaSet.GetNamespace())
		AddDeploymentParents(&ret.Parents, replicaSet)
		selector, ok := getRsChildSelector(replicaSet)
		if ok {
			AddPodChildren(&ret.Children, selector, replicaSet.GetNamespace())
		}
		AddHorizontalPodAutoscalerParents(&ret.Parents, replicaSet.GetNamespace(), replicaSet.APIVersion, replicaSet.Kind, replicaSet.GetName() )
	}
	return ret
}

func addReplicaSetMetrics(metrics *[]*draiosproto.AppMetric, replicaSet *v1beta1.ReplicaSet) {
	prefix := "kubernetes.replicaset."
	AppendMetricInt32(metrics, prefix+"status.replicas", replicaSet.Status.Replicas)
	AppendMetricInt32(metrics, prefix+"status.fullyLabeledReplicas", replicaSet.Status.FullyLabeledReplicas)
	AppendMetricInt32(metrics, prefix+"status.readyReplicas", replicaSet.Status.ReadyReplicas)
	AppendMetricPtrInt32(metrics, prefix+"spec.replicas", replicaSet.Spec.Replicas)
}

func AddReplicaSetParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !resourceReady("replicasets") {
		return
	}

	podLabels := labels.Set(pod.GetLabels())
	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		if pod.GetNamespace() != replicaSet.GetNamespace() {
			continue
		}

		selector, ok := getRsChildSelector(replicaSet)
		if ok && selector.Matches(podLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(replicaSet.GetUID()))})
			break
		}
	}
}

func AddReplicaSetChildren(children *[]*draiosproto.CongroupUid, selector labels.Selector, ns string) {
	if !resourceReady("replicasets") {
		return
	}

	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
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

func AddReplicaSetChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("replicasets") {
		return
	}

	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		if replicaSet.GetNamespace() == namespaceName {
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
		rs := obj.(*v1beta1.ReplicaSet)
		if (rs.GetNamespace() == namespace) &&
			(rs.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
				Id:proto.String(string(rs.GetUID()))})
		}
	}
}

func startReplicaSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	rsSelectors = make(map[string]labels.Selector)
	filterEmptyRs = filterEmpty
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicaSets", v1meta.NamespaceAll, fields.Everything())
	replicaSetInf = cache.NewSharedInformer(lw, &v1beta1.ReplicaSet{}, RsyncInterval)

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

				rs := obj.(*v1beta1.ReplicaSet)
				if rsFiltered(rs) {
					return
				}

				evtc <- replicaSetEvent(rs,
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("ReplicaSet", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("ReplicaSet", EVENT_UPDATE)
				oldRS := oldObj.(*v1beta1.ReplicaSet)
				newRS := newObj.(*v1beta1.ReplicaSet)
				if oldRS.GetResourceVersion() == newRS.GetResourceVersion() {
					return
				}

				newReplicas := rsSpecReplicas(newRS)
				oldReplicas := rsSpecReplicas(oldRS)
				if filterEmptyRs && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if filterEmptyRs && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicaSetEvent(newRS,
						draiosproto.CongroupEventType_ADDED.Enum(), true)
					addEvent("ReplicaSet", EVENT_UPDATE_AND_SEND)
					return
				} else if filterEmptyRs && oldReplicas > 0 && newReplicas == 0 {
					clearRsSelectorCache(newRS)
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
					if !sameLinks {
						updateRsSelectorCache(newRS)
					}
					if !sameEntity || !sameLinks {
						evtc <- replicaSetEvent(newRS,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
						addEvent("ReplicaSet", EVENT_UPDATE_AND_SEND)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				rs := (*v1beta1.ReplicaSet)(nil)
				switch obj.(type) {
				case *v1beta1.ReplicaSet:
					rs = obj.(*v1beta1.ReplicaSet)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1beta1.ReplicaSet)
					if ok {
						rs = o
					} else {
						log.Warn("DeletedFinalStateUnknown without replicaset object")
					}
				default:
					log.Warn("Unknown object type in replicaset DeleteFunc")
				}
				if rs == nil {
					return
				}

				if rsFiltered(rs) {
					return
				}

				clearRsSelectorCache(rs)
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

func getRsChildSelector(rs *v1beta1.ReplicaSet) (labels.Selector, bool) {
	// RSs with Status.Replicas==0 (aka active) never go in the cache to keep
	// memory consumption down, and Spec.Replicas==0 RSs can be filtered by config
	//
	// We have to check for both instead of just status because
	// an rs can have >0 status and 0 spec just after scaling down
	if rsFiltered(rs) || rs.Status.Replicas == 0 {
		var zeroVal labels.Selector
		return zeroVal, false
	}

	rsCacheMutex.RLock()
	s, ok := rsSelectors[string(rs.GetUID())]
	rsCacheMutex.RUnlock()

	if !ok {
		s = populateRsSelectorCache(rs)
	}
	return s, true
}

func populateRsSelectorCache(rs *v1beta1.ReplicaSet) labels.Selector {
	// This is the cpu-heavy piece, so keep it outside the lock
	s, _ := v1meta.LabelSelectorAsSelector(rs.Spec.Selector)

	rsCacheMutex.Lock()
	// It's possible another thread added the selector between
	// locks, but checking requires a second lookup in most cases
	// so always copy the newly created selector
	rsSelectors[string(rs.GetUID())] = s
	rsCacheMutex.Unlock()
	return s
}

func clearRsSelectorCache(rs *v1beta1.ReplicaSet) {
	rsCacheMutex.Lock()
	delete(rsSelectors, string(rs.GetUID()))
	rsCacheMutex.Unlock()
}

// If we know the selector will be used again,
// it's cheaper to update while we have the lock
func updateRsSelectorCache(rs *v1beta1.ReplicaSet) {
	if rs.Status.Replicas == 0 {
		clearRsSelectorCache(rs)
	} else {
		populateRsSelectorCache(rs)
	}
}

func rsSpecReplicas(rs *v1beta1.ReplicaSet) int32 {
	if rs.Spec.Replicas == nil {
		return 1
	}
	return *rs.Spec.Replicas
}

func rsFiltered(rs *v1beta1.ReplicaSet) bool {
	if filterEmptyRs && rsSpecReplicas(rs) == 0 {
		return true
	}
	return false
}
