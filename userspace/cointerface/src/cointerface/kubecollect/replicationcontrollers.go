package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"reflect"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/api/core/v1"
)

// Globals are reset in startReplicationControllersSInformer
var replicationControllerInf cache.SharedInformer
var rcSelectors map[string]labels.Selector
var rcCacheMutex sync.RWMutex
var filterEmptyRc bool

// make this a library function?
func replicationControllerEvent(rc *v1.ReplicationController, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicationControllerCongroup(rc, setLinks),
	}
}

func rcEquals(lhs *v1.ReplicationController, rhs *v1.ReplicationController) (bool, bool) {
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

func newReplicationControllerCongroup(replicationController *v1.ReplicationController, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicationcontroller"),
			Id:proto.String(string(replicationController.GetUID()))},
	}

	ret.Tags = GetTags(replicationController.ObjectMeta, "kubernetes.replicationController.")
	ret.InternalTags = GetAnnotations(replicationController.ObjectMeta, "kubernetes.replicationController.")
	addReplicationControllerMetrics(&ret.Metrics, replicationController)
	if setLinks {
		AddNSParents(&ret.Parents, replicationController.GetNamespace())
		selector, ok := getRcChildSelector(replicationController)
		if ok {
			AddPodChildren(&ret.Children, selector, replicationController.GetNamespace())
		}
		AddHorizontalPodAutoscalerParents(&ret.Parents, replicationController.GetNamespace(), replicationController.APIVersion, replicationController.Kind, replicationController.GetName() )
	}
	return ret
}

func addReplicationControllerMetrics(metrics *[]*draiosproto.AppMetric, replicationController *v1.ReplicationController) {
	prefix := "kubernetes.replicationController."
	AppendMetricInt32(metrics, prefix+"status.replicas", replicationController.Status.Replicas)
	AppendMetricInt32(metrics, prefix+"status.fullyLabeledReplicas", replicationController.Status.FullyLabeledReplicas)
	AppendMetricInt32(metrics, prefix+"status.readyReplicas", replicationController.Status.ReadyReplicas)
	AppendMetricInt32(metrics, prefix+"status.availableReplicas", replicationController.Status.AvailableReplicas)
	AppendMetricPtrInt32(metrics, prefix+"spec.replicas", replicationController.Spec.Replicas)
}

func AddReplicationControllerParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !resourceReady("replicationcontrollers") {
		return
	}

	podLabels := labels.Set(pod.GetLabels())
	for _, obj := range replicationControllerInf.GetStore().List() {
		replicationController := obj.(*v1.ReplicationController)
		if pod.GetNamespace() != replicationController.GetNamespace() {
			continue
		}
		selector, ok := getRcChildSelector(replicationController)
		if ok && selector.Matches(podLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(replicationController.GetUID()))})
			break
		}
	}
}

func AddReplicationControllerChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("replicationcontrollers") {
		return
	}

	for _, obj := range replicationControllerInf.GetStore().List() {
		replicationController := obj.(*v1.ReplicationController)
		if replicationController.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(replicationController.GetUID()))})
		}
	}
}

func AddReplicationControllerChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !resourceReady("replicationcontrollers") {
		return
	}

	for _, obj := range replicationControllerInf.GetStore().List() {
		rc := obj.(*v1.ReplicationController)
		if (rc.GetNamespace() == namespace) &&
			(rc.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(rc.GetUID()))})
		}
	}
}

func startReplicationControllersSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	rcSelectors = make(map[string]labels.Selector)
	filterEmptyRc = filterEmpty
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicationControllers", v1meta.NamespaceAll, fields.Everything())
	replicationControllerInf = cache.NewSharedInformer(lw, &v1.ReplicationController{}, RsyncInterval)

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
				eventReceived("replicationcontrollers")

				rc := obj.(*v1.ReplicationController)
				if rcFiltered(rc) {
					return
				}

				evtc <- replicationControllerEvent(rc,
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("ReplicationController", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("ReplicationController", EVENT_UPDATE)
				oldRC := oldObj.(*v1.ReplicationController)
				newRC := newObj.(*v1.ReplicationController)
				if oldRC.GetResourceVersion() == newRC.GetResourceVersion() {
					return
				}

				newReplicas := rcSpecReplicas(newRC)
				oldReplicas := rcSpecReplicas(oldRC)
				if filterEmptyRc && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if filterEmptyRc && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicationControllerEvent(newRC,
						draiosproto.CongroupEventType_ADDED.Enum(), true)
					addEvent("ReplicationController", EVENT_UPDATE_AND_SEND)
					return
				} else if filterEmptyRc && oldReplicas > 0 && newReplicas == 0 {
					clearRcSelectorCache(newRC)
					evtc <- draiosproto.CongroupUpdateEvent {
						Type: draiosproto.CongroupEventType_REMOVED.Enum(),
						Object: &draiosproto.ContainerGroup{
							Uid: &draiosproto.CongroupUid{
								Kind:proto.String("k8s_replicationcontroller"),
								Id:proto.String(string(newRC.GetUID()))},
						},
					}
					addEvent("ReplicationController", EVENT_UPDATE_AND_SEND)
					return
				} else {
					sameEntity, sameLinks := rcEquals(oldRC, newRC)
					if !sameLinks {
						updateRcSelectorCache(newRC)
					}
					if !sameEntity || !sameLinks {
						evtc <- replicationControllerEvent(newRC,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
						addEvent("ReplicationController", EVENT_UPDATE_AND_SEND)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				rc := (*v1.ReplicationController)(nil)
				switch obj.(type) {
				case *v1.ReplicationController:
					rc = obj.(*v1.ReplicationController)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.ReplicationController)
					if ok {
						rc = o
					} else {
						log.Warn("DeletedFinalStateUnknown without replicationcontroller object")
					}
				default:
					log.Warn("Unknown object type in replicationcontroller DeleteFunc")
				}
				if rc == nil {
					return
				}

				if rcFiltered(rc) {
					return
				}

				clearRcSelectorCache(rc)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_replicationcontroller"),
							Id:proto.String(string(rc.GetUID()))},
					},
				}
				addEvent("ReplicationController", EVENT_DELETE)
			},
		},
	)
}

func getRcChildSelector(rc *v1.ReplicationController) (labels.Selector, bool) {
	// RCs with Status.Replicas==0 (aka active) never go in the cache to keep
	// memory consumption down, and Spec.Replicas==0 RCs can be filtered by config
	//
	// We have to check for both instead of just status because
	// an rc can have >0 status and 0 spec just after scaling down
	if rcFiltered(rc) || rc.Status.Replicas == 0 {
		var zeroVal labels.Selector
		return zeroVal, false
	}

	rcCacheMutex.RLock()
	s, ok := rcSelectors[string(rc.GetUID())]
	rcCacheMutex.RUnlock()

	if !ok {
		s = populateRcSelectorCache(rc)
	}
	return s, true
}

func populateRcSelectorCache(rc *v1.ReplicationController) labels.Selector {
	// This is the cpu-heavy piece, so keep it outside the lock
	s := labels.Set(rc.Spec.Selector).AsSelector()

	rcCacheMutex.Lock()
	// It's possible another thread added the selector between
	// locks, but checking requires a second lookup in most cases
	// so always copy the newly created selector
	rcSelectors[string(rc.GetUID())] = s
	rcCacheMutex.Unlock()
	return s
}

func clearRcSelectorCache(rc *v1.ReplicationController) {
	rcCacheMutex.Lock()
	delete(rcSelectors, string(rc.GetUID()))
	rcCacheMutex.Unlock()
}

// If we know the selector will be used again,
// it's cheaper to update while we have the lock
func updateRcSelectorCache(rc *v1.ReplicationController) {
	if rc.Status.Replicas == 0 {
		clearRcSelectorCache(rc)
	} else {
		populateRcSelectorCache(rc)
	}
}

func rcSpecReplicas(rc *v1.ReplicationController) int32 {
	if rc.Spec.Replicas == nil {
		return 1
	}
	return *rc.Spec.Replicas
}

func rcFiltered(rc *v1.ReplicationController) bool {
	if filterEmptyRc && rcSpecReplicas(rc) == 0 {
		return true
	}
	return false
}
