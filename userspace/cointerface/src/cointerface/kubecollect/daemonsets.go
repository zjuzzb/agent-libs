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
	"k8s.io/api/core/v1"	
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/extensions/v1beta1"	
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
)

// Globals are reset in startDaemonSetsSInformer
var daemonSetInf cache.SharedInformer
var dsSelectors map[string]labels.Selector
var dsCacheMutex sync.RWMutex

func daemonSetEvent(ds *v1beta1.DaemonSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDaemonSetCongroup(ds, setLinks),
	}
}

func dsEquals(lhs *v1beta1.DaemonSet, rhs *v1beta1.DaemonSet) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
        EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

	if dsNumScheduled(lhs) != dsNumScheduled(rhs) {
		sameEntity = false
		if (dsNumScheduled(lhs) == 0) || (dsNumScheduled(rhs) == 0) {
			sameLinks = false
		}
	}

	if sameEntity {
		if (lhs.Status.CurrentNumberScheduled != rhs.Status.CurrentNumberScheduled) ||
			(lhs.Status.NumberMisscheduled != rhs.Status.NumberMisscheduled) ||
			(lhs.Status.DesiredNumberScheduled != rhs.Status.DesiredNumberScheduled) ||
			(lhs.Status.NumberReady != rhs.Status.NumberReady) {
		sameEntity = false
		}
	}

	if sameLinks && lhs.GetNamespace() != rhs.GetNamespace() {
		sameLinks = false
	}

	if sameLinks && !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		sameLinks = false
	}

	return sameEntity, sameLinks
}

func newDaemonSetCongroup(daemonSet *v1beta1.DaemonSet, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_daemonset"),
			Id:proto.String(string(daemonSet.GetUID()))},
	}

	ret.Tags = GetTags(daemonSet.ObjectMeta, "kubernetes.daemonSet.")
	ret.InternalTags = GetAnnotations(daemonSet.ObjectMeta, "kubernetes.daemonSet.")
	addDaemonSetMetrics(&ret.Metrics, daemonSet)
	if setLinks {
		AddNSParents(&ret.Parents, daemonSet.GetNamespace())
		selector, ok := getDsChildSelector(daemonSet)
		if ok {
			AddPodChildren(&ret.Children, selector, daemonSet.GetNamespace())
		}
	}
	return ret
}

func addDaemonSetMetrics(metrics *[]*draiosproto.AppMetric, daemonSet *v1beta1.DaemonSet) {
	prefix := "kubernetes.daemonSet."
	AppendMetricInt32(metrics, prefix+"status.currentNumberScheduled", daemonSet.Status.CurrentNumberScheduled)
	AppendMetricInt32(metrics, prefix+"status.numberMisscheduled", daemonSet.Status.NumberMisscheduled)
	AppendMetricInt32(metrics, prefix+"status.desiredNumberScheduled", daemonSet.Status.DesiredNumberScheduled)
	AppendMetricInt32(metrics, prefix+"status.numberReady", daemonSet.Status.NumberReady)
}

func AddDaemonSetParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !resourceReady("daemonsets") {
		return
	}

	podLabels := labels.Set(pod.GetLabels())
	for _, obj := range daemonSetInf.GetStore().List() {
		daemonSet := obj.(*v1beta1.DaemonSet)
		if pod.GetNamespace() != daemonSet.GetNamespace() {
			continue
		}

		selector, ok := getDsChildSelector(daemonSet)
		if ok && selector.Matches(podLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_daemonset"),
				Id:proto.String(string(daemonSet.GetUID()))})
			break
		}
	}
}

func AddDaemonSetChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("daemonsets") {
		return
	}

	for _, obj := range daemonSetInf.GetStore().List() {
		daemonSet := obj.(*v1beta1.DaemonSet)
		if daemonSet.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_daemonset"),
				Id:proto.String(string(daemonSet.GetUID()))})
		}
	}
}

func startDaemonSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	dsSelectors = make(map[string]labels.Selector)
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "DaemonSets", v1meta.NamespaceAll, fields.Everything())
	daemonSetInf = cache.NewSharedInformer(lw, &v1beta1.DaemonSet{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchDaemonSets(evtc)
		daemonSetInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchDaemonSets(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchDaemonSets()")

	daemonSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("daemonsets")
				//log.Debugf("AddFunc dumping DaemonSet: %v", obj.(*v1beta1.DaemonSet))
				evtc <- daemonSetEvent(obj.(*v1beta1.DaemonSet),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("DaemonSet", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("DaemonSet", EVENT_UPDATE)
				oldDS := oldObj.(*v1beta1.DaemonSet)
				newDS := newObj.(*v1beta1.DaemonSet)
				if oldDS.GetResourceVersion() == newDS.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := dsEquals(oldDS, newDS)
				if !sameLinks {
					updateDsSelectorCache(newDS)
				}
				if !sameEntity || !sameLinks {
					evtc <- daemonSetEvent(newDS,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("DaemonSet", EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ds := (*v1beta1.DaemonSet)(nil)
				switch obj.(type) {
				case *v1beta1.DaemonSet:
					ds = obj.(*v1beta1.DaemonSet)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1beta1.DaemonSet)
					if ok {
						ds = o
					} else {
						log.Warn("DeletedFinalStateUnknown without daemonset object")
					}
				default:
					log.Warn("Unknown object type in daemonset DeleteFunc")
				}
				if ds == nil {
					return
				}

				clearDsSelectorCache(ds)
				evtc <- daemonSetEvent(ds,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				addEvent("DaemonSet", EVENT_DELETE)
			},
		},
	)
}


func getDsChildSelector(ds *v1beta1.DaemonSet) (labels.Selector, bool) {
	// Only cache selectors for ds with pods currently scheduled
	if dsNumScheduled(ds) == 0 {
		var zeroVal labels.Selector
		return zeroVal, false
	}

	dsCacheMutex.RLock()
	s, ok := dsSelectors[string(ds.GetUID())]
	dsCacheMutex.RUnlock()

	if !ok {
		s = populateDsSelectorCache(ds)
	}
	return s, true
}

func populateDsSelectorCache(ds *v1beta1.DaemonSet) labels.Selector {
	// This is the cpu-heavy piece, so keep it outside the lock
	s, _ := v1meta.LabelSelectorAsSelector(ds.Spec.Selector)

	dsCacheMutex.Lock()
	// It's possible another thread added the selector between
	// locks, but checking requires a second lookup in most cases
	// so always copy the newly created selector
	dsSelectors[string(ds.GetUID())] = s
	dsCacheMutex.Unlock()
	return s
}

func clearDsSelectorCache(ds *v1beta1.DaemonSet) {
	dsCacheMutex.Lock()
	delete(dsSelectors, string(ds.GetUID()))
	dsCacheMutex.Unlock()
}

// If we know the selector will be used again,
// it's cheaper to update while we have the lock
func updateDsSelectorCache(ds *v1beta1.DaemonSet) {
	if dsNumScheduled(ds) == 0 {
		clearDsSelectorCache(ds)
	} else {
		populateDsSelectorCache(ds)
	}
}

func dsNumScheduled(ds *v1beta1.DaemonSet) int32 {
	return ds.Status.CurrentNumberScheduled + ds.Status.NumberMisscheduled
}
