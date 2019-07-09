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
var dsSelectorCache *selectorCache

type coDaemonSet struct {
	*v1beta1.DaemonSet
}

func (ds coDaemonSet) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(ds.Spec.Selector)
	return s
}

func (ds coDaemonSet) Filtered() bool {
	return false
}

func (ds coDaemonSet) ActiveChildren() int32 {
	return ds.Status.CurrentNumberScheduled + ds.Status.NumberMisscheduled
}

func daemonSetEvent(ds coDaemonSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDaemonSetCongroup(ds, setLinks),
	}
}

func dsEquals(lhs coDaemonSet, rhs coDaemonSet) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
        EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

	if lhs.ActiveChildren() != rhs.ActiveChildren() {
		sameEntity = false
		// Update() the selector cache when we go from childless
		// to having children or vice versa
		if (lhs.ActiveChildren() == 0) || (rhs.ActiveChildren() == 0) {
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

func newDaemonSetCongroup(daemonSet coDaemonSet, setLinks bool) (*draiosproto.ContainerGroup) {
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
		selector, ok := dsSelectorCache.Get(daemonSet)
		if ok {
			AddPodChildren(&ret.Children, selector, daemonSet.GetNamespace())
		}
	}
	return ret
}

func addDaemonSetMetrics(metrics *[]*draiosproto.AppMetric, daemonSet coDaemonSet) {
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
		daemonSet := coDaemonSet{obj.(*v1beta1.DaemonSet)}
		if pod.GetNamespace() != daemonSet.GetNamespace() {
			continue
		}

		selector, ok := dsSelectorCache.Get(daemonSet)
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
	dsSelectorCache = newSelectorCache()
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
				evtc <- daemonSetEvent(coDaemonSet{obj.(*v1beta1.DaemonSet)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("DaemonSet", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("DaemonSet", EVENT_UPDATE)
				oldDS := coDaemonSet{oldObj.(*v1beta1.DaemonSet)}
				newDS := coDaemonSet{newObj.(*v1beta1.DaemonSet)}
				if oldDS.GetResourceVersion() == newDS.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := dsEquals(oldDS, newDS)
				if !sameLinks {
					dsSelectorCache.Update(newDS)
				}
				if !sameEntity || !sameLinks {
					evtc <- daemonSetEvent(newDS,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("DaemonSet", EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ds := coDaemonSet{nil}
				switch obj.(type) {
				case *v1beta1.DaemonSet:
					ds = coDaemonSet{obj.(*v1beta1.DaemonSet)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1beta1.DaemonSet)
					if ok {
						ds = coDaemonSet{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without daemonset object")
					}
				default:
					log.Warn("Unknown object type in daemonset DeleteFunc")
				}
				if ds.DaemonSet == nil {
					return
				}

				dsSelectorCache.Remove(ds)
				evtc <- daemonSetEvent(ds,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				addEvent("DaemonSet", EVENT_DELETE)
			},
		},
	)
}
