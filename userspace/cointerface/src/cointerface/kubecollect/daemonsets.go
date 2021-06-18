package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"reflect"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Globals are reset in startDaemonSetsSInformer
var daemonSetInf cache.SharedInformer

type CoDaemonSet struct {
	*appsv1.DaemonSet
}

func (ds CoDaemonSet) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(ds.Spec.Selector)
	return s
}

func (ds CoDaemonSet) Filtered() bool {
	return false
}

func (ds CoDaemonSet) ActiveChildren() int32 {
	return ds.Status.CurrentNumberScheduled + ds.Status.NumberMisscheduled
}

func daemonSetEvent(ds CoDaemonSet, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newDaemonSetCongroup(ds, setLinks),
	}
}

func dsEquals(lhs CoDaemonSet, rhs CoDaemonSet) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
		kubecollect_common.EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

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

func newDaemonSetCongroup(daemonSet CoDaemonSet, setLinks bool) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_daemonset"),
			Id:   proto.String(string(daemonSet.GetUID()))},
		Namespace: proto.String(daemonSet.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(daemonSet.ObjectMeta, "kubernetes.daemonSet.")
	ret.InternalTags = kubecollect_common.GetAnnotations(daemonSet.ObjectMeta, "kubernetes.daemonSet.")
	AddDaemonSetMetrics(&ret.Metrics, daemonSet)
	if setLinks {
		AddPodChildrenFromOwnerRef(&ret.Children, daemonSet.ObjectMeta)
	}
	ret.LabelSelector = kubecollect_common.GetLabelSelector(*daemonSet.Spec.Selector)

	if daemonSet.Spec.Template.Labels != nil {
		if ret.PodTemplateLabels == nil {
			ret.PodTemplateLabels = make(map[string]string)
		}
		for key, val := range daemonSet.Spec.Template.Labels {
			ret.PodTemplateLabels[key] = val
		}
	}

	return ret
}

func AddDaemonSetMetrics(metrics *[]*draiosproto.AppMetric, daemonSet CoDaemonSet) {
	prefix := "kubernetes.daemonSet."
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.currentNumberScheduled", daemonSet.Status.CurrentNumberScheduled)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.numberMisscheduled", daemonSet.Status.NumberMisscheduled)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.desiredNumberScheduled", daemonSet.Status.DesiredNumberScheduled)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.numberReady", daemonSet.Status.NumberReady)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.numberAvailable", daemonSet.Status.NumberAvailable)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.numberUnavailable", daemonSet.Status.NumberUnavailable)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.updatedNumberScheduled", daemonSet.Status.UpdatedNumberScheduled)
}

func startDaemonSetsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.AppsV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "DaemonSets", v1meta.NamespaceAll, fields.Everything())
	daemonSetInf = cache.NewSharedInformer(lw, &appsv1.DaemonSet{}, kubecollect_common.RsyncInterval)

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
				kubecollect_common.EventReceived("daemonsets")
				//log.Debugf("AddFunc dumping DaemonSet: %v", obj.(*appsv1.DaemonSet))
				evtc <- daemonSetEvent(CoDaemonSet{obj.(*appsv1.DaemonSet)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_UPDATE)
				oldDS := CoDaemonSet{oldObj.(*appsv1.DaemonSet)}
				newDS := CoDaemonSet{newObj.(*appsv1.DaemonSet)}
				if oldDS.GetResourceVersion() == newDS.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := dsEquals(oldDS, newDS)
				if !sameEntity || !sameLinks {
					evtc <- daemonSetEvent(newDS,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ds := CoDaemonSet{nil}
				switch obj.(type) {
				case *appsv1.DaemonSet:
					ds = CoDaemonSet{obj.(*appsv1.DaemonSet)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*appsv1.DaemonSet)
					if ok {
						ds = CoDaemonSet{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without daemonset object")
					}
				default:
					log.Warn("Unknown object type in daemonset DeleteFunc")
				}
				if ds.DaemonSet == nil {
					return
				}

				evtc <- daemonSetEvent(ds,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				kubecollect_common.AddEvent("DaemonSet", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
