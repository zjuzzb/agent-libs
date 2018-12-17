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

func replicaSetEvent(rs *v1beta1.ReplicaSet, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicaSetCongroup(rs, setLinks),
	}
}

func replicaSetEquals(lhs *v1beta1.ReplicaSet, rhs *v1beta1.ReplicaSet) (bool, bool) {
	in := true
	out := true

	if lhs.GetName() != rhs.GetName() {
		in = false
	}

	in = in && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) &&
        EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta)

	if in {
		if (lhs.Status.Replicas != rhs.Status.Replicas) ||
			(lhs.Status.FullyLabeledReplicas != rhs.Status.FullyLabeledReplicas) ||
			(lhs.Status.ReadyReplicas != rhs.Status.ReadyReplicas) {
		in = false
		}
	}

	if in && ((lhs.Spec.Replicas == nil && rhs.Spec.Replicas != nil) ||
		(lhs.Spec.Replicas != nil && rhs.Spec.Replicas == nil)) {
		in = false
	}

	if in && (lhs.Spec.Replicas != nil && uint32(*lhs.Spec.Replicas) != uint32(*rhs.Spec.Replicas)) {
		in = false
	}

	if lhs.GetNamespace() != rhs.GetNamespace() {
		out = false
	}

	if lhs.Spec.Selector != nil && rhs.Spec.Selector != nil &&
		!reflect.DeepEqual(lhs.Spec.Selector.MatchLabels, rhs.Spec.Selector.MatchLabels) {
		out = false
	}

	return in, out
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
		selector, _ := v1meta.LabelSelectorAsSelector(replicaSet.Spec.Selector)
		AddPodChildren(&ret.Children, selector, replicaSet.GetNamespace())
		AddHorizontalPodAutoscalerParents(&ret.Parents, replicaSet.GetNamespace(), replicaSet.APIVersion, replicaSet.Kind, replicaSet.GetName() )
	}
	return ret
}

var replicaSetInf cache.SharedInformer

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

	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector, _ := v1meta.LabelSelectorAsSelector(replicaSet.Spec.Selector)
		if pod.GetNamespace() == replicaSet.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicaset"),
					Id:proto.String(string(replicaSet.GetUID()))})
		}
	}
}

func AddReplicaSetChildren(children *[]*draiosproto.CongroupUid, deployment *v1beta1.Deployment) {
	if !resourceReady("replicasets") {
		return
	}

	for _, obj := range replicaSetInf.GetStore().List() {
		replicaSet := obj.(*v1beta1.ReplicaSet)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector, _ := v1meta.LabelSelectorAsSelector(deployment.Spec.Selector)
		if replicaSet.GetNamespace() == deployment.GetNamespace() && selector.Matches(labels.Set(replicaSet.GetLabels())) {
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
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicaSets", v1meta.NamespaceAll, fields.Everything())
	replicaSetInf = cache.NewSharedInformer(lw, &v1beta1.ReplicaSet{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchReplicaSets(evtc, filterEmpty)
		replicaSetInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchReplicaSets(evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	log.Debugf("In WatchReplicaSets()")

	replicaSetInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("replicasets")

				rs := obj.(*v1beta1.ReplicaSet)
				if filterEmpty && rs.Spec.Replicas != nil && *rs.Spec.Replicas == 0 {
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

				// 1 is default if Spec.Replicas is nil
				var newReplicas int32 = 1
				if newRS.Spec.Replicas != nil {
					newReplicas = *newRS.Spec.Replicas
				}
				var oldReplicas int32 = 1
				if oldRS.Spec.Replicas != nil {
					oldReplicas = *oldRS.Spec.Replicas
				}

				if filterEmpty && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if filterEmpty && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicaSetEvent(newRS,
						draiosproto.CongroupEventType_ADDED.Enum(), true)
					addEvent("ReplicaSet", EVENT_UPDATE_AND_SEND)
					return
				} else if filterEmpty && oldReplicas > 0 && newReplicas == 0 {
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
				rs := obj.(*v1beta1.ReplicaSet)
				if filterEmpty && rs.Spec.Replicas != nil && *rs.Spec.Replicas == 0 {
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
