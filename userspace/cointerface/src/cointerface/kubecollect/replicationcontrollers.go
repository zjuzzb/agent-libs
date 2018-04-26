package kubecollect

import (
	"cointerface/draiosproto"
	"context"
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

// make this a library function?
func replicationControllerEvent(rc *v1.ReplicationController, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicationControllerCongroup(rc),
	}
}

func newReplicationControllerCongroup(replicationController *v1.ReplicationController) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicationcontroller"),
			Id:proto.String(string(replicationController.GetUID()))},
	}

	ret.Tags = GetTags(replicationController.ObjectMeta, "kubernetes.replicationController.")
	ret.InternalTags = GetAnnotations(replicationController.ObjectMeta, "kubernetes.replicationController.")
	addReplicationControllerMetrics(&ret.Metrics, replicationController)
	AddNSParents(&ret.Parents, replicationController.GetNamespace())
	selector := labels.Set(replicationController.Spec.Selector).AsSelector()
	AddPodChildren(&ret.Children, selector, replicationController.GetNamespace())
	AddHorizontalPodAutoscalerParents(&ret.Parents, replicationController.GetNamespace(), replicationController.APIVersion, replicationController.Kind, replicationController.GetName() )

	return ret
}

var replicationControllerInf cache.SharedInformer

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

	for _, obj := range replicationControllerInf.GetStore().List() {
		replicationController := obj.(*v1.ReplicationController)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector := labels.Set(replicationController.Spec.Selector).AsSelector()
		if pod.GetNamespace() == replicationController.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(replicationController.GetUID()))})
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
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicationControllers", v1meta.NamespaceAll, fields.Everything())
	replicationControllerInf = cache.NewSharedInformer(lw, &v1.ReplicationController{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchReplicationControllers(evtc, filterEmpty)
		replicationControllerInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchReplicationControllers(evtc chan<- draiosproto.CongroupUpdateEvent, filterEmpty bool) {
	log.Debugf("In WatchReplicationControllers()")

	replicationControllerInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("replicationcontrollers")

				rc := obj.(*v1.ReplicationController)
				if filterEmpty && rc.Spec.Replicas != nil && *rc.Spec.Replicas == 0 {
					return
				}

				evtc <- replicationControllerEvent(rc,
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldRC := oldObj.(*v1.ReplicationController)
				newRC := newObj.(*v1.ReplicationController)
				if oldRC.GetResourceVersion() == newRC.GetResourceVersion() {
					return
				}

				// 1 is default if Spec.Replicas is nil
				var newReplicas int32 = 1
				if newRC.Spec.Replicas != nil {
					newReplicas = *newRC.Spec.Replicas
				}
				var oldReplicas int32 = 1
				if oldRC.Spec.Replicas != nil {
					oldReplicas = *oldRC.Spec.Replicas
				}

				if filterEmpty && oldReplicas == 0 && newReplicas == 0 {
					return
				} else if filterEmpty && oldReplicas == 0 && newReplicas > 0 {
					evtc <- replicationControllerEvent(newRC,
						draiosproto.CongroupEventType_ADDED.Enum())
					return
				} else if filterEmpty && oldReplicas > 0 && newReplicas == 0 {
					evtc <- draiosproto.CongroupUpdateEvent {
						Type: draiosproto.CongroupEventType_REMOVED.Enum(),
						Object: &draiosproto.ContainerGroup{
							Uid: &draiosproto.CongroupUid{
								Kind:proto.String("k8s_replicationcontroller"),
								Id:proto.String(string(newRC.GetUID()))},
						},
					}
					return
				} else {
					// XXX add equals check like other resources
					/*
					sameEntity, sameLinks := replicationControllerEquals(oldRC, newRC)
					if !sameEntity || !sameLinks {
						evtc <- replicationControllerEvent(newRC,
							draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					}
					*/
					evtc <- replicationControllerEvent(newRC,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				rc := obj.(*v1.ReplicationController)
				if filterEmpty && rc.Spec.Replicas != nil && *rc.Spec.Replicas == 0 {
					return
				}

				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_replicationcontroller"),
							Id:proto.String(string(rc.GetUID()))},
					},
				}
			},
		},
	)
}
