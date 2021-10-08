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
	"k8s.io/apimachinery/pkg/types"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Globals are reset in startDeploymentsSInformer
var deploymentInf cache.SharedInformer
var deploySelectorCache *SelectorCache

type CoDeployment struct {
	*appsv1.Deployment
}

func (deploy CoDeployment) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(deploy.Spec.Selector)
	return s
}

func (deploy CoDeployment) Filtered() bool {
	return false
}

func (deploy CoDeployment) ActiveChildren() int32 {
	return deploy.Status.Replicas
}

func deploymentEvent(dep CoDeployment, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newDeploymentCongroup(dep, setLinks),
	}
}

// sameEntity will always be false when sameLinks is false
func deploymentEquals(lhs CoDeployment, rhs CoDeployment) (sameEntity bool, sameLinks bool) {
	if rhs.Deployment == nil || lhs.Deployment == nil {
		return false, false
	}

	// Check sameLinks fields first
	if lhs.GetNamespace() != rhs.GetNamespace() {
		return false, false
	}
	if !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		return false, false
	}
	// This is the last sameLinks check because it sometimes
	// returns sameLinks == true unlike the above checks
	if lhs.Status.Replicas != rhs.Status.Replicas {
		if (lhs.Status.Replicas == 0) || (rhs.Status.Replicas == 0) {
			return false, false
		} else {
			return false, true
		}
	}

	// Now check sameEntity, sameLinks is always true from here out
	if lhs.GetName() != rhs.GetName() {
		return false, true
	}
	if !reflect.DeepEqual(lhs.Spec.Replicas, rhs.Spec.Replicas) ||
		lhs.Spec.Paused != rhs.Spec.Paused ||
		lhs.Status.AvailableReplicas != rhs.Status.AvailableReplicas ||
		lhs.Status.UnavailableReplicas != rhs.Status.UnavailableReplicas ||
		lhs.Status.UpdatedReplicas != rhs.Status.UpdatedReplicas {
		return false, true
	}
	if !kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) ||
		!kubecollect_common.EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta) {
		return false, true
	}

	return true, true
}

func newDeploymentCongroup(deployment CoDeployment, setLinks bool) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_deployment"),
			Id:   proto.String(string(deployment.GetUID()))},
		Namespace: proto.String(deployment.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(deployment, "kubernetes.deployment.")
	ret.InternalTags = kubecollect_common.GetAnnotations(deployment.ObjectMeta, "kubernetes.deployment.")
	AddDeploymentMetrics(&ret.Metrics, deployment)
	if setLinks {
		selector, _ := deploySelectorCache.Get(deployment)
		AddReplicaSetChild(&ret.Children, selector, deployment.GetNamespace(), deployment.ObjectMeta)
		AddHorizontalPodAutoscalerParents(&ret.Parents, deployment.GetNamespace(), deployment.APIVersion, deployment.Kind, deployment.GetName())
	}
	ret.LabelSelector = kubecollect_common.GetLabelSelector(*deployment.Spec.Selector)

	if deployment.Spec.Template.Labels != nil {
		if ret.PodTemplateLabels == nil {
			ret.PodTemplateLabels = make(map[string]string)
		}
		for key, val := range deployment.Spec.Template.Labels {
			ret.PodTemplateLabels[key] = val
		}
	}

	return ret
}

func AddDeploymentMetrics(metrics *[]*draiosproto.AppMetric, deployment CoDeployment) {
	prefix := "kubernetes.deployment."
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.replicas", deployment.Status.Replicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.readyReplicas", deployment.Status.ReadyReplicas)
	// kube-state-metrics uses "kube_deployment_status_replicas_available" but
	// we use availableReplicas instead of replicasAvailable because it matches
	// the name in DeploymentStatus and other resources like ReplicationControllers
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.availableReplicas", deployment.Status.AvailableReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.unavailableReplicas", deployment.Status.UnavailableReplicas)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.updatedReplicas", deployment.Status.UpdatedReplicas)
	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"spec.replicas", deployment.Spec.Replicas)
	kubecollect_common.AppendMetricBool(metrics, prefix+"spec.paused", deployment.Spec.Paused)
	//if deployment.Spec.Strategy.RollingUpdate != nil {
	//	metrics[prefix + "spec.strategy.rollingupdate.max.unavailable"] = uint32(deployment.Spec.Strategy.RollingUpdate.MaxUnavailable)
	//}
}

func AddDeploymentParent(parents *[]*draiosproto.CongroupUid, rs CoReplicaSet) {
	if !kubecollect_common.ResourceReady("deployments") {
		return
	}

	uid := types.UID("")

	// Start looking for the owner reference
	for _, owner := range rs.GetOwnerReferences() {
		if owner.Kind == "Deployment" {
			uid = owner.UID
			break
		}
	}

	if string(uid) != "" {
		*parents = append(*parents, &draiosproto.CongroupUid{
			Kind: proto.String("k8s_deployment"),
			Id:   proto.String(string(uid))})
	}
}

func AddDeploymentChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !kubecollect_common.ResourceReady("deployments") {
		return
	}

	for _, obj := range deploymentInf.GetStore().List() {
		deployment := obj.(*appsv1.Deployment)
		if (deployment.GetNamespace() == namespace) &&
			(deployment.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind: proto.String("k8s_deployment"),
				Id:   proto.String(string(deployment.GetUID()))})
		}
	}
}

func startDeploymentsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	deploySelectorCache = NewSelectorCache()
	client := kubeClient.AppsV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Deployments", v1meta.NamespaceAll, fields.Everything())
	deploymentInf = cache.NewSharedInformer(lw, &appsv1.Deployment{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchDeployments(evtc)
		deploymentInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchDeployments(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchDeployments()")

	deploymentInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("deployments")
				evtc <- deploymentEvent(CoDeployment{obj.(*appsv1.Deployment)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("Deployment", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kubecollect_common.AddEvent("Deployment", kubecollect_common.EVENT_UPDATE)
				oldDeployment := CoDeployment{oldObj.(*appsv1.Deployment)}
				newDeployment := CoDeployment{newObj.(*appsv1.Deployment)}
				if oldDeployment.GetResourceVersion() == newDeployment.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := deploymentEquals(oldDeployment, newDeployment)
				if !sameLinks {
					deploySelectorCache.Update(newDeployment)
				}
				if !sameEntity || !sameLinks {
					evtc <- deploymentEvent(newDeployment,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					kubecollect_common.AddEvent("Deployment", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldDeployment := CoDeployment{nil}
				switch obj := obj.(type) {
				case *appsv1.Deployment:
					oldDeployment = CoDeployment{Deployment: obj}
				case cache.DeletedFinalStateUnknown:
					o, ok := (obj.Obj).(*appsv1.Deployment)
					if ok {
						oldDeployment = CoDeployment{o}
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without deployment object")
					}
				default:
					_ = log.Warn("Unknown object type in deployment DeleteFunc")
				}
				if oldDeployment.Deployment == nil {
					return
				}
				deploySelectorCache.Remove(oldDeployment)
				evtc <- draiosproto.CongroupUpdateEvent{
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind: proto.String("k8s_deployment"),
							Id:   proto.String(string(oldDeployment.GetUID()))},
					},
				}
				kubecollect_common.AddEvent("Deployment", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
